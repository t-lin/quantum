# vim: tabstop=4 shiftwidth=4 softtabstop=4

import httplib
import logging
import os
import stat

import webob.exc
from swift.common import utils as swift_utils
from keystone.openstack.common import jsonutils


CONF = None
try:
    from openstack.common import cfg
    CONF = cfg.CONF
except ImportError:
    for app in 'nova', 'glance', 'quantum', 'cinder', 'swift':
        try:
            cfg = __import__('%s.openstack.common.cfg' % app,
                             fromlist=['%s.openstack.common' % app])
            if hasattr(cfg, 'CONF') and 'config_file' in cfg.CONF:
                CONF = cfg.CONF
                break
        except ImportError:
            pass
if not CONF:
    from keystone.openstack.common import cfg
    CONF = cfg.CONF
LOG = logging.getLogger(__name__)

opts = [
    cfg.StrOpt('auth_admin_prefix', default=''),
    cfg.StrOpt('auth_host', default='127.0.0.1'),
    cfg.IntOpt('auth_port', default=35357),
    cfg.StrOpt('auth_protocol', default='https'),
    cfg.StrOpt('auth_uri', default=None),
    cfg.StrOpt('admin_token'),
    cfg.StrOpt('admin_user'),
    cfg.StrOpt('admin_password'),
    cfg.StrOpt('admin_tenant_name', default='admin'),
    cfg.StrOpt('certfile'),
    cfg.StrOpt('keyfile'),
    cfg.StrOpt('signing_dir'),
]
CONF.register_opts(opts, group='keystone_policy')

class InvalidPolicy(Exception):
    pass

class ServiceError(Exception):
    pass


class ConfigurationError(Exception):
    pass


class Authorize(object):
    """Auth Middleware that handles authorizing client calls."""

    def __init__(self, app, conf):
        
        self.conf = conf
        self.app = app
        # delay_auth_decision means we still allow unauthenticated requests
        # through and we let the downstream service make the final decision
        self.delay_auth_decision = (self._conf_get('delay_auth_decision') in
                                    (True, 'true', 't', '1', 'on', 'yes', 'y'))
        self.local_settings = self._conf_get('local_settings')
        self.logger = swift_utils.get_logger(conf, log_route='swiftauth')
        # where to find the auth service (we use this to validate tokens)
        self.auth_host = self._conf_get('auth_host')
        self.auth_port = int(self._conf_get('auth_port'))
        self.auth_protocol = self._conf_get('auth_protocol')
        if self.auth_protocol == 'http':
            self.http_client_class = httplib.HTTPConnection
        else:
            self.http_client_class = httplib.HTTPSConnection
        self.auth_admin_prefix = self._conf_get('auth_admin_prefix')
        self.auth_uri = self._conf_get('auth_uri')
        if self.auth_uri is None:
            self.auth_uri = '%s://%s:%s' % (self.auth_protocol,
                                            self.auth_host,
                                            self.auth_port)

        # SSL
        self.cert_file = self._conf_get('certfile')
        self.key_file = self._conf_get('keyfile')

        #signing
        self.signing_dirname = self._conf_get('signing_dir')
        if self.signing_dirname is None:
            self.signing_dirname = '%s/keystone-signing' % os.environ['HOME']
        LOG.info('Using %s as cache directory for signing certificate' %
                 self.signing_dirname)
        if (os.path.exists(self.signing_dirname) and
                not os.access(self.signing_dirname, os.W_OK)):
                raise ConfigurationError("unable to access signing dir %s" %
                                         self.signing_dirname)

        if not os.path.exists(self.signing_dirname):
            os.makedirs(self.signing_dirname)
        #will throw IOError  if it cannot change permissions
        os.chmod(self.signing_dirname, stat.S_IRWXU)

        val = '%s/signing_cert.pem' % self.signing_dirname
        self.signing_cert_file_name = val
        val = '%s/cacert.pem' % self.signing_dirname
        self.ca_file_name = val
        val = '%s/revoked.pem' % self.signing_dirname
        self.revoked_file_name = val

        # Credentials used to verify this component with the Auth service since
        # validating tokens is a privileged call
        self.admin_token = self._conf_get('admin_token')
        self.admin_user = self._conf_get('admin_user')
        self.admin_password = self._conf_get('admin_password')
        self.admin_tenant_name = self._conf_get('admin_tenant_name')

    def _conf_get(self, name):
        # try config from paste-deploy first
        if name in self.conf:
            return self.conf[name]
        else:
            return CONF.keystone_authtoken[name]

    def _build_policy_check_credentials(self, environ):
        """Extract the identity from the Keystone auth component."""
        if environ.get('HTTP_X_IDENTITY_STATUS') != 'Confirmed':
            return
        roles = []
        if 'HTTP_X_ROLES' in environ:
            roles = environ['HTTP_X_ROLES'].split(',')
        context = {'user': environ.get('HTTP_X_USER_NAME'),
                    'tenant': (environ.get('HTTP_X_TENANT_ID',None),
                               environ.get('HTTP_X_TENANT_NAME',None)),
                    'roles': roles}
        return context

    def __call__(self, env, start_response):
        
        self.logger.debug('Authorizing User Request2')
        context = self._build_policy_check_credentials(env)
        self.logger.debug("Printing Identity %s" % context)
        self._add_headers(env, {'X-Authorized': 'NO'})
        self._add_headers(env, {'context':context})
        self._add_headers(env, {'enforce':self.enforce})
        return self.app(env, start_response)

    def enforce(self, request, action, kwargs={}):
        self.logger.debug(_('ABAC: Authorizing %s(%s)') % (
        action,
        ', '.join(['%s=%s' % (k, kwargs[k]) for k in kwargs])))
        return self.denied_response(request)
        """Handle incoming request.

        Authorize and send downstream on success. Reject request if
        we can't authorize.

        """
        

    def get_admin_token(self):
        """Return admin token, possibly fetching a new one.

        :return admin token id
        :raise ServiceError when unable to retrieve token from keystone

        """
        if not self.admin_token:
            self.admin_token = self._request_admin_token()

        return self.admin_token

    def _get_http_connection(self):
        if self.auth_protocol == 'http':
            return self.http_client_class(self.auth_host, self.auth_port)
        else:
            return self.http_client_class(self.auth_host,
                                          self.auth_port,
                                          self.key_file,
                                          self.cert_file)

    def _http_request(self, method, path):
        """HTTP request helper used to make unspecified content type requests.

        :param method: http method
        :param path: relative request url
        :return (http response object)
        :raise ServerError when unable to communicate with keystone

        """
        conn = self._get_http_connection()

        try:
            conn.request(method, path)
            response = conn.getresponse()
            body = response.read()
        except Exception, e:
            LOG.error('HTTP connection exception: %s' % e)
            raise ServiceError('Unable to communicate with keystone')
        finally:
            conn.close()

        return response, body

    def _json_request(self, method, path, body=None, additional_headers=None):
        """HTTP request helper used to make json requests.

        :param method: http method
        :param path: relative request url
        :param body: dict to encode to json as request body. Optional.
        :param additional_headers: dict of additional headers to send with
                                   http request. Optional.
        :return (http response object, response body parsed as json)
        :raise ServerError when unable to communicate with keystone

        """
        conn = self._get_http_connection()

        kwargs = {
            'headers': {
                'Content-type': 'application/json',
                'Accept': 'application/json',
            },
        }

        if additional_headers:
            kwargs['headers'].update(additional_headers)

        if body:
            kwargs['body'] = jsonutils.dumps(body)

        full_path = self.auth_admin_prefix + path
        try:
            conn.request(method, full_path, **kwargs)
            response = conn.getresponse()
            body = response.read()
        except Exception, e:
            LOG.error('HTTP connection exception: %s' % e)
            raise ServiceError('Unable to communicate with keystone')
        finally:
            conn.close()

        try:
            data = jsonutils.loads(body)
        except ValueError:
            LOG.debug('Keystone did not return json-encoded body')
            data = {}

        return response, data

    def _request_admin_token(self):
        """Retrieve new token as admin user from keystone.

        :return token id upon success
        :raises ServerError when unable to communicate with keystone

        """
        params = {
            'auth': {
                'passwordCredentials': {
                    'username': self.admin_user,
                    'password': self.admin_password,
                },
                'tenantName': self.admin_tenant_name,
            }
        }

        response, data = self._json_request('POST',
                                            '/v2.0/tokens',
                                            body=params)

        try:
            token = data['access']['token']['id']
            assert token
            return token
        except (AssertionError, KeyError):
            LOG.warn("Unexpected response from keystone service: %s", data)
            raise ServiceError('invalid json response')

    def _fetch_policy(self, policy_id):
        """ Fetch policy from Keystone """

        headers = {'X-Auth-Token': self.get_admin_token()}
        response, data = self._json_request('GET',
                                            '/v2.0/policies/%s' % policy_id,
                                            additional_headers=headers)

        if response.status == 200:
            return data
        if response.status == 404:
            LOG.warn("Fetching policy %s failed %s", policy_id)
            raise InvalidPolicy('authorization failed')
        if response.status == 401:
            LOG.info('Keystone rejected admin token %s, resetting', headers)
            self.admin_token = None
        else:
            LOG.error('Bad response code while fetching policy: %s' %
                      response.status)

    def cert_file_missing(self, called_proc_err, file_name):
        return (called_proc_err.output.find(file_name)
                and not os.path.exists(file_name))

    def fetch_signing_cert(self):
        response, data = self._http_request('GET',
                                            '/v2.0/certificates/signing')
        try:
            #todo check response
            certfile = open(self.signing_cert_file_name, 'w')
            certfile.write(data)
            certfile.close()
        except (AssertionError, KeyError):
            LOG.warn("Unexpected response from keystone service: %s", data)
            raise ServiceError('invalid json response')

    def fetch_ca_cert(self):
        response, data = self._http_request('GET',
                                            '/v2.0/certificates/ca')
        try:
            #todo check response
            certfile = open(self.ca_file_name, 'w')
            certfile.write(data)
            certfile.close()
        except (AssertionError, KeyError):
            LOG.warn("Unexpected response from keystone service: %s", data)
            raise ServiceError('invalid json response')

    def denied_response(self, req):
        """Deny WSGI Response.

        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            return webob.exc.HTTPForbidden(request=req)
        else:
            return webob.exc.HTTPUnauthorized(request=req) 

    def _header_to_env_var(self, key):
        """Convert header to wsgi env variable.

        :param key: http header name (ex. 'X-Auth-Token')
        :return wsgi env variable name (ex. 'HTTP_X_AUTH_TOKEN')

        """
        return 'HTTP_%s' % key.replace('-', '_').upper()

    def _add_headers(self, env, headers):
        """Add http headers to environment."""
        for (k, v) in headers.iteritems():
            env_key = self._header_to_env_var(k)
            env[env_key] = v
         
        
        
def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return Authorize(app, conf)
    return auth_filter


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return Authorize(None, conf)
