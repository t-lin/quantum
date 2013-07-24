# vim: tabstop=4 shiftwidth=4 softtabstop=4

#    Copyright 2011 OpenStack LLC
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Quotas for instances, volumes, and floating ips."""

import logging

from quantum.common import exceptions
from quantum.openstack.common import cfg
from quantum.openstack.common import importutils

LOG = logging.getLogger(__name__)
quota_opts = [
    cfg.ListOpt('quota_items',
                default=['network', 'subnet', 'port'],
                help='resource name(s) that are supported in quota features'),
    cfg.IntOpt('default_quota',
               default=-1,
               help='default number of resource allowed per tenant, '
               'minus for unlimited'),
    cfg.IntOpt('quota_network',
               default=10,
               help='number of networks allowed per tenant,'
               'minus for unlimited'),
    cfg.IntOpt('quota_subnet',
               default=10,
               help='number of subnets allowed per tenant, '
               'minus for unlimited'),
    cfg.IntOpt('quota_port',
               default=50,
               help='number of ports allowed per tenant, minus for unlimited'),
    cfg.StrOpt('quota_driver',
               default='quantum.quota.ConfDriver',
               help='default driver to use for quota checks'),
]
# Register the configuration options
cfg.CONF.register_opts(quota_opts, 'QUOTAS')


class ConfDriver(object):
    """
    Driver to perform necessary checks to enforce quotas and obtain
    quota information. The default driver utilizes the default values
    in quantum.conf.
    """

    def _get_quotas(self, context, resources, keys):
        """
        A helper method which retrieves the quotas for the specific
        resources identified by keys, and which apply to the current
        context.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resources.
        :param keys: A list of the desired quotas to retrieve.
        """

        # Filter resources
        desired = set(keys)
        sub_resources = dict((k, v) for k, v in resources.items()
                             if k in desired)

        # Make sure we accounted for all of them...
        if len(keys) != len(sub_resources):
            unknown = desired - set(sub_resources.keys())
            raise exceptions.QuotaResourceUnknown(unknown=sorted(unknown))
        quotas = {}
        for resource in sub_resources.values():
            quotas[resource.name] = resource.default
        return quotas

    def limit_check(self, context, tenant_id,
                    resources, values):
        """Check simple quota limits.

        For limits--those quotas for which there is no usage
        synchronization function--this method checks that a set of
        proposed values are permitted by the limit restriction.

        This method will raise a QuotaResourceUnknown exception if a
        given resource is unknown or if it is not a simple limit
        resource.

        If any of the proposed values is over the defined quota, an
        OverQuota exception will be raised with the sorted list of the
        resources which are too high.  Otherwise, the method returns
        nothing.

        :param context: The request context, for access checks.
        :param tennant_id: The tenant_id to check quota.
        :param resources: A dictionary of the registered resources.
        :param values: A dictionary of the values to check against the
                       quota.
        """

        # Ensure no value is less than zero
        unders = [key for key, val in values.items() if val < 0]
        if unders:
            raise exceptions.InvalidQuotaValue(unders=sorted(unders))

        # Get the applicable quotas
        quotas = self._get_quotas(context, resources, values.keys())

        # Check the quotas and construct a list of the resources that
        # would be put over limit by the desired values
        overs = [key for key, val in values.items()
                 if quotas[key] >= 0 and quotas[key] < val]
        if overs:
            raise exceptions.OverQuota(overs=sorted(overs), quotas=quotas,
                                       usages={})


class BaseResource(object):
    """Describe a single resource for quota checking."""

    def __init__(self, name, flag):
        """
        Initializes a Resource.

        :param name: The name of the resource, i.e., "instances".
        :param flag: The name of the flag or configuration option
        """

        self.name = name
        self.flag = flag

    @property
    def default(self):
        """Return the default value of the quota."""
        if hasattr(cfg.CONF.QUOTAS, self.flag):
            return cfg.CONF.QUOTAS[self.flag]
        else:
            return cfg.CONF.QUOTAS.default_quota


class CountableResource(BaseResource):
    """Describe a resource where the counts are determined by a function.
    """

    def __init__(self, name, count, flag=None):
        """Initializes a CountableResource.

        Countable resources are those resources which directly
        correspond to objects in the database, i.e., netowk, subnet,
        etc.,.  A CountableResource must be constructed with a counting
        function, which will be called to determine the current counts
        of the resource.

        The counting function will be passed the context, along with
        the extra positional and keyword arguments that are passed to
        Quota.count().  It should return an integer specifying the
        count.

        :param name: The name of the resource, i.e., "instances".
        :param count: A callable which returns the count of the
                      resource.  The arguments passed are as described
                      above.
        :param flag: The name of the flag or configuration option
                     which specifies the default value of the quota
                     for this resource.
        """

        super(CountableResource, self).__init__(name, flag=flag)
        self.count = count


class QuotaEngine(object):
    """Represent the set of recognized quotas."""

    def __init__(self, quota_driver_class=None):
        """Initialize a Quota object."""

        if not quota_driver_class:
            quota_driver_class = cfg.CONF.QUOTAS.quota_driver

        if isinstance(quota_driver_class, basestring):
            quota_driver_class = importutils.import_object(quota_driver_class)

        self._resources = {}
        self._driver = quota_driver_class

    def __contains__(self, resource):
        return resource in self._resources

    def register_resource(self, resource):
        """Register a resource."""
        if resource.name in self._resources:
            LOG.warn('%s is already registered.', resource.name)
            return
        self._resources[resource.name] = resource

    def register_resource_by_name(self, resourcename):
        """Register a resource by name."""
        resource = CountableResource(resourcename, _count_resource,
                                     'quota_' + resourcename)
        self.register_resource(resource)

    def register_resources(self, resources):
        """Register a list of resources."""

        for resource in resources:
            self.register_resource(resource)

    def count(self, context, resource, *args, **kwargs):
        """Count a resource.

        For countable resources, invokes the count() function and
        returns its result.  Arguments following the context and
        resource are passed directly to the count function declared by
        the resource.

        :param context: The request context, for access checks.
        :param resource: The name of the resource, as a string.
        """

        # Get the resource
        res = self._resources.get(resource)
        if not res or not hasattr(res, 'count'):
            raise exceptions.QuotaResourceUnknown(unknown=[resource])

        return res.count(context, *args, **kwargs)

    def limit_check(self, context, tenant_id, **values):
        """Check simple quota limits.

        For limits--those quotas for which there is no usage
        synchronization function--this method checks that a set of
        proposed values are permitted by the limit restriction.  The
        values to check are given as keyword arguments, where the key
        identifies the specific quota limit to check, and the value is
        the proposed value.

        This method will raise a QuotaResourceUnknown exception if a
        given resource is unknown or if it is not a simple limit
        resource.

        If any of the proposed values is over the defined quota, an
        OverQuota exception will be raised with the sorted list of the
        resources which are too high.  Otherwise, the method returns
        nothing.

        :param context: The request context, for access checks.
        """

        return self._driver.limit_check(context, tenant_id,
                                        self._resources, values)

    @property
    def resources(self):
        return self._resources


QUOTAS = QuotaEngine()


def _count_resource(context, plugin, resources, tenant_id):
    count_getter_name = "get_%s_count" % resources

    # Some plugins support a count method for particular resources,
    # using a DB's optimized counting features. We try to use that one
    # if present. Otherwise just use regular getter to retrieve all objects
    # and count in python, allowing older plugins to still be supported
    try:
        obj_count_getter = getattr(plugin, count_getter_name)
        return obj_count_getter(context, filters={'tenant_id': [tenant_id]})
    except (exceptions.NotImplementedError, AttributeError):
        obj_getter = getattr(plugin, "get_%s" % resources)
        obj_list = obj_getter(context, filters={'tenant_id': [tenant_id]})
        return len(obj_list) if obj_list else 0


resources = []
for resource_item in cfg.CONF.QUOTAS.quota_items:
    resources.append(CountableResource(resource_item, _count_resource,
                                       'quota_' + resource_item))

QUOTAS.register_resources(resources)
