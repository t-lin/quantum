# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2013, The SAVI Project.
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
#                               <yamahata at valinux co jp>
# All Rights Reserved.
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

from janus.network.network import JanusNetworkDriver

from nova import flags
from nova.network import linux_net
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova import utils


LOG = logging.getLogger(__name__)

janus_linux_net_opt = cfg.StrOpt('linuxnet_ovs_janus_api_host',
                               default='127.0.0.1:8091',
                               help='Janus REST API host:port')

FLAGS = flags.FLAGS
FLAGS.register_opt(janus_linux_net_opt)


def _get_datapath_id(bridge_name):
    out, _err = utils.execute('ovs-vsctl', 'get', 'Bridge',
                              bridge_name, 'datapath_id', run_as_root=True)
    return out.strip().strip('"')


def _get_port_no(dev):
    out, _err = utils.execute('ovs-vsctl', 'get', 'Interface', dev,
                              'ofport', run_as_root=True)
    return int(out.strip())


class LinuxOVSJanusInterfaceDriver(linux_net.LinuxOVSInterfaceDriver):
    def __init__(self):
        super(LinuxOVSJanusInterfaceDriver, self).__init__()

        LOG.debug('Janus REST host and port: %s', FLAGS.linuxnet_ovs_janus_api_host)
        host, port = FLAGS.linuxnet_ovs_janus_api_host.split(':')
        self.client = JanusNetworkDriver(host, port)
        self.datapath_id = _get_datapath_id(
            FLAGS.linuxnet_ovs_integration_bridge)

        if linux_net.binary_name == 'nova-network':
            for tables in [linux_net.iptables_manager.ipv4,
                           linux_net.iptables_manager.ipv6]:
                tables['filter'].add_rule(
                    'FORWARD',
                    '--in-interface gw-+ --out-interface gw-+ -j DROP')
            linux_net.iptables_manager.apply()

    def plug(self, network, mac_address, gateway=True):
        LOG.debug("network %s mac_adress %s gateway %s",
                  network, mac_address, gateway)
        ret = super(LinuxOVSJanusInterfaceDriver, self).plug(
            network, mac_address, gateway)

        port_no = _get_port_no(self.get_dev(network))
        self.client.create_port(network['uuid'], self.datapath_id, port_no)
        return ret
