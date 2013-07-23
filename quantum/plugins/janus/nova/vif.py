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

import httplib

from janus.network.network import JanusNetworkDriver

from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova import utils
from nova.virt.libvirt import vif as libvirt_vif


LOG = logging.getLogger(__name__)

janus_libvirt_ovs_driver_opt = cfg.StrOpt('libvirt_ovs_janus_api_host',
                                        default='127.0.0.1:8091',
                                        help='Janus REST API host:port')

FLAGS = flags.FLAGS
FLAGS.register_opt(janus_libvirt_ovs_driver_opt)


def _get_datapath_id(bridge_name):
    out, _err = utils.execute('ovs-vsctl', 'get', 'Bridge',
                              bridge_name, 'datapath_id', run_as_root=True)
    return out.strip().strip('"')


def _get_port_no(dev):
    out, _err = utils.execute('ovs-vsctl', 'get', 'Interface', dev,
                              'ofport', run_as_root=True)
    return int(out.strip())


class LibvirtOpenVswitchOFPJanusDriver(libvirt_vif.LibvirtHybridOVSBridgeDriver):
    def __init__(self, **kwargs):
        super(LibvirtOpenVswitchOFPJanusDriver, self).__init__()
        LOG.debug('Janus REST host and port: %s', FLAGS.libvirt_ovs_janus_api_host)
        host, port = FLAGS.libvirt_ovs_janus_api_host.split(':')
        self.client = JanusNetworkDriver(host, port)
        self.datapath_id = _get_datapath_id(FLAGS.libvirt_ovs_bridge)

    def _get_port_no(self, mapping):
        iface_id = mapping['vif_uuid']
        _v1_name, v2_name = self.get_veth_pair_names(iface_id)
        return _get_port_no(v2_name)

    def plug(self, instance, vif):
        result = super(LibvirtOpenVswitchOFPJanusDriver, self).plug(
            instance, vif)
        network, mapping = vif
        port_no = self._get_port_no(mapping)
        try:
            self.client.createPort(network['id'], self.datapath_id, port_no)
            self.client.addMAC(network['id'], mapping['mac'])
            for ip in mapping['ips']:
                self.client.ip_mac_mapping(network['id'], self.datapath_id, 
                                           mapping['mac'], ip['ip'],
                                           port_no)
        except httplib.HTTPException as e:
            res = e.args[0]
            if res.status != httplib.CONFLICT:
                raise
        return result

    def unplug(self, instance, vif):
        network, mapping = vif
        port_no = self._get_port_no(mapping)
        try:
            self.client.deletePort(network['id'], self.datapath_id, port_no)
            self.client.delMAC(network['id'], mapping['mac'])
            # To do: Un-mapping of ip to mac?
        except httplib.HTTPException as e:
            res = e.args[0]
            if res.status != httplib.NOT_FOUND:
                raise
        super(LibvirtOpenVswitchOFPJanusDriver, self).unplug(instance, vif)
