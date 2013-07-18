# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2013, The SAVI Project.
# Copyright 2012 OpenStack LLC
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

import sys
import abc
import logging

import netaddr

from quantum.agent.linux import ip_lib
from quantum.agent.linux import ovs_lib
from quantum.agent.linux import utils
from quantum.agent.linux.interface import OVSInterfaceDriver
from quantum.common import exceptions
from quantum.extensions.flavor import (FLAVOR_NETWORK)
from quantum.openstack.common import cfg
from quantum.openstack.common import importutils

from janus.network.network import JanusNetworkDriver

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('janus_api_host',
               default='127.0.0.1:8091',
               help='Openflow Janus REST API host:port'),
]

class JanusInterfaceDriver(OVSInterfaceDriver):
    """Driver for creating a Janus OVS interface."""

    def __init__(self, conf):
        super(JanusInterfaceDriver, self).__init__(conf)
        conf.register_opts(OPTS)

        if not conf.janus_api_host:
            LOG.error(_('You must specify Janus API host and address (e.g. 127.0.0.1:8091'))
            sys.exit(1)

        if not conf.ovs_integration_bridge:
            LOG.error(_('You must specify the name of the OVS integration bridge'))
            sys.exit(1)

        LOG.debug('Janus rest host %s', self.conf.janus_api_host)
        host, port = self.conf.janus_api_host.split(':')
        self.client = JanusNetworkDriver(host, port)
        self.device2netid = {}

    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None, prefix=None, internal_cidr=None):
        """Plug in the interface."""
        super(JanusInterfaceDriver, self).plug(network_id, port_id, device_name,
                                             mac_address, bridge=bridge,
                                             namespace=namespace,
                                             prefix=prefix)
        if not bridge:
            bridge = self.conf.ovs_integration_bridge

        self.check_bridge_exists(bridge)
        ovs_br = ovs_lib.OVSBridge(bridge, self.conf.root_helper)
        datapath_id = ovs_br.get_datapath_id()
        port_no = ovs_br.get_port_ofport(device_name)
        self.client.addMAC(network_id, mac_address)
        self.client.createPort(network_id, datapath_id, port_no)
        if internal_cidr is not None:
            ip = internal_cidr.split("/")[0]
            self.client.ip_mac_mapping(network_id, datapath_id, mac_address, ip, port_no)
        self.device2netid[device_name] = network_id

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""
        # Unregistering port and disassociating MAC from network done by q-svc in
        #   the main Janus plugin file. This is because q-svc deletes network before
        #   q-dhcp unregisters the port, resulting in an error in Janus.
        #   In the future, perhaps Janus can auto-unregister ports in a deleted network?
        #   Currently this is not done to prevent users from accidentally deleting their
        #   entire network, including all the ports.

        # To do: Un-mapping of ip to mac?

        super(JanusInterfaceDriver, self).unplug(device_name, bridge,
                                                    namespace, prefix)

