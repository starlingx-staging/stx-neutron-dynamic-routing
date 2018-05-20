# Copyright 2016 IBM
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import contextlib

import mock

from oslo_utils import uuidutils

from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from neutron.tests.unit.plugins.ml2 import test_plugin

from neutron_dynamic_routing.extensions import bgp
from neutron_dynamic_routing.services.bgp import bgp_plugin

from networking_bgpvpn.neutron.db import bgpvpn_db

_uuid = uuidutils.generate_uuid

ADVERTISE_FIPS_KEY = 'advertise_floating_ip_host_routes'
IMAGINARY = '2b2334c8-adfe-42d9-82c6-ad866c7fc5d8'  # non existent resource id


class BgpvpnEntityCreationMixin(object):

    @contextlib.contextmanager
    def bgp_speaker(self, ip_version, local_as, name='my-speaker',
                    advertise_fip_host_routes=True,
                    advertise_tenant_networks=True,
                    vpns=None):
        data = {'ip_version': ip_version,
                ADVERTISE_FIPS_KEY: advertise_fip_host_routes,
                'advertise_tenant_networks': advertise_tenant_networks,
                'local_as': local_as, 'name': name}
        bgp_speaker = self.bgp_plugin.create_bgp_speaker(self.context,
                                                        {'bgp_speaker': data})
        bgp_speaker_id = bgp_speaker['id']

        if vpns:
            for vpn_id in vpns:
                self.bgp_plugin.add_bgp_vpn(self.context, bgp_speaker_id,
                                            {'bgpvpn_id': vpn_id})

        yield self.bgp_plugin.get_bgp_speaker(self.context, bgp_speaker_id)

    @contextlib.contextmanager
    def router(self, name='bgp-test-router', tenant_id=_uuid(),
               admin_state_up=True, **kwargs):
        request = {'router': {'tenant_id': tenant_id,
                              'name': name,
                              'admin_state_up': admin_state_up}}
        for arg in kwargs:
            request['router'][arg] = kwargs[arg]
        router = self.l3plugin.create_router(self.context, request)
        yield router

    @contextlib.contextmanager
    def bgpvpn_router(self):
        # create 4 networks and 4 subnets:
        # sub-1, sub-2 in pool1, and sub-3 in pool2, sub-4 in pool3
        # add all subnets to router
        seg_1 = [{'provider:network_type': 'vxlan',
                  'provider:segmentation_id': 1000}]
        seg_2 = [{'provider:network_type': 'vxlan',
                  'provider:segmentation_id': 1001}]
        seg_3 = [{'provider:network_type': 'vxlan',
                  'provider:segmentation_id': 1002}]
        seg_4 = [{'provider:network_type': 'vxlan',
                  'provider:segmentation_id': 1003}]
        with self.network(arg_list=('segments',), segments=seg_1) as net_1, \
            self.subnet(net_1, cidr='10.1.1.0/24',
                subnetpool_id=self.pool_1_id) as sub_1, \
            self.network(arg_list=('segments',), segments=seg_2) as net_2, \
            self.subnet(net_2, cidr='10.1.2.0/24',
                subnetpool_id=self.pool_1_id) as sub_2, \
            self.network(arg_list=('segments',), segments=seg_3) as net_3, \
            self.subnet(net_3, cidr='10.2.1.0/24',
                subnetpool_id=self.pool_2_id) as sub_3, \
            self.network(arg_list=('segments',), segments=seg_4) as net_4, \
            self.subnet(net_4, cidr='10.3.1.0/24',
                subnetpool_id=self.pool_3_id) as sub_4, \
            self.router() as router:

            port1_data = {'subnet_id': sub_1['subnet']['id']}
            port1 = self.l3plugin.add_router_interface(self.context,
                router['id'], port1_data)
            port2_data = {'subnet_id': sub_2['subnet']['id']}
            self.l3plugin.add_router_interface(self.context,
                router['id'], port2_data)
            port3_data = {'subnet_id': sub_3['subnet']['id']}
            self.l3plugin.add_router_interface(self.context,
                router['id'], port3_data)
            port4_data = {'subnet_id': sub_4['subnet']['id']}
            self.l3plugin.add_router_interface(self.context,
                router['id'], port4_data)
            yield (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
                  sub_4, port1)


class BgpvpnTests(test_plugin.Ml2PluginV2TestCase,
               BgpvpnEntityCreationMixin):
    fmt = 'json'

    def setup_parent(self):
        self.l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                          'TestL3NatAgentSchedulingServicePlugin')
        super(BgpvpnTests, self).setup_parent()

    def setup_bgpvpn(self):
        # create 2 address scope: scope-1, scope-2
        scope_data_1 = {'tenant_id': 'tenant_id', 'ip_version': 4,
                      'shared': False, 'name': 'scope-1'}
        scope_data_2 = {'tenant_id': 'tenant_id', 'ip_version': 4,
                      'shared': False, 'name': 'scope-2'}
        self.scope_1 = self.plugin.create_address_scope(self.context,
            {'address_scope': scope_data_1})
        self.scope_2 = self.plugin.create_address_scope(self.context,
            {'address_scope': scope_data_2})
        self.scope_1_id = self.scope_1['id']
        self.scope_2_id = self.scope_2['id']

        # create 3 subnetpool: pool-1, pool-2, pool-3.
        # pool-1, pool-2 are in scope-1, pool-3 is in scope-2
        pool1_data = {'tenant_id': 'tenant_id', 'shared': False,
                      'name': 'pool-1', 'address_scope_id': self.scope_1_id,
                      'prefixes': ['10.1.0.0/16'], 'is_default': False}
        pool2_data = {'tenant_id': 'tenant_id', 'shared': False,
                      'name': 'pool-2', 'address_scope_id': self.scope_1_id,
                      'prefixes': ['10.2.0.0/16'], 'is_default': False}
        pool3_data = {'tenant_id': 'tenant_id', 'shared': False,
                      'name': 'pool-3', 'address_scope_id': self.scope_2_id,
                      'prefixes': ['10.3.0.0/16'], 'is_default': False}
        self.pool_1 = self.plugin.create_subnetpool(self.context,
            {'subnetpool': pool1_data})
        self.pool_2 = self.plugin.create_subnetpool(self.context,
            {'subnetpool': pool2_data})
        self.pool_3 = self.plugin.create_subnetpool(self.context,
            {'subnetpool': pool3_data})
        self.pool_1_id = self.pool_1['id']
        self.pool_2_id = self.pool_2['id']
        self.pool_3_id = self.pool_3['id']

    def setUp(self):
        super(BgpvpnTests, self).setUp()
        self.l3plugin = directory.get_plugin(plugin_constants.L3)
        self.bgp_plugin = bgp_plugin.BgpPlugin()
        self.plugin = directory.get_plugin()
        self.bgpvpn_db = bgpvpn_db.BGPVPNPluginDb()
        get_bgpvpn_mock = mock.patch.object(self.bgp_plugin,
                                           '_get_bgpvpn_info')
        get_bgpvpn_mock.start()
        self.fake_bgpvpn = {'id': 'bgpvpn_id',
                       'tenant_id': 'tenant1',
                       'networks': [],
                       'routers': [],
                       'name': 'bgpvpn1',
                       'type': 'l3',
                       'route_distinguishers': '100:100',
                       'import_rt': '100:100',
                       'export_rt': '100:100'}
        get_bgpvpn_mock.return_value = self.fake_bgpvpn
        self.setup_bgpvpn()

    @contextlib.contextmanager
    def subnetpool_with_address_scope(self, ip_version, prefixes=None,
                                      shared=False, admin=True,
                                      name='test-pool', is_default_pool=False,
                                      tenant_id=None, **kwargs):
        if not tenant_id:
            tenant_id = _uuid()

        scope_data = {'tenant_id': tenant_id, 'ip_version': ip_version,
                      'shared': shared, 'name': name + '-scope'}
        address_scope = self.plugin.create_address_scope(
                                                self.context,
                                                {'address_scope': scope_data})
        address_scope_id = address_scope['id']
        pool_data = {'tenant_id': tenant_id, 'shared': shared, 'name': name,
                     'address_scope_id': address_scope_id,
                     'prefixes': prefixes, 'is_default': is_default_pool}
        for key in kwargs:
            pool_data[key] = kwargs[key]

        yield self.plugin.create_subnetpool(self.context,
                                            {'subnetpool': pool_data})

    @contextlib.contextmanager
    def bgpvpn(self):
        tenant_id = _uuid()
        data = {"tenant_id": tenant_id,
                "type": "l3",
                "name": "bgpvpn1",
                "route_targets": ["64512:1"],
                "import_targets": ["64512:11", "64512:12"],
                "export_targets": ["64512:13", "64512:14"],
                "route_distinguishers": ["64512:15", "64512:16"],
                "vni": None
                }
        bgpvpn = self.bgpvpn_db.create_bgpvpn(self.context,
                                              data)
        yield bgpvpn
        self.bgpvpn_db.delete_bgpvpn(self.context, bgpvpn['id'])

    def test_add_bgp_vpn(self):
        with self.bgp_speaker(4, 1234) as speaker,\
            self.bgpvpn() as bgpvpn:
            vpn_id = bgpvpn['id']
            self.bgp_plugin.add_bgp_vpn(self.context,
                                        speaker['id'],
                                        {'bgpvpn_id': vpn_id})
            new_speaker = self.bgp_plugin.get_bgp_speaker(self.context,
                                                          speaker['id'])
            self.assertEqual(1, len(new_speaker['vpns']))
            self.assertTrue(vpn_id in new_speaker['vpns'])

    def test_remove_bgp_vpn(self):
        with self.bgpvpn() as bgpvpn1,\
            self.bgpvpn() as bgpvpn2:
            vpn1_id = bgpvpn1['id']
            vpn2_id = bgpvpn2['id']
            with self.bgp_speaker(4, 1234, vpns=[vpn1_id, vpn2_id]) as speaker:
                self.bgp_plugin.remove_bgp_vpn(self.context,
                                               speaker['id'],
                                               {'bgpvpn_id': vpn1_id})
                new_speaker = self.bgp_plugin.get_bgp_speaker(self.context,
                                                              speaker['id'])
                self.assertEqual(1, len(new_speaker['vpns']))
                self.assertTrue(vpn2_id in new_speaker['vpns'])

                self.bgp_plugin.remove_bgp_vpn(self.context,
                                               speaker['id'],
                                               {'bgpvpn_id': vpn2_id})
                new_speaker = self.bgp_plugin.get_bgp_speaker(self.context,
                                                              speaker['id'])
                self.assertFalse(new_speaker['vpns'])

    def test_add_non_existent_bgp_vpn(self):
        vpn_id = IMAGINARY
        with self.bgp_speaker(4, 1234) as speaker:
            self.assertRaises(bgp.BgpVpnNotFound,
                              self.bgp_plugin.add_bgp_vpn,
                              self.context, speaker['id'],
                              {'bgpvpn_id': vpn_id})

    def test_remove_non_existent_bgp_vpn(self):
        vpn_id = IMAGINARY
        with self.bgp_speaker(4, 1234) as speaker:
            self.assertRaises(bgp.BgpSpeakerVpnNotAssociated,
                              self.bgp_plugin.remove_bgp_vpn,
                              self.context, speaker['id'],
                              {'bgpvpn_id': vpn_id})

    @contextlib.contextmanager
    def test__get_l3vpn_gw_query(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res

            # Test #1 port
            res1 = self.bgp_plugin._get_l3vpn_gw_query(self.context,
                router['id'], net_1['network']['provider:segmentation_id'])
            (ip_address, ip_version, subnetpool_id, address_scope_id) = res1
            self.assertEqual(ip_address, sub_1['subnet']['gateway_ip'])
            self.assertEqual(ip_version, 4)
            self.assertEqual(subnetpool_id, self.pool_1_id)
            self.assertEqual(address_scope_id, self.scope_1_id)

            # Test #2 port
            res1 = self.bgp_plugin._get_l3vpn_gw_query(self.context,
                router['id'], net_2['network']['provider:segmentation_id'])
            (ip_address, ip_version, subnetpool_id, address_scope_id) = res1
            self.assertEqual(ip_address, sub_2['subnet']['gateway_ip'])
            self.assertEqual(ip_version, 4)
            self.assertEqual(subnetpool_id, self.pool_1_id)
            self.assertEqual(address_scope_id, self.scope_1_id)

            # Test #3 port
            res1 = self.bgp_plugin._get_l3vpn_gw_query(self.context,
                router['id'], net_3['network']['provider:segmentation_id'])
            (ip_address, ip_version, subnetpool_id, address_scope_id) = res1
            self.assertEqual(ip_address, sub_3['subnet']['gateway_ip'])
            self.assertEqual(ip_version, 4)
            self.assertEqual(subnetpool_id, self.pool_2_id)
            self.assertEqual(address_scope_id, self.scope_1_id)

            # Test #4 port
            res1 = self.bgp_plugin._get_l3vpn_gw_query(self.context,
                router['id'], net_4['network']['provider:segmentation_id'])
            (ip_address, ip_version, subnetpool_id, address_scope_id) = res1
            self.assertEqual(ip_address, sub_4['subnet']['gateway_ip'])
            self.assertEqual(ip_version, 4)
            self.assertEqual(subnetpool_id, self.pool_3_id)
            self.assertEqual(address_scope_id, self.scope_2_id)

    @contextlib.contextmanager
    def test__get_l3vpn_gw_query_with_wrong_args(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res

            # wrong router id
            res1 = self.bgp_plugin._get_l3vpn_gw_query(self.context,
                'router_id', net_1['network']['provider:segmentation_id'])
            self.assertIsNone(res1)

            # wrong segment_id
            res1 = self.bgp_plugin._get_l3vpn_gw_query(self.context,
                router['id'], 'segmentation_id')
            self.assertIsNone(None)

    @contextlib.contextmanager
    def test__get_l3vpn_prefix_query_address_scope(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_address_scope(
                self.context, router['id'], self.scope_1_id, 4)
            self.assertEqual(prefixes, ['10.1.1.0/24', '10.1.2.0/24',
                                        '10.2.1.0/24'])

            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_address_scope(
                self.context, router['id'], self.scope_2_id, 4)
            self.assertEqual(prefixes, ['10.3.1.0/24'])

    @contextlib.contextmanager
    def test__get_l3vpn_prefix_query_address_scope_with_wrong_args(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res

            # wrong router_id
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_address_scope(
                self.context, 'router_id', self.scope_1_id, 4)
            self.assertEqual(prefixes, [])

            # wrong scope id
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_address_scope(
                self.context, router['id'], 'scope_id', 4)
            self.assertEqual(prefixes, [])

            # wrong ip version
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_address_scope(
                self.context, 'router_id', self.scope_1_id, 6)
            self.assertEqual(prefixes, [])

    @contextlib.contextmanager
    def test__get_l3vpn_prefix_query_by_port(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res

            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_by_port(
                self.context, self.scope_1_id, 4, port1['port_id'])
            self.assertEqual(prefixes, ['10.1.1.0/24'])

    @contextlib.contextmanager
    def test__get_l3vpn_prefix_query_by_port_with_wrong_args(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res

            #wrong scope id
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_by_port(
                self.context, 'scope_id', 4, port1['port_id'])
            self.assertEqual(prefixes, [])

            #wrong ip version
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_by_port(
                self.context, self.scope_1_id, 6, port1['port_id'])
            self.assertEqual(prefixes, [])

            #wrong port id
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_by_port(
                self.context, self.scope_1_id, 4, 'port_id')
            self.assertEqual(prefixes, [])

    @contextlib.contextmanager
    def test__get_l3vpn_prefix_query_by_subnetpool(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res

            # pool 1
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_by_subnetpool(
                self.context, router['id'], 4, self.pool_1_id)
            self.assertEqual(prefixes, ['10.1.1.0/24', '10.1.2.0/24'])

            # pool 2
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_by_subnetpool(
                self.context, router['id'], 4, self.pool_2_id)
            self.assertEqual(prefixes, ['10.2.1.0/24'])

            # pool 3
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_by_subnetpool(
                self.context, router['id'], 4, self.pool_3_id)
            self.assertEqual(prefixes, ['10.3.1.0/24'])

    @contextlib.contextmanager
    def test__get_l3vpn_prefix_query_by_subnetpool_with_wrong_args(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res

            # wrong router id
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_by_subnetpool(
                self.context, 'router_id', 4, self.pool_1_id)
            self.assertEqual(prefixes, [])

            # wrong ip version
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_by_subnetpool(
                self.context, router['id'], 6, self.pool_1_id)
            self.assertEqual(prefixes, [])

            # wrong pool id
            prefixes = self.bgp_plugin._get_l3vpn_prefix_query_by_subnetpool(
                self.context, router['id'], 4, 'pool_id')
            self.assertEqual(prefixes, [])

    @contextlib.contextmanager
    def test_get_l3vpn_routes(self):
        # there is no negative test for this API, because it's has been
        # included in prvious test
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res

            res1 = self.bgp_plugin.get_l3vpn_routes(self.context, router['id'],
                net_1['network']['provider:segmentation_id'])
            (next_hop, ip_version, prefixes) = res1
            self.assertEqual(next_hop, sub_1['subnet']['gateway_ip'])
            self.assertEqual(ip_version, 4)
            self.assertEqual(prefixes, ['10.1.1.0/24', '10.1.2.0/24',
                                        '10.2.1.0/24'])

            res1 = self.bgp_plugin.get_l3vpn_routes(self.context, router['id'],
                net_1['network']['provider:segmentation_id'], port1['port_id'])
            (next_hop, ip_version, prefixes) = res1
            self.assertEqual(next_hop, sub_1['subnet']['gateway_ip'])
            self.assertEqual(ip_version, 4)
            self.assertEqual(prefixes, ['10.1.1.0/24'])

    @contextlib.contextmanager
    def test_get_l3vpn_routes_for_scope_change(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res
            # suppose net-1 change it address scope from scope-2 to scope-1
            res1 = self.bgp_plugin.get_l3vpn_routes_for_scope_change(
                self.context, router['id'],
                net_1['network']['provider:segmentation_id'],
                self.pool_1_id, self.scope_1_id, self.scope_2_id)
            (next_hop, ip_version, added_prefixes, deleted_prefixes) = res1
            self.assertEqual(added_prefixes, ['10.3.1.0/24'])
            self.assertEqual(deleted_prefixes, ['10.1.1.0/24', '10.1.2.0/24',
                                                '10.2.1.0/24'])

    @contextlib.contextmanager
    def test_get_segment_address_scope(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res

            #net_1 scope id
            res1 = self.bgp_plugin.get_segment_address_scope(self.context,
                net_1['network']['provider:segmentation_id'])
            (ip_version, address_scope_id) = res1
            self.assertEqual(ip_version, 4)
            self.assertEqual(address_scope_id, self.scope_1_id)

            #net_2 scope id
            res1 = self.bgp_plugin.get_segment_address_scope(self.context,
                net_2['network']['provider:segmentation_id'])
            (ip_version, address_scope_id) = res1
            self.assertEqual(ip_version, 4)
            self.assertEqual(address_scope_id, self.scope_1_id)

            #net_3 scope id
            res1 = self.bgp_plugin.get_segment_address_scope(self.context,
                net_3['network']['provider:segmentation_id'])
            (ip_version, address_scope_id) = res1
            self.assertEqual(ip_version, 4)
            self.assertEqual(address_scope_id, self.scope_1_id)

            #net_4 scope id
            res1 = self.bgp_plugin.get_segment_address_scope(self.context,
                net_4['network']['provider:segmentation_id'])
            (ip_version, address_scope_id) = res1
            self.assertEqual(ip_version, 4)
            self.assertEqual(address_scope_id, self.scope_2_id)

            #wrong vni
            res1 = self.bgp_plugin.get_segment_address_scope(self.context,
                'segmentation_id')
            self.assertIsNone(res1)

    @contextlib.contextmanager
    def test_get_network_address_scope(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res

            #net_1 scope id
            res1 = self.bgp_plugin.get_network_address_scope(self.context,
                net_1['network']['id'])
            (ip_version, address_scope_id) = res1
            self.assertEqual(ip_version, 4)
            self.assertEqual(address_scope_id, self.scope_1_id)

            #net_2 scope id
            res1 = self.bgp_plugin.get_network_address_scope(self.context,
                net_2['network']['id'])
            (ip_version, address_scope_id) = res1
            self.assertEqual(ip_version, 4)
            self.assertEqual(address_scope_id, self.scope_1_id)

            #net_3 scope id
            res1 = self.bgp_plugin.get_network_address_scope(self.context,
                net_3['network']['id'])
            (ip_version, address_scope_id) = res1
            self.assertEqual(ip_version, 4)
            self.assertEqual(address_scope_id, self.scope_1_id)

            #net_4 scope id
            res1 = self.bgp_plugin.get_network_address_scope(self.context,
                net_4['network']['id'])
            (ip_version, address_scope_id) = res1
            self.assertEqual(ip_version, 4)
            self.assertEqual(address_scope_id, self.scope_2_id)

            #net_4 wrong network id
            res1 = self.bgp_plugin.get_network_address_scope(self.context,
                'id')
            self.assertIsNone(res1)

    @contextlib.contextmanager
    def test_get_l3vpn_routes_by_network(self):
        with self.bgpvpn_router() as res:
            (router, net_1, sub_1, net_2, sub_2, net_3, sub_3, net_4,
             sub_4, port1) = res

            #net_1
            res1 = self.bgp_plugin.get_l3vpn_routes_by_network(self.context,
                router['id'], net_1['network']['id'])
            (ip_version, prefixes) = res1
            self.assertEqual(ip_version, 4)
            self.assertEqual(prefixes, ['10.1.1.0/24', '10.1.2.0/24',
                                        '10.2.1.0/24'])

            #net_4
            res1 = self.bgp_plugin.get_l3vpn_routes_by_network(self.context,
                router['id'], net_4['network']['id'])
            (ip_version, prefixes) = res1
            self.assertEqual(ip_version, 4)
            self.assertEqual(prefixes, ['10.3.1.0/24'])

            #wrong net id
            res1 = self.bgp_plugin.get_l3vpn_routes_by_network(self.context,
                router['id'], 'network_id')
            self.assertEqual(res1, (None, None))

    def test__get_bgp_speakers_by_bgpvpn(self):
        with self.bgp_speaker(4, 1234) as speaker,\
            self.bgp_speaker(4, 1235) as speaker1,\
            self.bgpvpn() as bgpvpn:
            vpn_id = bgpvpn['id']
            self.bgp_plugin.add_bgp_vpn(self.context,
                                        speaker['id'],
                                        {'bgpvpn_id': vpn_id})
            self.bgp_plugin.add_bgp_vpn(self.context,
                                        speaker1['id'],
                                        {'bgpvpn_id': vpn_id})
            speakers = self.bgp_plugin.get_bgp_speakers_by_bgpvpn(self.context,
                                                                  vpn_id)
            self.assertEqual(sorted(speakers),
                             sorted([speaker['id'], speaker1['id']]))
