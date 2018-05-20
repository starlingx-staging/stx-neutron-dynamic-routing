# Copyright (c) 2016 IBM.
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

import copy

from oslo_log import log as logging

from neutron_lib.api.definitions import bgpvpn as bgpvpn_def
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.plugins import directory

from neutron.db import segments_db

from networking_bgpvpn.neutron.callback import resources as bgpvpn_res
from networking_bgpvpn.neutron.services.common import constants

from neutron_dynamic_routing.api.rpc.callbacks import resources as dr_resources
from neutron_dynamic_routing.db import bgpvpn_db

DR_DRIVER_NAME = "neutron-dynamic-routing"
LOG = logging.getLogger(__name__)


class BGPVPNBase(bgpvpn_db.BgpvpnDbMixin):

    """BGPVPN base class """

    def __init__(self):
        self._register_bgpvpn_callbacks()

    def _register_bgpvpn_callbacks(self):
        # event from neutron l3 plugin
        registry.subscribe(self.bgpvpn_router_port_create_callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_CREATE)
        registry.subscribe(self.bgpvpn_router_port_delete_callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_DELETE)

        # event from core plugin
        registry.subscribe(self.bgpvpn_sunetpool_change_address_scope_callback,
                           resources.SUBNETPOOL_ADDRESS_SCOPE,
                           events.AFTER_UPDATE)

        # event from bgp plugin
        registry.subscribe(self.bgpvpn_speaker_delete_callback,
                           dr_resources.BGP_SPEAKER,
                           events.AFTER_DELETE)

        # event from bgpvpn pugin
        registry.subscribe(self.bgpvpn_create_callback,
                           bgpvpn_res.BGPVPN,
                           events.AFTER_CREATE)
        registry.subscribe(self.bgpvpn_update_callback,
                           bgpvpn_res.BGPVPN,
                           events.AFTER_UPDATE)
        registry.subscribe(self.bgpvpn_delete_callback,
                           bgpvpn_res.BGPVPN,
                           events.AFTER_DELETE)
        registry.subscribe(self.bgpvpn_router_assoc_callback,
                           bgpvpn_res.BGPVPN_ROUTER_ASSOC,
                           events.AFTER_CREATE)
        registry.subscribe(self.bgpvpn_router_assoc_callback,
                           bgpvpn_res.BGPVPN_ROUTER_ASSOC,
                           events.AFTER_DELETE)
        registry.subscribe(self.bgpvpn_network_assoc_callback,
                           bgpvpn_res.BGPVPN_NETWORK_ASSOC,
                           events.AFTER_CREATE)
        registry.subscribe(self.bgpvpn_network_assoc_callback,
                           bgpvpn_res.BGPVPN_NETWORK_ASSOC,
                           events.AFTER_DELETE)

    def get_bgp_speaker_by_bgpvpn(self, context, bgpvpn_id):
        return self.get_bgp_speakers_by_bgpvpn(context, bgpvpn_id)

    def add_bgp_vpn(self, context, bgp_speaker_id,
            vpn_info):
        ret_value = super(BGPVPNBase, self).add_bgp_vpn(context,
                                                        bgp_speaker_id,
                                                        vpn_info)
        if ret_value is None:
            return

        vpn_id = self._get_id_for(vpn_info, 'bgpvpn_id')
        self.bgp_speaker_associate_bgpvpn(context, bgp_speaker_id, vpn_id)

    def remove_bgp_vpn(self, context, bgp_speaker_id,
            vpn_info):
        ret_value = super(BGPVPNBase, self).remove_bgp_vpn(context,
                                                        bgp_speaker_id,
                                                        vpn_info)
        if ret_value is None:
            return

        vpn_id = self._get_id_for(vpn_info, 'bgpvpn_id')
        self.bgp_speaker_disassociate_bgpvpn(context, bgp_speaker_id, vpn_id)

    def _get_bgpvpn_info(self, context, bgpvpn_id):
        bgpvpn_plugin = directory.get_plugin(alias=bgpvpn_def.LABEL)
        return bgpvpn_plugin.get_bgpvpn(context, bgpvpn_id)

    @staticmethod
    def _make_bgpvpn_rpc_info(bgpvpn):
        """Convert bgpvpn dict to dict format expected by DrAgent."""
        bgpvpn_dict = {'id': bgpvpn['id'],
                       'name': bgpvpn['name'],
                       'rd': bgpvpn['route_distinguishers'],
                       'type': bgpvpn['type'],
                       'import_rt': (bgpvpn['route_targets'] +
                                     bgpvpn['import_targets']),
                       'export_rt': (bgpvpn['route_targets'] +
                                     bgpvpn['export_targets']),
                       'vni': bgpvpn['vni'],
                       'routers': bgpvpn['routers'],
                       'networks': bgpvpn['networks']}
        return bgpvpn_dict

    def _get_bgpvpn_rpc_info(self, context, bgpvpn_id):
        bgpvpn = self._get_bgpvpn_info(context, bgpvpn_id)
        bgpvpn_info = self._make_bgpvpn_rpc_info(bgpvpn)
        return bgpvpn_info

    def _get_bgpvpns(self, context, filters=None):
        bgpvpn_plugin = directory.get_plugin(alias=bgpvpn_def.LABEL)
        return bgpvpn_plugin.get_bgpvpns(context, filters=filters)

    def get_bgpvpns_rpc_info(self, context, filters=None):
        bgpvpns = self._get_bgpvpns(context, filters=filters)
        return [self._make_bgpvpn_rpc_info(bgpvpn) for bgpvpn in bgpvpns]

    def _get_bgpvpn_ids_by_router_id(self, context, rouer_id):
        bgpvpns = self._get_bgpvpns(context)
        bgpvpn_ids = []
        for bgpvpn in bgpvpns:
            if rouer_id in bgpvpn['routers']:
                if not bgpvpn_ids:
                    bgpvpn_ids = [bgpvpn['id']]
                else:
                    bgpvpn_ids.append(bgpvpn['id'])

        return bgpvpn_ids

    def _get_segment_info(self, context, network_id):
        return segments_db.get_networks_segments(context, [network_id])

    def _get_port_info(self, context, port_id):
        core_plugin = directory.get_plugin()
        return core_plugin.get_port(context, port_id)

    def bgpvpn_speaker_delete_callback(self, resource, event, trigger,
                                       **kwargs):
        context = kwargs['payload']['context']
        bgp_speaker = kwargs['payload']['bgp_speaker']
        for bgpvpn_id in bgp_speaker['vpns']:
            kwargs = {'context': context,
                      'bgpvpn_id': bgpvpn_id,
                      'speaker_id': bgp_speaker['id']}
            registry.notify(dr_resources.BGP_SPEAKER_VPN_ASSOC,
                            events.AFTER_DELETE,
                            self, **kwargs)

    def bgpvpn_create_callback(self, resource, event, trigger, **kwargs):
        #Nothing to do for now
        pass

    def bgpvpn_update_callback(self, resource, event, trigger, **kwargs):
        old_vpn = kwargs['old_vpn']
        new_vpn = kwargs['new_vpn']
        context = kwargs['context']
        vpn = copy.copy(old_vpn)
        if new_vpn['import_rt']:
            vpn['import_rt'] = new_vpn['import_rt']

        if new_vpn['export_rt']:
            vpn['export_rt'] = new_vpn['export_rt']

        self.bgpvpn_update_all_speakers(context, old_vpn['id'])

    def bgpvpn_delete_callback(self, resource, event, trigger, **kwargs):
        # NOTE(alegacy): by the time this callback is invoked the speaker to
        # vpn association has already been deleted but we still need to
        # tell the agents that this VPN is no longer active.  Since we do
        # not know which agents used to have this VPN we need to notify all
        # speakers.
        context = kwargs['context']
        bgpvpn_id = kwargs['id']
        bgp_speakers = self.get_bgp_speakers(context)
        if not bgp_speakers:
            return
        for bgp_speaker in bgp_speakers:
            bgp_speaker_id = bgp_speaker['id']
            dragents = self.list_dragent_hosting_bgp_speaker(
                context, bgp_speaker_id)
            for agent in dragents['agents']:
                self._bgp_rpc.bgp_speaker_vpn_disassociated(
                    context, bgp_speaker_id, bgpvpn_id, agent['host'])

    def _make_bgpvpn_route_dict(self, bgpvpn_type, next_hop, ip_version,
            prefixes):
        if bgpvpn_type == constants.BGPVPN_L3:
            return {'prefixes': [x for x in prefixes],
                    'next_hop': next_hop}

    def bgpvpn_network_assoc_callback(self, resource, event, trigger,
                                      **kwargs):
        context = kwargs['context']
        bgpvpn_id = kwargs['bgpvpn_id']
        bgp_speaker_ids = self.get_bgp_speakers_by_bgpvpn(context, bgpvpn_id)
        if not bgp_speaker_ids:
            return
        bgpvpn = self._get_bgpvpn_rpc_info(context, kwargs['bgpvpn_id'])
        if bgpvpn['type'] != constants.BGPVPN_L2:
            # NOTE(alegacy): we do not support these for now
            return
        for bgp_speaker_id in bgp_speaker_ids:
            dragents = self.list_dragent_hosting_bgp_speaker(
                context, bgp_speaker_id)
            for agent in dragents['agents']:
                if event == events.AFTER_DELETE:
                    self._bgp_rpc.bgp_speaker_vpn_disassociated(
                        context, bgp_speaker_id, bgpvpn_id, agent['host'])
                elif event == events.AFTER_CREATE:
                    self._bgp_rpc.bgp_speaker_vpn_associated(
                        context, bgp_speaker_id, bgpvpn, agent['host'])

    def bgpvpn_router_assoc_callback(self, resource, event, trigger, **kwargs):
        router_id = kwargs['router_id']
        context = kwargs['context']
        bgpvpn_id = kwargs['bgpvpn_id']
        bgpvpn = self._get_bgpvpn_info(context, kwargs['bgpvpn_id'])
        (next_hop, ip_version, prefixes) = self.get_l3vpn_routes(
            context, router_id, bgpvpn['vni'])
        if not prefixes:
            return

        routes = self._make_bgpvpn_route_dict(bgpvpn['type'], next_hop,
                    ip_version, prefixes)
        if event == events.AFTER_CREATE:
            self.bgp_speaker_advertise_vpn_routes(context, bgpvpn_id, routes,
                kwargs.get('speaker_id', None))
        elif event == events.AFTER_DELETE:
            self.bgp_speaker_withdraw_vpn_routes(context, bgpvpn_id, routes,
                kwargs.get('speaker_id', None))

    def bgpvpn_router_port_create_callback(self, resource, event, trigger,
            **kwargs):
        """when route add interface, if interface belong a bgpvpn,
           advertise the interface cidr
        """
        context = kwargs['context']
        router_id = kwargs['router_id']
        network_id = kwargs['port']['network_id']

        # router is not binding to bgpvpn, return
        bgpvpn_ids = self._get_bgpvpn_ids_by_router_id(context,
                                                       router_id)
        if bgpvpn_ids is None:
            return

        segment = self._get_segment_info(context, network_id)
        for bgpvpn_id in bgpvpn_ids:
            bgpvpn = self._get_bgpvpn_info(context, bgpvpn_id)
            # bgpvpn vni port added to router
            if (segment[network_id][0]['segmentation_id'] == bgpvpn['vni'] and
                segment[network_id][0]['network_type'] == 'vxlan'):
                kwargs = {'router_id': router_id,
                          'bgpvpn_id': bgpvpn_id,
                          'context': context}
                registry.notify(bgpvpn_res.BGPVPN_ROUTER_ASSOC,
                                event, self, **kwargs)
                #goto next vpn
                continue

            # other port added to router
            port_id = kwargs['port_id']
            (next_hop, ip_version, prefixes) = self.get_l3vpn_routes(
                context, router_id, bgpvpn['vni'], port_id)
            routes = self._make_bgpvpn_route_dict(bgpvpn['type'], next_hop,
                    ip_version, prefixes)
            self.bgp_speaker_advertise_vpn_routes(context, bgpvpn_id,
                routes)

    def bgpvpn_router_port_delete_callback(self, resource, event, trigger,
            **kwargs):
        """when route add interface, if interface belong a bgpvpn,
           advertise the interface cidr
        """
        context = kwargs['context']
        cidrs = kwargs['cidrs']
        router_id = kwargs['router_id']
        network_id = kwargs['port'].network_id

        # router is not binding to bgpvpn, return
        bgpvpn_ids = self._get_bgpvpn_ids_by_router_id(context,
                                                       router_id)
        if bgpvpn_ids is None:
            return

        segment = self._get_segment_info(context, network_id)
        for bgpvpn_id in bgpvpn_ids:
            bgpvpn = self._get_bgpvpn_info(context, bgpvpn_id)
            # router delete bgpvpn vni port
            if (segment[network_id][0]['segmentation_id'] == bgpvpn['vni'] and
                segment[network_id][0]['network_type'] == 'vxlan'):
                # because each network will only belong to 1 address scope,
                # find other router port cidrs of same address scope.
                (ip_version, prefixes) = self.get_l3vpn_routes_by_network(
                    context, router_id, network_id)
                prefixes += cidrs
                routes = self._make_bgpvpn_route_dict(bgpvpn['type'], None,
                    ip_version, prefixes)
                self.bgp_speaker_withdraw_vpn_routes(context, bgpvpn_id,
                    routes)
                # goto next vpn
                continue

            # router delete port which segment_id is not bgpvpn vni
            (port_ip_version, port_address_scope_id) = (
                self.get_network_address_scope(context, network_id))
            (gw_ip_version, gw_address_scope_id) = (
                self.get_segment_address_scope(context, bgpvpn['vni']))
            if (port_ip_version == gw_ip_version and
                port_address_scope_id == gw_address_scope_id):
                routes = self._make_bgpvpn_route_dict(bgpvpn['type'], None,
                    gw_ip_version, cidrs)
                self.bgp_speaker_withdraw_vpn_routes(context, bgpvpn_id,
                    routes)

    def bgpvpn_sunetpool_change_address_scope_callback(self, resource, event,
            trigger, **kwargs):
        subnetpool_id = kwargs['subnetpool_id']
        context = kwargs['context']
        old_address_scope_id = kwargs['orig_address_scope_id']
        new_address_scope_id = kwargs['new_address_scope_id']

        bgpvpns = self._get_bgpvpns(context)
        for bgpvpn in bgpvpns:
            for router_id in bgpvpn['routers']:
                (next_hop, ip_version, added_prefixes, deleted_prefixes) = (
                    self.get_l3vpn_routes_for_scope_change(context, router_id,
                                                       bgpvpn['vni'],
                                                       subnetpool_id,
                                                       old_address_scope_id,
                                                       new_address_scope_id))
                if deleted_prefixes:
                    routes = self._make_bgpvpn_route_dict(bgpvpn['type'],
                        next_hop, ip_version, deleted_prefixes)
                    self.bgp_speaker_withdraw_vpn_routes(context, bgpvpn['id'],
                                                         routes)
                if added_prefixes:
                    routes = self._make_bgpvpn_route_dict(bgpvpn['type'],
                        next_hop, ip_version, added_prefixes)
                    self.bgp_speaker_advertise_vpn_routes(context,
                                                          bgpvpn['id'],
                                                          routes)

    def bgpvpn_update_all_speakers(self, context, bgpvpn_id):
        bgp_speaker_ids = self.get_bgp_speaker_by_bgpvpn(context, bgpvpn_id)
        if bgp_speaker_ids is None:
            return

        bgpvpn = self._get_bgpvpn_rpc_info(context, bgpvpn_id)

        LOG.debug("bgp speakers %(speaker_id)s update bgpvpn"
            " %(bgpvpn)s", {'speaker_id': bgp_speaker_ids,
                            'bgpvpn': bgpvpn})
        for bgp_speaker_id in bgp_speaker_ids:
            hosted_bgp_dragents = self.list_dragent_hosting_bgp_speaker(
                    context, bgp_speaker_id)
            for agent in hosted_bgp_dragents['agents']:
                self._bgp_rpc.bgp_speaker_vpn_associated(context,
                    bgp_speaker_id, bgpvpn, agent['host'])

    def bgp_speaker_associate_bgpvpn(self, context, bgp_speaker_id, bgpvpn_id):
        bgpvpn = self._get_bgpvpn_rpc_info(context, bgpvpn_id)

        LOG.debug("bgp speakers %(speaker_id)s associate with bgpvpn"
            " %(bgpvpn)s", {'speaker_id': bgp_speaker_id,
                            'bgpvpn': bgpvpn})
        if not bgpvpn['networks'] and not bgpvpn['routers']:
            # NOTE(alegacy): Only consider bgpvpns that have at least one
            # network or router associated; otherwise there is no point in
            # receiving anything from the peer.
            return
        hosted_bgp_dragents = self.list_dragent_hosting_bgp_speaker(
                    context, bgp_speaker_id)
        for agent in hosted_bgp_dragents['agents']:
            self._bgp_rpc.bgp_speaker_vpn_associated(context,
                    bgp_speaker_id, bgpvpn, agent['host'])

        for router_id in bgpvpn['routers']:
            kwargs = {'router_id': router_id,
                      'bgpvpn_id': bgpvpn_id,
                      'context': context,
                      'speaker_id': bgp_speaker_id}
            registry.notify(bgpvpn_res.BGPVPN_ROUTER_ASSOC,
                            events.AFTER_CREATE,
                            self, **kwargs)

        kwargs = {'context': context,
                  'bgpvpn_id': bgpvpn_id,
                  'speaker_id': bgp_speaker_id}
        registry.notify(dr_resources.BGP_SPEAKER_VPN_ASSOC,
                        events.AFTER_CREATE,
                        self, **kwargs)

    def bgp_speaker_disassociate_bgpvpn(self, context, bgp_speaker_id,
                bgpvpn_id):
        bgpvpn = self._get_bgpvpn_rpc_info(context, bgpvpn_id)

        LOG.debug("bgp speakers %(speaker_id)s disassociate with bgpvpn"
            " %(bgpvpn)s", {'speaker_id': bgp_speaker_id,
                            'bgpvpn': bgpvpn})
        hosted_bgp_dragents = self.list_dragent_hosting_bgp_speaker(
                    context, bgp_speaker_id)
        for agent in hosted_bgp_dragents['agents']:
            self._bgp_rpc.bgp_speaker_vpn_disassociated(context,
                    bgp_speaker_id, bgpvpn['id'], agent['host'])

        for router_id in bgpvpn['routers']:
            kwargs = {'router_id': router_id,
                      'bgpvpn_id': bgpvpn_id,
                      'context': context,
                      'speaker_id': bgp_speaker_id}
            registry.notify(bgpvpn_res.BGPVPN_ROUTER_ASSOC,
                            events.AFTER_DELETE,
                            self, **kwargs)

        kwargs = {'context': context,
                  'bgpvpn_id': bgpvpn_id,
                  'speaker_id': bgp_speaker_id}
        registry.notify(dr_resources.BGP_SPEAKER_VPN_ASSOC,
                        events.AFTER_DELETE,
                        self, **kwargs)

    def bgp_speaker_advertise_vpn_routes(self, context, bgpvpn_id, routes,
           speaker=None):
        if speaker is None:
            speaker_ids = self.get_bgp_speaker_by_bgpvpn(context, bgpvpn_id)
            if speaker_ids is None:
                return
        else:
            speaker_ids = [speaker]

        LOG.debug("bgp speakers %(speaker)s advertise vpn %(vpn_id)s routes "
            "%(route)s", {'speaker': speaker_ids, 'vpn_id': bgpvpn_id,
                          'route': routes})
        for speaker_id in speaker_ids:
            dragents = self.list_dragent_hosting_bgp_speaker(
                context, speaker_id)
            for agent in dragents['agents']:
                self._bgp_rpc.bgpvpn_routes_advertisement(
                    context,
                    speaker_id,
                    bgpvpn_id,
                    routes,
                    agent['host'])

    def bgp_speaker_withdraw_vpn_routes(self, context, bgpvpn_id, routes,
            speaker=None):
        if speaker is None:
            speaker_ids = self.get_bgp_speaker_by_bgpvpn(context, bgpvpn_id)
            if speaker_ids is None:
                return
        else:
            speaker_ids = [speaker]

        LOG.debug("bgp speakers %(speaker)s withdraw vpn %(vpn_id)s routes "
            "%(route)s", {'speaker': speaker_ids, 'vpn_id': bgpvpn_id,
                          'route': routes})
        for speaker_id in speaker_ids:
            dragents = self.list_dragent_hosting_bgp_speaker(
                context, speaker_id)

            for agent in dragents['agents']:
                self._bgp_rpc.bgpvpn_routes_withdrawal(
                    context,
                    speaker_id,
                    bgpvpn_id,
                    routes,
                    agent['host'])
