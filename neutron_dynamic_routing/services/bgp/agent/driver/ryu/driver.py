# Copyright 2016 Huawei Technologies India Pvt. Ltd.
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

from oslo_log import log as logging
from oslo_utils import encodeutils
from ryu.lib.packet import bgp as libbgp
from ryu.services.protocols.bgp import bgpspeaker
from ryu.services.protocols.bgp.rtconf.neighbors import CONNECT_MODE_ACTIVE

from neutron_lib import constants as lib_consts

from neutron_dynamic_routing._i18n import _LE, _LI
from neutron_dynamic_routing.services.bgp.agent.driver import base
from neutron_dynamic_routing.services.bgp.agent.driver import exceptions as bgp_driver_exc  # noqa
from neutron_dynamic_routing.services.bgp.agent.driver import utils

from networking_bgpvpn.neutron.services.common import constants as bgpvpn_constants  # noqa

LOG = logging.getLogger(__name__)


class RyuBgpDriver(base.BgpDriverBase):
    """BGP speaker implementation via Ryu."""

    def __init__(self, cfg, *args, **kwargs):
        super(RyuBgpDriver, self).__init__(*args, **kwargs)
        LOG.info(_LI('Initializing Ryu driver for BGP Speaker functionality.'))
        self._read_config(cfg)

        # Note: Even though Ryu can only support one BGP speaker as of now,
        # we have tried making the framework generic for the future purposes.
        self.cache = utils.BgpMultiSpeakerCache()

    def bgp_peer_down_cb(self, remote_ip, remote_as):
        LOG.info(
            _LI('BGP Peer %(peer_ip)s for remote_as=%(peer_as)d went DOWN.'),
            {'peer_ip': remote_ip, 'peer_as': remote_as})
        if self._peer_down_callback:
            self._peer_down_callback(remote_ip=remote_ip, remote_as=remote_as)

    def bgp_peer_up_cb(self, remote_ip, remote_as):
        LOG.info(_LI('BGP Peer %(peer_ip)s for remote_as=%(peer_as)d is UP.'),
                 {'peer_ip': remote_ip, 'peer_as': remote_as})
        if self._peer_up_callback:
            self._peer_up_callback(remote_ip=remote_ip, remote_as=remote_as)

    def _normalize_path_event(self, event):
        """Converts a RYU event to a normalized dict.

        The returned dict can be used generically by users of this driver
        without needing to know what type of driver is instantiated.
        """
        data = {'route_type':
                self.get_route_type_from_nlri(event.path.nlri.type),
                'nexthop': event.nexthop,
                'remote_as': event.remote_as,
                'is_withdraw': event.is_withdraw}
        nlri_type = event.path.nlri.type
        if nlri_type == libbgp.EvpnNLRI.MAC_IP_ADVERTISEMENT:
            data['mac_address'] = event.path.nlri.mac_addr
            data['ip_address'] = event.path.nlri.ip_addr
            data['vni'] = int(event.path.nlri.vni)
        elif nlri_type == libbgp.EvpnNLRI.INCLUSIVE_MULTICAST_ETHERNET_TAG:
            route_dist = event.route_dist
            data['vni'] = int(route_dist.split(':')[1])
        return data

    def best_path_change_cb(self, event):
        LOG.info(_LI("Best path change observed. cidr=%(prefix)s, "
                     "nexthop=%(nexthop)s, remote_as=%(remote_as)d, "
                     "is_withdraw=%(is_withdraw)s"),
                 {'prefix': event.prefix, 'nexthop': event.nexthop,
                  'remote_as': event.remote_as,
                  'is_withdraw': event.is_withdraw})
        if self._path_change_callback:
            normalized_event = self._normalize_path_event(event)
            self._path_change_callback(**normalized_event)

    def _read_config(self, cfg):
        if cfg is None or cfg.bgp_router_id is None:
            # If either cfg or router_id is not specified, raise voice
            LOG.error(_LE('BGP router-id MUST be specified for the correct '
                          'functional working.'))
        else:
            self.routerid = cfg.bgp_router_id
            LOG.info(_LI('Initialized Ryu BGP Speaker driver interface with '
                         'bgp_router_id=%s'), self.routerid)

    def get_vrf_type(self, vpn_type):
        if vpn_type == bgpvpn_constants.BGPVPN_L2:
            return bgpspeaker.RF_L2_EVPN
        raise bgp_driver_exc.InvalidParamValue(
            param='vpn_type', value=vpn_type)

    def convert_to_local_route_type(self, route_type):
        if route_type == bgpvpn_constants.BGPEVPN_RT_ETH_AUTO_DISCOVERY:
            return bgpspeaker.EVPN_ETH_AUTO_DISCOVERY
        elif route_type == bgpvpn_constants.BGPEVPN_RT_MAC_IP_ADV_ROUTE:
            return bgpspeaker.EVPN_MAC_IP_ADV_ROUTE
        elif route_type == bgpvpn_constants.BGPEVPN_RT_MULTICAST_ETAG_ROUTE:
            return bgpspeaker.EVPN_MULTICAST_ETAG_ROUTE
        elif route_type == bgpvpn_constants.BGPEVPN_RT_ETH_SEGMENT:
            return bgpspeaker.EVPN_ETH_SEGMENT
        elif route_type == bgpvpn_constants.BGPEVPN_RT_IP_PREFIX_ROUTE:
            return bgpspeaker.EVPN_IP_PREFIX_ROUTE
        raise bgp_driver_exc.InvalidParamValue(
            param='route_type', value=route_type)

    @staticmethod
    def get_route_type_from_nlri(nlri_type):
        if nlri_type == libbgp.EvpnNLRI.ETHERNET_AUTO_DISCOVERY:
            return bgpvpn_constants.BGPEVPN_RT_ETH_AUTO_DISCOVERY
        elif nlri_type == libbgp.EvpnNLRI.MAC_IP_ADVERTISEMENT:
            return bgpvpn_constants.BGPEVPN_RT_MAC_IP_ADV_ROUTE
        elif nlri_type == libbgp.EvpnNLRI.INCLUSIVE_MULTICAST_ETHERNET_TAG:
            return bgpvpn_constants.BGPEVPN_RT_MULTICAST_ETAG_ROUTE
        elif nlri_type == libbgp.EvpnNLRI.ETHERNET_SEGMENT:
            return bgpvpn_constants.BGPEVPN_RT_ETH_SEGMENT
        elif nlri_type == libbgp.EvpnNLRI.IP_PREFIX_ROUTE:
            return bgpvpn_constants.BGPEVPN_RT_IP_PREFIX_ROUTE
        return None

    def add_bgp_speaker(self, speaker_as):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if curr_speaker is not None:
            raise bgp_driver_exc.BgpSpeakerAlreadyScheduled(
                                                    current_as=speaker_as,
                                                    rtid=self.routerid)

        # Ryu can only support One speaker
        if self.cache.get_hosted_bgp_speakers_count() == 1:
            raise bgp_driver_exc.BgpSpeakerMaxScheduled(count=1)

        # Validate input parameters.
        # speaker_as must be an integer in the allowed range.
        utils.validate_as_num('local_as', speaker_as)

        # Notify Ryu about BGP Speaker addition.
        curr_speaker = bgpspeaker.BGPSpeaker(as_number=speaker_as,
                             router_id=self.routerid, bgp_server_port=179,
                             best_path_change_handler=self.best_path_change_cb,
                             peer_down_handler=self.bgp_peer_down_cb,
                             peer_up_handler=self.bgp_peer_up_cb)
        LOG.info(_LI('Added BGP Speaker for local_as=%(as)d with '
                     'router_id= %(rtid)s.'),
                 {'as': speaker_as, 'rtid': self.routerid})

        self.cache.put_bgp_speaker(speaker_as, curr_speaker)

    def delete_bgp_speaker(self, speaker_as):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)
        # Notify Ryu about BGP Speaker deletion
        curr_speaker.shutdown()
        LOG.info(_LI('Removed BGP Speaker for local_as=%(as)d with '
                     'router_id=%(rtid)s.'),
                 {'as': speaker_as, 'rtid': self.routerid})
        self.cache.remove_bgp_speaker(speaker_as)

    def add_bgp_peer(self, speaker_as, peer_ip, peer_as,
                     auth_type='none', password=None, enable_evpn=None,
                     hold_time=None, connect_mode=CONNECT_MODE_ACTIVE):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)

        # Validate peer_ip and peer_as.
        utils.validate_as_num('remote_as', peer_as)
        ip_version = utils.validate_ip_addr(peer_ip)
        utils.validate_auth(auth_type, password)
        if password is not None:
            password = encodeutils.to_utf8(password)

        kwargs = {}
        if enable_evpn is not None:
            kwargs['enable_evpn'] = enable_evpn
        if hold_time is not None:
            kwargs['hold_time'] = hold_time
        # Notify Ryu about BGP Peer addition
        if ip_version == lib_consts.IP_VERSION_4:
            enable_ipv4 = True
            enable_ipv6 = False
        else:
            enable_ipv4 = False
            enable_ipv6 = True
        curr_speaker.neighbor_add(address=peer_ip,
                                  remote_as=peer_as,
                                  enable_ipv4=enable_ipv4,
                                  enable_ipv6=enable_ipv6,
                                  password=password,
                                  connect_mode=connect_mode,
                                  **kwargs)
        LOG.info(_LI('Added BGP Peer %(peer)s for remote_as=%(as)d to '
                     'BGP Speaker running for local_as=%(local_as)d.'),
                 {'peer': peer_ip, 'as': peer_as, 'local_as': speaker_as})

    def delete_bgp_peer(self, speaker_as, peer_ip):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)
        # Validate peer_ip. It must be a string.
        utils.validate_ip_addr(peer_ip)

        # Notify Ryu about BGP Peer removal
        curr_speaker.neighbor_del(address=peer_ip)
        LOG.info(_LI('Removed BGP Peer %(peer)s from BGP Speaker '
                     'running for local_as=%(local_as)d.'),
                 {'peer': peer_ip, 'local_as': speaker_as})

    def advertise_route(self, speaker_as, cidr, nexthop):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)

        # Validate cidr and nexthop. Both must be strings.
        utils.validate_string(cidr)
        utils.validate_string(nexthop)

        # Notify Ryu about route advertisement
        curr_speaker.prefix_add(prefix=cidr, next_hop=nexthop)
        LOG.info(_LI('Route cidr=%(prefix)s, nexthop=%(nexthop)s is '
                     'advertised for BGP Speaker running for '
                     'local_as=%(local_as)d.'),
                 {'prefix': cidr, 'nexthop': nexthop, 'local_as': speaker_as})

    def withdraw_route(self, speaker_as, cidr, nexthop=None):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)
        # Validate cidr. It must be a string.
        utils.validate_string(cidr)

        # Notify Ryu about route withdrawal
        curr_speaker.prefix_del(prefix=cidr)
        LOG.info(_LI('Route cidr=%(prefix)s is withdrawn from BGP Speaker '
                     'running for local_as=%(local_as)d.'),
                 {'prefix': cidr, 'local_as': speaker_as})

    def get_bgp_speaker_statistics(self, speaker_as):
        LOG.info(_LI('Collecting BGP Speaker statistics for local_as=%d.'),
                 speaker_as)
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)

        # TODO(vikram): Filter and return the necessary information.
        # Will be done as part of new RFE requirement
        # https://bugs.launchpad.net/neutron/+bug/1527993
        return curr_speaker.neighbor_state_get()

    def get_bgp_peer_statistics(self, speaker_as, peer_ip, peer_as):
        LOG.info(_LI('Collecting BGP Peer statistics for peer_ip=%(peer)s, '
                     'running in speaker_as=%(speaker_as)d '),
                 {'peer': peer_ip, 'speaker_as': speaker_as})
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)

        # TODO(vikram): Filter and return the necessary information.
        # Will be done as part of new RFE requirement
        # https://bugs.launchpad.net/neutron/+bug/1527993
        return curr_speaker.neighbor_state_get(address=peer_ip)

    def add_vrf(self, speaker_as, route_dist, import_rts, export_rts,
                vrf_type):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)
        # Validate route_dist. It must be a string.
        utils.validate_string(route_dist)

        # Notify Ryu about a new VRF
        curr_speaker.vrf_add(
            route_dist=route_dist,
            import_rts=import_rts,
            export_rts=export_rts,
            route_family=self.get_vrf_type(vrf_type))
        LOG.info(_LI('VRF for RD %(rd)s is advertised for BGP Speaker '
                     'running for local_as=%(local_as)d.'),
                 {'rd': route_dist, 'local_as': speaker_as})

    def delete_vrf(self, speaker_as, route_dist):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)
        # Validate route_dist. It must be a string.
        utils.validate_string(route_dist)

        # Notify Ryu about a deleted VRF
        curr_speaker.vrf_del(
            route_dist=route_dist)
        LOG.info(_LI('VRF for RD %(rd)s is no longer advertised for BGP '
                     'Speaker running for local_as=%(local_as)d.'),
                 {'rd': route_dist, 'local_as': speaker_as})

    def advertise_evpn_route(self, speaker_as, route_type, route_dist, esi=0,
                             ethernet_tag_id=None, mac_addr=None, ip_addr=None,
                             ip_prefix=None, gw_ip_addr=None, vni=None,
                             next_hop=None, tunnel_type=None):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)
        # Validate parameters that must be strings.
        utils.validate_string(route_dist)
        utils.validate_string(mac_addr)
        utils.validate_string(ip_addr)
        utils.validate_string(gw_ip_addr)
        utils.validate_string(next_hop)
        utils.validate_string(tunnel_type)

        kwargs = {'esi': esi,
                  'ethernet_tag_id': ethernet_tag_id,
                  'mac_addr': mac_addr,
                  'ip_addr': ip_addr,
                  'ip_prefix': ip_prefix,
                  'gw_ip_addr': gw_ip_addr,
                  'vni': vni,
                  'next_hop': next_hop,
                  'tunnel_type': tunnel_type}

        curr_speaker.evpn_prefix_add(
            self.convert_to_local_route_type(route_type), route_dist, **kwargs)

        LOG.info(_LI('EVPN route type %(route_type)s for RD %(rd)s is '
                     'advertised for BGP Speaker running for '
                     'local_as=%(local_as)d attributes: %(attributes)s.'),
                 {'rd': route_dist,
                  'route_type': route_type,
                  'local_as': speaker_as,
                  'attributes': kwargs})

    def withdraw_evpn_route(self, speaker_as, route_type, route_dist, esi=0,
                            ethernet_tag_id=None, mac_addr=None, ip_addr=None,
                            ip_prefix=None):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)
        # Validate parameters that must be strings.
        utils.validate_string(route_dist)
        utils.validate_string(mac_addr)
        utils.validate_string(ip_addr)

        kwargs = {'esi': esi,
                  'ethernet_tag_id': ethernet_tag_id,
                  'mac_addr': mac_addr,
                  'ip_addr': ip_addr,
                  'ip_prefix': ip_prefix}

        curr_speaker.evpn_prefix_del(
            self.convert_to_local_route_type(route_type), route_dist, **kwargs)

        LOG.info(_LI('EVPN route type %(route_type)s for RD %(rd)s is '
                     'withdrawn for BGP Speaker running for '
                     'local_as=%(local_as)d attributes: %(attributes)s.'),
                 {'rd': route_dist,
                  'route_type': route_type,
                  'local_as': speaker_as,
                  'attributes': kwargs})
