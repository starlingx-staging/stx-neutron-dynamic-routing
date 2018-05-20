# Copyright 2016 Huawei Technologies India Pvt. Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class BgpDriverBase(object):
    """Base class for BGP Speaking drivers.

    Any class which provides BGP functionality should extend this
    defined base class.
    """

    def __init__(self, *args, **kwargs):
        self._peer_up_callback = kwargs.get('peer_up_callback')
        self._peer_down_callback = kwargs.get('peer_down_callback')
        self._path_change_callback = kwargs.get('path_change_callback')

    @abc.abstractmethod
    def get_vrf_type(self, vpn_type):
        """Convert the VPN type to a value understood by the driver.

        :param vpn_type: Specifies the VPN type in neutron term.
        :type: vpn_type: string

        :raises: InvalidParamType
        :returns: vrf_type as string
        """

    @abc.abstractmethod
    def convert_to_local_route_type(self, route_type):
        """Convert the EVPN numeric route type to a value understood by the
        driver.

        :param route_type: A numeric route type value
        :type route_type: integer

        :raises: InvalidParamType
        :returns: A driver representation of the route type
        """

    @abc.abstractmethod
    def add_bgp_speaker(self, speaker_as):
        """Add a BGP speaker.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :raises: BgpSpeakerAlreadyScheduled, BgpSpeakerMaxScheduled,
                 InvalidParamType, InvalidParamRange
        """

    @abc.abstractmethod
    def delete_bgp_speaker(self, speaker_as):
        """Deletes BGP speaker.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :raises: BgpSpeakerNotAdded
        """

    @abc.abstractmethod
    def add_bgp_peer(self, speaker_as, peer_ip, peer_as,
                     auth_type='none', password=None):
        """Add a new BGP peer.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param peer_ip: Specifies the IP address of the peer.
        :type peer_ip: string
        :param peer_as: Specifies Autonomous Number of the peer.
                        Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type peer_as: integer
        :param auth_type: Specifies authentication type.
                          By default, authentication will be disabled.
        :type auth_type: value in SUPPORTED_AUTH_TYPES
        :param password: Authentication password.By default, authentication
                         will be disabled.
        :type password: string
        :raises: BgpSpeakerNotAdded, InvalidParamType, InvalidParamRange,
                 InvaildAuthType, PasswordNotSpecified
        """

    @abc.abstractmethod
    def delete_bgp_peer(self, speaker_as, peer_ip):
        """Delete a BGP peer associated with the given peer IP

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param peer_ip: Specifies the IP address of the peer. Must be the
                        string representation of an IP address.
        :type peer_ip: string
        :raises: BgpSpeakerNotAdded, BgpPeerNotAdded
        """

    @abc.abstractmethod
    def advertise_route(self, speaker_as, cidr, nexthop):
        """Add a new prefix to advertise.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param cidr: CIDR of the network to advertise. Must be the string
                     representation of an IP network (e.g., 10.1.1.0/24)
        :type cidr: string
        :param nexthop: Specifies the next hop address for the above
                        prefix.
        :type nexthop: string
        :raises: BgpSpeakerNotAdded, InvalidParamType
        """

    @abc.abstractmethod
    def withdraw_route(self, speaker_as, cidr, nexthop=None):
        """Withdraw an advertised prefix.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param cidr: CIDR of the network to withdraw. Must be the string
                     representation of an IP network (e.g., 10.1.1.0/24)
        :type cidr: string
        :param nexthop: Specifies the next hop address for the above
                        prefix.
        :type nexthop: string
        :raises: BgpSpeakerNotAdded, RouteNotAdvertised, InvalidParamType
        """

    @abc.abstractmethod
    def get_bgp_speaker_statistics(self, speaker_as):
        """Collect BGP Speaker statistics.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :raises: BgpSpeakerNotAdded
        :returns: bgp_speaker_stats: string
        """

    @abc.abstractmethod
    def get_bgp_peer_statistics(self, speaker_as, peer_ip, peer_as):
        """Collect BGP Peer statistics.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param peer_ip: Specifies the IP address of the peer.
        :type peer_ip: string
        :param peer_as: Specifies the AS number of the peer. Must be an
                        integer between MIN_ASNUM and MAX_ASNUM.
        :type peer_as: integer                    .
        :raises: BgpSpeakerNotAdded, BgpPeerNotAdded
        :returns: bgp_peer_stats: string
        """

    @abc.abstractmethod
    def add_vrf(self, speaker_as, route_dist, import_rts, export_rts,
                vrf_type):
        """Advertise a new VRF instance.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param route_dist: Specifies the VRF route distinguisher value
        :type route_dist: string
        :param import_rts: Specifies the list of route targets to import
        :type import_rts: integer
        :param export_rts: Specifies the list of route targets to export
        :type export_rts: integer
        :param vrf_type: Specifies the VRF address family
        :type vrf_type: string

        :raises: BgpSpeakerNotAdded, BgpPeerNotAdded
        """

    @abc.abstractmethod
    def delete_vrf(self, speaker_as, route_dist):
        """Withdraws a VRF instance.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param route_dist: Specifies the VRF route distinguisher value
        :type route_dist: string

        :raises: BgpSpeakerNotAdded, BgpPeerNotAdded
        """

    @abc.abstractmethod
    def advertise_evpn_route(self, speaker_as, route_type, route_dist, esi=0,
                             ethernet_tag_id=None, mac_addr=None, ip_addr=None,
                             ip_prefix=None, gw_ip_addr=None, vni=None,
                             next_hop=None, tunnel_type=None):
        """Add a new EVPN prefix to advertise.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer

        :param route_type: Specifies the EVPN Route Type number
        :type route_type: integer
        :param route_dist: Specifies the route distinguisher value
        :type route_dist: string
        :param esi: Specifies the Ethernet Segment Identifier
        :type esi: integer
        :param ethernet_tag_id: Specifies the Ethernet Tag ID value
        :type ethernet_tag_id: string
        :param mac_addr: Specifies the MAC address to be advertised
        :type mac_addr: string
        :param ip_addr: Specifies the IP address to be advertised
        :type ip_addr: string
        :param ip_prefix: Specifies the IP address prefix to be
        advertised (e.g., 192.168.1.1/24).
        :type ip_prefix: string
        :param gw_ip_addr:  Specifies the gateway IP address which
        services the IP prefix being advertised
        :type gw_ip_addr: string
        :param vni: Specifies the VXLAN VNI value of the VPN
        :type vni: integer
        :param next_hop:  Specifies the underlay IP address of the next hop
        VTEP instance
        :param tunnel_type: Specifies the underlay tunnel type
        :type tunnel_type: string
        """

    @abc.abstractmethod
    def withdraw_evpn_route(self, speaker_as, route_type, route_dist, esi=0,
                            ethernet_tag_id=None, mac_addr=None, ip_addr=None,
                            ip_prefix=None):
        """Add a new EVPN prefix to advertise.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer

        :param route_type: Specifies the EVPN Route Type number
        :type route_type: integer
        :param route_dist: Specifies the route distinguisher value
        :type route_dist: string
        :param esi: Specifies the Ethernet Segment Identifier
        :type esi: integer
        :param ethernet_tag_id: Specifies the Ethernet Tag ID value
        :type ethernet_tag_id: string
        :param mac_addr: Specifies the MAC address to be advertised
        :type mac_addr: string
        :param ip_addr: Specifies the IP address to be advertised
        :type ip_addr: string
        :param ip_prefix: Specifies the IP address prefix to be
        advertised (e.g., 192.168.1.1/24).
        :type ip_prefix: string
        """
