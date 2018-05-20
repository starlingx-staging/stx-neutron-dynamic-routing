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

from oslo_db import exception as oslo_db_exc
from oslo_log import log as logging
import sqlalchemy as sa
from sqlalchemy.orm import aliased
from sqlalchemy.orm import exc as sa_exc

from neutron_lib import constants as lib_consts
from neutron_lib.db import model_base

from neutron.db import common_db_mixin as common_db
from neutron.db.models import l3 as l3_models
from neutron.db.models import segment as segments_model
from neutron.db import models_v2

from neutron_dynamic_routing.extensions import bgp as bgp_ext

from networking_bgpvpn.neutron.db import bgpvpn_db

LOG = logging.getLogger(__name__)
DEVICE_OWNER_ROUTER_GW = lib_consts.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_ROUTER_INTF = lib_consts.DEVICE_OWNER_ROUTER_INTF


class BgpSpeakerVpnBinding(model_base.BASEV2):

    """Represents a mapping between BGP speaker and BGP VPN"""

    __tablename__ = 'bgp_speaker_vpn_bindings'

    bgp_speaker_id = sa.Column(sa.String(length=36),
                               sa.ForeignKey('bgp_speakers.id',
                                             ondelete='CASCADE'),
                               nullable=False,
                               primary_key=True)
    bgpvpn_id = sa.Column(sa.String(length=36),
                          sa.ForeignKey('bgpvpns.id',
                                        ondelete='CASCADE'),
                          nullable=False,
                          primary_key=True)


class BgpvpnDbMixin(common_db.CommonDbMixin):

    def add_bgp_vpn(self, context, bgp_speaker_id, vpn_info):
        vpn_id = self._get_id_for(vpn_info, 'bgpvpn_id')
        with context.session.begin(subtransactions=True):
            try:
                self._save_bgp_speaker_vpn_binding(context,
                                                   bgp_speaker_id,
                                                   vpn_id)
            except oslo_db_exc.DBDuplicateEntry:
                raise bgp_ext.BgpSpeakerVpnBindingError(
                                                vpn_id=vpn_id,
                                                bgp_speaker_id=bgp_speaker_id)
        return {'bgpvpn_id': vpn_id}

    def remove_bgp_vpn(self, context, bgp_speaker_id, vpn_info):
        with context.session.begin(subtransactions=True):
            vpn_id = self._get_id_for(vpn_info, 'bgpvpn_id')
            self._remove_bgp_speaker_vpn_binding(context,
                                                 bgp_speaker_id,
                                                 vpn_id)
        return {'bgpvpn_id': vpn_id}

    def _save_bgp_speaker_vpn_binding(self, context, bgp_speaker_id, vpn_id):
        from neutron_dynamic_routing.db import bgp_db
        with context.session.begin(subtransactions=True):
            try:
                bgp_speaker = self._get_by_id(context, bgp_db.BgpSpeaker,
                                              bgp_speaker_id)
            except sa_exc.NoResultFound:
                raise bgp_ext.BgpSpeakerNotFound(id=bgp_speaker_id)

            try:
                vpn = self._get_by_id(context, bgpvpn_db.BGPVPN,
                                      vpn_id)
            except sa_exc.NoResultFound:
                raise bgp_ext.BgpVpnNotFound(vpn_id=vpn_id)

            binding = BgpSpeakerVpnBinding(bgp_speaker_id=bgp_speaker.id,
                                           bgpvpn_id=vpn.id)
            context.session.add(binding)

    def _remove_bgp_speaker_vpn_binding(self, context, bgp_speaker_id, vpn_id):
        with context.session.begin(subtransactions=True):
            try:
                binding = self._get_bgp_speaker_vpn_binding(context,
                                                            bgp_speaker_id,
                                                            vpn_id)
            except sa_exc.NoResultFound:
                raise bgp_ext.BgpSpeakerVpnNotAssociated(
                                                vpn_id=vpn_id,
                                                bgp_speaker_id=bgp_speaker_id)
            context.session.delete(binding)

    def _get_bgp_speaker_vpn_binding(self, context,
                                     bgp_speaker_id, vpn_id):
        query = self._model_query(context, BgpSpeakerVpnBinding)
        return query.filter(
                    BgpSpeakerVpnBinding.bgp_speaker_id == bgp_speaker_id,
                    BgpSpeakerVpnBinding.bgpvpn_id == vpn_id).one()

    def get_bgp_speakers_by_bgpvpn(self, context, bgpvpn_id):
        with context.session.begin(subtransactions=True):
            query = context.session.query(BgpSpeakerVpnBinding.bgp_speaker_id)
            query = query.filter(
                BgpSpeakerVpnBinding.bgpvpn_id == bgpvpn_id).all()
            return [item.bgp_speaker_id for item in query]

    def _get_l3vpn_gw_query(self, context, router_id, vni):
        """for l3vpn, the router port which segment id is vni
         is the gateway port, this API will return gateway port
         ip address, ip version, subnet pool, address scope
        """
        with context.session.begin(subtransactions=True):
            routerport = aliased(l3_models.RouterPort)
            ip_allocated = aliased(models_v2.IPAllocation)
            segment = aliased(segments_model.NetworkSegment)
            subnet = aliased(models_v2.Subnet)
            subnetpool = aliased(models_v2.SubnetPool)
            query = context.session.query(ip_allocated.ip_address,
                                          subnet.ip_version,
                                          subnet.subnetpool_id,
                                          subnetpool.address_scope_id)
            query = query.filter(
                    routerport.router_id == router_id,
                    routerport.port_id == ip_allocated.port_id,
                    ip_allocated.subnet_id == subnet.id,
                    subnet.subnetpool_id == subnetpool.id,
                    subnet.network_id == segment.network_id,
                    segment.segmentation_id == vni)
            return query.first()

    def _get_l3vpn_prefix_query_address_scope(self, context, router_id,
                                              address_scope_id, ip_version):
        with context.session.begin(subtransactions=True):
            routerport = aliased(l3_models.RouterPort)
            ip_allocated = aliased(models_v2.IPAllocation)
            subnet = aliased(models_v2.Subnet)
            subnetpool = aliased(models_v2.SubnetPool)
            query = context.session.query(subnet.cidr)
            query = query.filter(routerport.router_id == router_id,
                    routerport.port_id == ip_allocated.port_id,
                    ip_allocated.subnet_id == subnet.id,
                    subnet.ip_version == ip_version,
                    subnet.subnetpool_id == subnetpool.id,
                    subnetpool.address_scope_id == address_scope_id)
            return [item.cidr for item in query.all()]

    def _get_l3vpn_prefix_query_by_port(self, context,
                                address_scope_id, ip_version, port_id):
        with context.session.begin(subtransactions=True):
            ip_allocated = aliased(models_v2.IPAllocation)
            subnet = aliased(models_v2.Subnet)
            subnetpool = aliased(models_v2.SubnetPool)
            query = context.session.query(subnet.cidr)
            query = query.filter(ip_allocated.port_id == port_id,
                    ip_allocated.subnet_id == subnet.id,
                    subnet.ip_version == ip_version,
                    subnet.subnetpool_id == subnetpool.id,
                    subnetpool.address_scope_id == address_scope_id)
            return [item.cidr for item in query.all()]

    def _get_l3vpn_prefix_query_by_subnetpool(self, context, router_id,
            ip_version, subnetpool_id):
        with context.session.begin(subtransactions=True):
            routerport = aliased(l3_models.RouterPort)
            ip_allocated = aliased(models_v2.IPAllocation)
            subnet = aliased(models_v2.Subnet)
            query = context.session.query(subnet.cidr)
            query = query.filter(routerport.router_id == router_id,
                    routerport.port_id == ip_allocated.port_id,
                    ip_allocated.subnet_id == subnet.id,
                    subnet.ip_version == ip_version,
                    subnet.subnetpool_id == subnetpool_id)
            return [item.cidr for item in query.all()]

    def get_l3vpn_routes(self, context, router_id, vni, port_id=None):
        """get l3vpn routes from db"""
        res = self._get_l3vpn_gw_query(context, router_id, vni)

        (next_hop, ip_version, subnetpool_id, address_scope_id) = res
        if port_id is not None:
            prefixes = self._get_l3vpn_prefix_query_by_port(context,
                        address_scope_id, ip_version, port_id)
        else:
            prefixes = self._get_l3vpn_prefix_query_address_scope(context,
                        router_id, address_scope_id, ip_version)
        return (next_hop, ip_version, prefixes)

    def get_l3vpn_routes_for_scope_change(self, context, router_id,
            vni, subnetpool_id, old_address_scope_id, new_address_scope_id):
        """get route change for address scope change"""
        (next_hop, ip_version, gw_subnetpool_id, gw_address_scope_id) = (
            self._get_l3vpn_gw_query(context, router_id, vni))

        # bgpvpn vni port change its address_scope
        if gw_subnetpool_id == subnetpool_id:
            added_prefixes = self._get_l3vpn_prefix_query_address_scope(
                context, router_id, new_address_scope_id, ip_version)
            deleted_prefixes = self._get_l3vpn_prefix_query_address_scope(
                context, router_id, old_address_scope_id, ip_version)
        elif old_address_scope_id == gw_address_scope_id:
            added_prefixes = []
            deleted_prefixes = self._get_l3vpn_prefix_query_by_subnetpool(
                        context, router_id, ip_version, subnetpool_id)
        elif new_address_scope_id == gw_address_scope_id:
            added_prefixes = self._get_l3vpn_prefix_query_by_subnetpool(
                        context, router_id, ip_version, subnetpool_id)
            deleted_prefixes = []
        else:
            added_prefixes = []
            deleted_prefixes = []
        return (next_hop, ip_version, added_prefixes, deleted_prefixes)

    def get_segment_address_scope(self, context, vni):
        with context.session.begin(subtransactions=True):
            subnet = aliased(models_v2.Subnet)
            subnetpool = aliased(models_v2.SubnetPool)
            segment = aliased(segments_model.NetworkSegment)
            query = context.session.query(subnetpool.ip_version,
                                          subnetpool.address_scope_id)
            query = query.filter(subnet.network_id == segment.network_id,
                                 segment.segmentation_id == vni,
                                 subnet.subnetpool_id == subnetpool.id)
            return query.first()

    def get_network_address_scope(self, context, network_id):
        with context.session.begin(subtransactions=True):
            subnet = aliased(models_v2.Subnet)
            subnetpool = aliased(models_v2.SubnetPool)
            query = context.session.query(subnetpool.ip_version,
                                          subnetpool.address_scope_id)
            query = query.filter(subnet.network_id == network_id,
                                 subnet.subnetpool_id == subnetpool.id)
            return query.first()

    def get_l3vpn_routes_by_network(self, context, router_id, network_id):
        # This API will be called when router delete port,
        # it does not need retrun nexthop
        res = self.get_network_address_scope(context, network_id)
        if res is None:
            return (None, None)

        (ip_version, address_scope_id) = res
        prefixes = self._get_l3vpn_prefix_query_address_scope(
            context, router_id, address_scope_id, ip_version)
        return (ip_version, prefixes)
