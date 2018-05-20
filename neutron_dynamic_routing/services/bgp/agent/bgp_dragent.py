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

import collections

import netaddr
import six

from neutron_lib import context
from neutron_lib.utils import runtime
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from oslo_service import periodic_task
from oslo_utils import importutils

from neutron_lib import constants

from networking_bgpvpn.neutron.api import rpc as bgpvpn_rpc
from networking_bgpvpn.neutron.services.common import constants as bgpvpn_constants  # noqa

from neutron.agent import rpc as agent_rpc
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron import manager
from neutron.notifiers import batch_notifier
from neutron.plugins.ml2.drivers.l2pop.rpc_manager import l2population_rpc

from neutron_dynamic_routing.extensions import bgp as bgp_ext
from neutron_dynamic_routing._i18n import _, _LE, _LI, _LW
from neutron_dynamic_routing.services.bgp.agent.driver import exceptions as driver_exc  # noqa
from neutron_dynamic_routing.services.bgp.common import constants as bgp_consts  # noqa
from neutron_dynamic_routing.services.bgp.common import keystore

LOG = logging.getLogger(__name__)


class BgpDrAgent(manager.Manager):
    """BGP Dynamic Routing agent service manager.

    Note that the public methods of this class are exposed as the server side
    of an rpc interface.  The neutron server uses
    api.rpc.agentnotifiers.bgp_dr_rpc_agent_api.BgpDrAgentNotifyApi as the
    client side to execute the methods here. For more information about
    changing rpc interfaces, see
    https://docs.openstack.org/neutron/latest/contributor/internals/rpc_api.html.

    API version history:
        1.0 initial Version
    """
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, host, conf=None):
        super(BgpDrAgent, self).__init__()
        self.needs_resync_reasons = collections.defaultdict(list)
        self.needs_full_sync_reason = None

        self.cache = BgpSpeakerCache()
        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = BgpDrPluginApi(bgp_consts.BGP_PLUGIN,
                                         self.context, host)
        self.host = host
        self.initialize_driver(conf)
        self.bgpvpn_rpc = bgpvpn_rpc.BGPVPNRpcApi(bgpvpn_constants.BGPVPN,
                                                  self.context, host)
        self.bgpvpn_notifier = BgpBatchedEventNotifier(self)

    @utils.synchronized('bgp-dr-agent')
    def peer_up_callback(self, remote_ip, remote_as, **kwargs):
        peer_state = bgp_consts.PEER_CONNECTIVITY_UP
        self.plugin_rpc.update_bgp_dragent_peer_state(self.context, self.host,
                                                      remote_ip, remote_as,
                                                      peer_state)

    @utils.synchronized('bgp-dr-agent')
    def peer_down_callback(self, remote_ip, remote_as, **kwargs):
        peer_state = bgp_consts.PEER_CONNECTIVITY_DOWN
        self.plugin_rpc.update_bgp_dragent_peer_state(self.context, self.host,
                                                      remote_ip, remote_as,
                                                      peer_state)

    @utils.synchronized('bgp-dr-agent')
    def path_change_callback(self, route_type, **kwargs):
        if route_type not in bgpvpn_constants.BGPEVPN_SUPPORTED_ROUTE_TYPES:
            LOG.warning(_LW("Unsupported route type {} from driver").format(
                route_type))
            return
        vni = kwargs['vni']
        bgpvpn = self.cache.get_bgpvpn_by_vni(vni)
        if not bgpvpn:
            LOG.debug("Ignoring path event on unknown VNI {}: {}".format(
                vni, kwargs))
            return
        kwargs['route_type'] = route_type
        kwargs['bgpvpn_id'] = bgpvpn['id']
        self.bgpvpn_notifier.queue_event(kwargs)

    def initialize_driver(self, conf):
        self.conf = conf or cfg.CONF.BGP
        try:
            kwargs = {'peer_up_callback': self.peer_up_callback,
                      'peer_down_callback': self.peer_down_callback,
                      'path_change_callback': self.path_change_callback}

            self.dr_driver_cls = (
                    importutils.import_object(self.conf.bgp_speaker_driver,
                                              self.conf, **kwargs))
        except ImportError:
            LOG.exception(_LE("Error while importing BGP speaker driver %s"),
                          self.conf.bgp_speaker_driver)
            raise SystemExit(1)

    def _handle_driver_failure(self, bgp_speaker_id, method, driver_exec):
        self.schedule_resync(reason=driver_exec,
                             speaker_id=bgp_speaker_id)
        LOG.error(_LE('Call to driver for BGP Speaker %(bgp_speaker)s '
                      '%(method)s has failed with exception '
                      '%(driver_exec)s.'),
                  {'bgp_speaker': bgp_speaker_id,
                   'method': method,
                   'driver_exec': driver_exec})

    def after_start(self):
        self.run()
        LOG.info(_LI("BGP Dynamic Routing agent started"))

    def run(self):
        """Activate BGP Dynamic Routing agent."""
        self.sync_state(self.context)
        self.periodic_resync(self.context)

    @runtime.synchronized('bgp-dragent')
    def sync_state(self, context, full_sync=None, bgp_speakers=None):
        try:
            hosted_bgp_speakers = self.plugin_rpc.get_bgp_speakers(context)
            hosted_bgp_speaker_ids = [bgp_speaker['id']
                                      for bgp_speaker in hosted_bgp_speakers]
            cached_bgp_speakers = self.cache.get_bgp_speaker_ids()
            for bgp_speaker_id in cached_bgp_speakers:
                if bgp_speaker_id not in hosted_bgp_speaker_ids:
                    self.remove_bgp_speaker_from_dragent(bgp_speaker_id)

            resync_all = not bgp_speakers or full_sync
            only_bs = set() if resync_all else set(bgp_speakers)
            for hosted_bgp_speaker in hosted_bgp_speakers:
                hosted_bs_id = hosted_bgp_speaker['id']
                if resync_all or hosted_bs_id in only_bs:
                    if not self.cache.is_bgp_speaker_added(hosted_bs_id):
                        self.safe_configure_dragent_for_bgp_speaker(
                            hosted_bgp_speaker)
                        continue
                    self.sync_bgp_speaker(hosted_bgp_speaker)
                    resync_reason = "Periodic route cache refresh"
                    self.schedule_resync(speaker_id=hosted_bs_id,
                                         reason=resync_reason)
        except Exception as e:
            self.schedule_full_resync(reason=e)
            LOG.error(_LE('Unable to sync BGP speaker state.'))

    def sync_bgp_speaker_bgpvpns(self, bgp_speaker):
        # NOTE(alegacy): Only consider bgpvpns that have at least one
        # network or router associated; otherwise there is no point in
        # receiving anything from the peer.
        bgpvpn_ids = set([v['id'] for v in bgp_speaker['bgpvpns']
                          if v['networks'] or v['routers']])
        cached_bgpvpn_ids = set(self.cache.get_bgpvpn_ids(bgp_speaker['id']))

        removed_bgpvpn_ids = cached_bgpvpn_ids - bgpvpn_ids
        for bgpvpn_id in removed_bgpvpn_ids:
            self.remove_bgpvpn_from_speaker(bgp_speaker['id'], bgpvpn_id)

        added_bgpvpn_ids = bgpvpn_ids - cached_bgpvpn_ids
        for bgpvpn in bgp_speaker['bgpvpns']:
            if bgpvpn['id'] in added_bgpvpn_ids:
                self.add_bgpvpn_to_speaker(bgp_speaker['id'], bgpvpn)

    def sync_bgp_speaker(self, bgp_speaker):
        # sync BGP Speakers
        bgp_peer_ips = set(
            [bgp_peer['peer_ip'] for bgp_peer in bgp_speaker['peers']])
        cached_bgp_peer_ips = set(
            self.cache.get_bgp_peer_ips(bgp_speaker['id']))
        removed_bgp_peer_ips = cached_bgp_peer_ips - bgp_peer_ips

        for bgp_peer_ip in removed_bgp_peer_ips:
            self.remove_bgp_peer_from_bgp_speaker(bgp_speaker['id'],
                                                  bgp_peer_ip)
        if bgp_peer_ips:
            self.add_bgp_peers_to_bgp_speaker(bgp_speaker)

        # sync advertise routes
        cached_adv_routes = self.cache.get_adv_routes(bgp_speaker['id'])
        adv_routes = bgp_speaker['advertised_routes']
        if cached_adv_routes == adv_routes:
            return

        for cached_route in cached_adv_routes:
            if cached_route not in adv_routes:
                self.withdraw_route_via_bgp_speaker(bgp_speaker['id'],
                                                    bgp_speaker['local_as'],
                                                    cached_route)

        self.advertise_routes_via_bgp_speaker(bgp_speaker)

        # sync vpns
        self.sync_bgp_speaker_bgpvpns(bgp_speaker)

    @utils.exception_logger()
    def _periodic_resync_helper(self, context):
        """Resync the BgpDrAgent state at the configured interval."""
        if self.needs_resync_reasons or self.needs_full_sync_reason:
            full_sync = self.needs_full_sync_reason
            reasons = self.needs_resync_reasons
            # Reset old reasons
            self.needs_full_sync_reason = None
            self.needs_resync_reasons = collections.defaultdict(list)
            if full_sync:
                LOG.debug("resync all: %(reason)s", {"reason": full_sync})
            for bgp_speaker, reason in reasons.items():
                LOG.debug("resync (%(bgp_speaker)s): %(reason)s",
                          {"reason": reason, "bgp_speaker": bgp_speaker})
            self.sync_state(
                context, full_sync=full_sync, bgp_speakers=reasons.keys())

    # NOTE: spacing is set 1 sec. The actual interval is controlled
    # by neutron/service.py which defaults to CONF.periodic_interval
    @periodic_task.periodic_task(spacing=1)
    def periodic_resync(self, context):
        LOG.debug("Started periodic resync.")
        self._periodic_resync_helper(context)

    @runtime.synchronized('bgp-dr-agent')
    def bgp_speaker_create_end(self, context, payload):
        """Handle bgp_speaker_create_end notification event."""
        bgp_speaker_id = payload['bgp_speaker']['id']
        LOG.debug('Received BGP speaker create notification for '
                  'speaker_id=%(speaker_id)s from the neutron server.',
                  {'speaker_id': bgp_speaker_id})
        self.add_bgp_speaker_helper(bgp_speaker_id)

    @runtime.synchronized('bgp-dr-agent')
    def bgp_speaker_remove_end(self, context, payload):
        """Handle bgp_speaker_remove_end notification event."""

        bgp_speaker_id = payload['bgp_speaker']['id']
        LOG.debug('Received BGP speaker remove notification for '
                  'speaker_id=%(speaker_id)s from the neutron server.',
                  {'speaker_id': bgp_speaker_id})
        self.remove_bgp_speaker_from_dragent(bgp_speaker_id)

    @runtime.synchronized('bgp-dr-agent')
    def bgp_peer_association_end(self, context, payload):
        """Handle bgp_peer_association_end notification event."""

        bgp_peer_id = payload['bgp_peer']['peer_id']
        bgp_speaker_id = payload['bgp_peer']['speaker_id']
        LOG.debug('Received BGP peer associate notification for '
                  'speaker_id=%(speaker_id)s peer_id=%(peer_id)s '
                  'from the neutron server.',
                  {'speaker_id': bgp_speaker_id,
                   'peer_id': bgp_peer_id})
        self.add_bgp_peer_helper(bgp_speaker_id, bgp_peer_id)

    @runtime.synchronized('bgp-dr-agent')
    def bgp_peer_disassociation_end(self, context, payload):
        """Handle bgp_peer_disassociation_end notification event."""

        bgp_peer_ip = payload['bgp_peer']['peer_ip']
        bgp_speaker_id = payload['bgp_peer']['speaker_id']
        LOG.debug('Received BGP peer disassociate notification for '
                  'speaker_id=%(speaker_id)s peer_ip=%(peer_ip)s '
                  'from the neutron server.',
                  {'speaker_id': bgp_speaker_id,
                   'peer_ip': bgp_peer_ip})
        self.remove_bgp_peer_from_bgp_speaker(bgp_speaker_id, bgp_peer_ip)

    @runtime.synchronized('bgp-dr-agent')
    def bgp_routes_advertisement_end(self, context, payload):
        """Handle bgp_routes_advertisement_end notification event."""

        bgp_speaker_id = payload['advertise_routes']['speaker_id']
        LOG.debug('Received routes advertisement end notification '
                  'for speaker_id=%(speaker_id)s from the neutron server.',
                  {'speaker_id': bgp_speaker_id})
        routes = payload['advertise_routes']['routes']
        self.add_routes_helper(bgp_speaker_id, routes)

    @runtime.synchronized('bgp-dr-agent')
    def bgp_routes_withdrawal_end(self, context, payload):
        """Handle bgp_routes_withdrawal_end notification event."""

        bgp_speaker_id = payload['withdraw_routes']['speaker_id']
        LOG.debug('Received route withdrawal notification for '
                  'speaker_id=%(speaker_id)s from the neutron server.',
                  {'speaker_id': bgp_speaker_id})
        routes = payload['withdraw_routes']['routes']
        self.withdraw_routes_helper(bgp_speaker_id, routes)

    def add_bgp_speaker_helper(self, bgp_speaker_id):
        """Add BGP speaker."""
        bgp_speaker = self.safe_get_bgp_speaker_info(bgp_speaker_id)
        if bgp_speaker:
            self.add_bgp_speaker_on_dragent(bgp_speaker)

    def add_bgp_peer_helper(self, bgp_speaker_id, bgp_peer_id):
        """Add BGP peer."""
        # Ideally BGP Speaker must be added by now, If not then let's
        # re-sync.
        if not self.cache.is_bgp_speaker_added(bgp_speaker_id):
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason="BGP Speaker Out-of-sync")
            return

        bgp_peer = self.safe_get_bgp_peer_info(bgp_speaker_id,
                                               bgp_peer_id)
        if bgp_peer:
            bgp_speaker_as = self.cache.get_bgp_speaker_local_as(
                                                            bgp_speaker_id)
            self.add_bgp_peer_to_bgp_speaker(bgp_speaker_id,
                                             bgp_speaker_as,
                                             bgp_peer)

    def add_routes_helper(self, bgp_speaker_id, routes):
        """Advertise routes to BGP speaker."""
        # Ideally BGP Speaker must be added by now, If not then let's
        # re-sync.
        if not self.cache.is_bgp_speaker_added(bgp_speaker_id):
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason="BGP Speaker Out-of-sync")
            return

        bgp_speaker_as = self.cache.get_bgp_speaker_local_as(bgp_speaker_id)
        for route in routes:
            self.advertise_route_via_bgp_speaker(bgp_speaker_id,
                                                 bgp_speaker_as,
                                                 route)
            if self.is_resync_scheduled(bgp_speaker_id):
                break

    def withdraw_routes_helper(self, bgp_speaker_id, routes):
        """Withdraw routes advertised by BGP speaker."""
        # Ideally BGP Speaker must be added by now, If not then let's
        # re-sync.
        if not self.cache.is_bgp_speaker_added(bgp_speaker_id):
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason="BGP Speaker Out-of-sync")
            return

        bgp_speaker_as = self.cache.get_bgp_speaker_local_as(bgp_speaker_id)
        for route in routes:
            self.withdraw_route_via_bgp_speaker(bgp_speaker_id,
                                                bgp_speaker_as,
                                                route)
            if self.is_resync_scheduled(bgp_speaker_id):
                break

    def safe_get_bgp_speaker_info(self, bgp_speaker_id):
        try:
            bgp_speaker = self.plugin_rpc.get_bgp_speaker_info(self.context,
                                                               bgp_speaker_id)
            if not bgp_speaker:
                LOG.warning(_LW('BGP Speaker %s has been deleted.'),
                            bgp_speaker_id)
            return bgp_speaker
        except Exception as e:
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason=e)
            LOG.error(_LE('BGP Speaker %(bgp_speaker)s info call '
                          'failed with reason=%(e)s.'),
                      {'bgp_speaker': bgp_speaker_id, 'e': e})

    def safe_get_bgp_peer_info(self, bgp_speaker_id, bgp_peer_id):
        try:
            bgp_peer = self.plugin_rpc.get_bgp_peer_info(self.context,
                                                         bgp_peer_id)
            if not bgp_peer:
                LOG.warning(_LW('BGP Peer %s has been deleted.'), bgp_peer)
            return bgp_peer
        except Exception as e:
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason=e)
            LOG.error(_LE('BGP peer %(bgp_peer)s info call '
                          'failed with reason=%(e)s.'),
                      {'bgp_peer': bgp_peer_id, 'e': e})

    @utils.exception_logger()
    def safe_configure_dragent_for_bgp_speaker(self, bgp_speaker):
        try:
            self.add_bgp_speaker_on_dragent(bgp_speaker)
        except (bgp_ext.BgpSpeakerNotFound, RuntimeError):
            LOG.warning(_LW('BGP speaker %s may have been deleted and its '
                            'resources may have already been disposed.'),
                     bgp_speaker['id'])

    def add_bgp_speaker_on_dragent(self, bgp_speaker):
        # Caching BGP speaker details in BGPSpeakerCache. Will be used
        # during smooth.
        self.cache.put_bgp_speaker(bgp_speaker)

        LOG.debug('Calling driver for adding BGP speaker %(speaker_id)s,'
                  ' speaking for local_as %(local_as)s',
                  {'speaker_id': bgp_speaker['id'],
                   'local_as': bgp_speaker['local_as']})
        try:
            self.dr_driver_cls.add_bgp_speaker(bgp_speaker['local_as'])
        except driver_exc.BgpSpeakerAlreadyScheduled:
            return
        except Exception as e:
            self._handle_driver_failure(bgp_speaker['id'],
                                        'add_bgp_speaker', e)

        # Add peer and route information to the driver.
        self.add_bgp_peers_to_bgp_speaker(bgp_speaker)
        for bgpvpn in bgp_speaker['bgpvpns']:
            if not bgpvpn['networks'] and not bgpvpn['routers']:
                # NOTE(alegacy): Only consider bgpvpns that have at least one
                # network or router associated; otherwise there is no point in
                # receiving anything from the far end.
                continue
            self.add_bgpvpn_to_speaker(bgp_speaker['id'], bgpvpn)
        self.advertise_routes_via_bgp_speaker(bgp_speaker)
        self.schedule_resync(speaker_id=bgp_speaker['id'],
                             reason="Periodic route cache refresh")

    def remove_bgp_speaker_from_dragent(self, bgp_speaker_id):
        if self.cache.is_bgp_speaker_added(bgp_speaker_id):
            bgp_speaker_as = self.cache.get_bgp_speaker_local_as(
                                                        bgp_speaker_id)
            self.cache.remove_bgp_speaker_by_id(bgp_speaker_id)

            LOG.debug('Calling driver for removing BGP speaker %(speaker_as)s',
                      {'speaker_as': bgp_speaker_as})
            try:
                self.dr_driver_cls.delete_bgp_speaker(bgp_speaker_as)
            except Exception as e:
                self._handle_driver_failure(bgp_speaker_id,
                                            'remove_bgp_speaker', e)
            return

        # Ideally, only the added speakers can be removed by the neutron
        # server. Looks like there might be some synchronization
        # issue between the server and the agent. Let's initiate a re-sync
        # to resolve the issue.
        self.schedule_resync(speaker_id=bgp_speaker_id,
                             reason="BGP Speaker Out-of-sync")

    def add_bgp_peers_to_bgp_speaker(self, bgp_speaker):
        for bgp_peer in bgp_speaker['peers']:
            self.add_bgp_peer_to_bgp_speaker(bgp_speaker['id'],
                                             bgp_speaker['local_as'],
                                             bgp_peer)
            if self.is_resync_scheduled(bgp_speaker['id']):
                break

    def add_bgp_peer_to_bgp_speaker(self, bgp_speaker_id,
                                    bgp_speaker_as, bgp_peer):
        if self.cache.get_bgp_peer_by_ip(bgp_speaker_id, bgp_peer['peer_ip']):
            return

        self.cache.put_bgp_peer(bgp_speaker_id, bgp_peer)

        LOG.debug('Calling driver interface for adding BGP peer %(peer_ip)s '
                  'remote_as=%(remote_as)s to BGP Speaker running for '
                  'local_as=%(local_as)d',
                  {'peer_ip': bgp_peer['peer_ip'],
                   'remote_as': bgp_peer['remote_as'],
                   'local_as': bgp_speaker_as})
        try:
            password = keystore.get_bgp_peer_password(bgp_peer['id'])
            hold_time = bgp_peer.get('hold_time')
            self.dr_driver_cls.add_bgp_peer(bgp_speaker_as,
                                            bgp_peer['peer_ip'],
                                            bgp_peer['remote_as'],
                                            bgp_peer['auth_type'],
                                            password,
                                            enable_evpn=True,
                                            hold_time=hold_time,
                                            connect_mode='both')
        except Exception as e:
            self._handle_driver_failure(bgp_speaker_id,
                                        'add_bgp_peer', e)

    def remove_bgp_peer_from_bgp_speaker(self, bgp_speaker_id, bgp_peer_ip):
        # Ideally BGP Speaker must be added by now, If not then let's
        # re-sync.
        if not self.cache.is_bgp_speaker_added(bgp_speaker_id):
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason="BGP Speaker Out-of-sync")
            return

        if self.cache.is_bgp_peer_added(bgp_speaker_id, bgp_peer_ip):
            self.cache.remove_bgp_peer_by_ip(bgp_speaker_id, bgp_peer_ip)

            bgp_speaker_as = self.cache.get_bgp_speaker_local_as(
                                                        bgp_speaker_id)

            LOG.debug('Calling driver interface to remove BGP peer '
                      '%(peer_ip)s from BGP Speaker running for '
                      'local_as=%(local_as)d',
                      {'peer_ip': bgp_peer_ip, 'local_as': bgp_speaker_as})
            try:
                self.dr_driver_cls.delete_bgp_peer(bgp_speaker_as,
                                                   bgp_peer_ip)
            except Exception as e:
                self._handle_driver_failure(bgp_speaker_id,
                                            'remove_bgp_peer', e)
            return

        # Ideally, only the added peers can be removed by the neutron
        # server. Looks like there might be some synchronization
        # issue between the server and the agent. Let's initiate a re-sync
        # to resolve the issue.
        self.schedule_resync(speaker_id=bgp_speaker_id,
                             reason="BGP Peer Out-of-sync")

    def advertise_routes_via_bgp_speaker(self, bgp_speaker):
        for route in bgp_speaker['advertised_routes']:
            self.advertise_route_via_bgp_speaker(bgp_speaker['id'],
                                                 bgp_speaker['local_as'],
                                                 route)
            if self.is_resync_scheduled(bgp_speaker['id']):
                break

    def advertise_route_via_bgp_speaker(self, bgp_speaker_id,
                                        bgp_speaker_as, route):
        if self.cache.is_route_advertised(bgp_speaker_id, route):
            # Requested route already advertised. Hence, Nothing to be done.
            return
        self.cache.put_adv_route(bgp_speaker_id, route)

        LOG.debug('Calling driver for advertising prefix: %(cidr)s, '
                  'next_hop: %(nexthop)s',
                  {'cidr': route['destination'],
                   'nexthop': route['next_hop']})
        try:
            self.dr_driver_cls.advertise_route(bgp_speaker_as,
                                               route['destination'],
                                               route['next_hop'])
        except Exception as e:
            self._handle_driver_failure(bgp_speaker_id,
                                        'advertise_route', e)

    def withdraw_route_via_bgp_speaker(self, bgp_speaker_id,
                                       bgp_speaker_as, route):
        if self.cache.is_route_advertised(bgp_speaker_id, route):
            self.cache.remove_adv_route(bgp_speaker_id, route)
            LOG.debug('Calling driver for withdrawing prefix: %(cidr)s, '
                  'next_hop: %(nexthop)s',
                  {'cidr': route['destination'],
                   'nexthop': route['next_hop']})
            try:
                self.dr_driver_cls.withdraw_route(bgp_speaker_as,
                                                  route['destination'],
                                                  route['next_hop'])
            except Exception as e:
                self._handle_driver_failure(bgp_speaker_id,
                                            'withdraw_route', e)
            return

        # Ideally, only the advertised routes can be withdrawn by the
        # neutron server. Looks like there might be some synchronization
        # issue between the server and the agent. Let's initiate a re-sync
        # to resolve the issue.
        self.schedule_resync(speaker_id=bgp_speaker_id,
                             reason="Advertised routes Out-of-sync")

    def schedule_full_resync(self, reason):
        LOG.debug('Recording full resync request for all BGP Speakers '
                  'with reason=%s', reason)
        self.needs_full_sync_reason = reason

    def schedule_resync(self, reason, speaker_id):
        """Schedule a full resync for a given BGP Speaker.
        If no BGP Speaker is specified, resync all BGP Speakers.
        """
        LOG.debug('Recording resync request for BGP Speaker %s '
                  'with reason=%s', speaker_id, reason)
        self.needs_resync_reasons[speaker_id].append(reason)

    def is_resync_scheduled(self, bgp_speaker_id):
        if bgp_speaker_id not in self.needs_resync_reasons:
            return False

        reason = self.needs_resync_reasons[bgp_speaker_id]
        # Re-sync scheduled for the queried BGP speaker. No point
        # continuing further. Let's stop processing and wait for
        # re-sync to happen.
        LOG.debug('Re-sync already scheduled for BGP Speaker %s '
                  'with reason=%s', bgp_speaker_id, reason)
        return True

    @staticmethod
    def _get_route_dist(bgp_speaker_as, bgpvpn):
        """Determine what to use for a route distinguisher value.

        The data passed down from the server bgpvpn plugin includes a route
        distinguisher value but it is optional and when present is formatted
        as a list.  The driver API requires a single RD value so either use
        the first value from the RD list provided by the server or build one
        based on the AS and the VNI value.
        """
        route_dist = bgpvpn.get('rd')
        if not route_dist:
            route_dist = ["%s:%d" % (bgp_speaker_as, bgpvpn['vni'])]
        return str(route_dist[0])

    def add_bgpvpn_to_speaker(self, bgp_speaker_id, bgpvpn):
        if not self.cache.is_bgp_speaker_added(bgp_speaker_id):
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason="BGP Speaker Out-of-sync")
            return

        bgp_speaker_as = self.cache.get_bgp_speaker_local_as(bgp_speaker_id)
        route_dist = self._get_route_dist(bgp_speaker_as, bgpvpn)

        LOG.debug('Calling driver interface for adding %(type)s VRF %(rd)s '
                  'for import_rt %(import_rt)s and export_rt %(export_rt)s '
                  'to BGP Speaker running for local_as=%(local_as)d',
                  {'rd': route_dist,
                   'type': bgpvpn['type'],
                   'import_rt': bgpvpn['import_rt'],
                   'export_rt': bgpvpn['export_rt'],
                   'local_as': bgp_speaker_as})

        try:
            self.dr_driver_cls.add_vrf(bgp_speaker_as, route_dist,
                                       [str(r) for r in bgpvpn['import_rt']],
                                       [str(r) for r in bgpvpn['export_rt']],
                                       str(bgpvpn['type']))
            self.cache.put_bgpvpn(bgp_speaker_id, bgpvpn)
            return True
        except Exception as e:
            self._handle_driver_failure(bgp_speaker_id, 'add_vrf', e)

    def remove_bgpvpn_from_speaker(self, bgp_speaker_id, bgpvpn_id):
        if not self.cache.is_bgp_speaker_added(bgp_speaker_id):
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason="BGP Speaker Out-of-sync")
            return

        bgpvpn = self.cache.get_bgpvpn_by_id(bgp_speaker_id, bgpvpn_id)
        if not bgpvpn:
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason="VPN not present on BGP Speaker")
            return

        bgp_speaker_as = self.cache.get_bgp_speaker_local_as(bgp_speaker_id)
        route_dist = self._get_route_dist(bgp_speaker_as, bgpvpn)

        self.cache.remove_bgpvpn_by_id(bgp_speaker_id, bgpvpn_id)

        LOG.debug('Calling driver interface for removing %(type)s VRF %(rd)s '
                  'for import_rt %(import_rt)s and export_rt %(export_rt)s '
                  'from BGP Speaker running for local_as=%(local_as)d',
                  {'rd': route_dist,
                   'type': bgpvpn['type'],
                   'import_rt': bgpvpn['import_rt'],
                   'export_rt': bgpvpn['export_rt'],
                   'local_as': bgp_speaker_as})
        try:
            self.dr_driver_cls.delete_vrf(bgp_speaker_as, route_dist)
        except Exception as e:
            self._handle_driver_failure(bgp_speaker_id, 'delete_vrf', e)

    @utils.synchronized('bgp-dr-agent')
    def bgp_speaker_vpn_associated(self, context, payload):
        """Handle bgp_speaker_vpn_associated notification event."""
        bgpvpn = payload['bgpvpn']
        bgp_speaker_id = bgpvpn['speaker_id']

        LOG.debug('Received BGP VPN association notification for '
                  'speaker_id=%(speaker_id)s bgpvpn=%(bgpvpn)s from the '
                  'neutron server.',
                  {'speaker_id': bgp_speaker_id,
                   'bgpvpn': bgpvpn['bgpvpn']})
        self.add_bgpvpn_to_speaker(bgp_speaker_id, bgpvpn['bgpvpn'])

    @utils.synchronized('bgp-dr-agent')
    def bgp_speaker_vpn_disassociated(self, context, payload):
        """Handle bgp_speaker_vpn_associated notification event."""
        bgpvpn = payload['bgpvpn']
        bgp_speaker_id = bgpvpn['speaker_id']
        bgpvpn_id = bgpvpn['bgpvpn_id']

        LOG.debug('Received BGP VPN disassociation notification for '
                  'speaker_id=%(speaker_id)s bgpvpn_id=%(bgpvpn_id)s from the '
                  'neutron server.',
                  {'speaker_id': bgp_speaker_id,
                   'bgpvpn_id': bgpvpn_id})
        self.remove_bgpvpn_from_speaker(bgp_speaker_id, bgpvpn_id)

    def bgpvpn_update_gateways(self, updates):
        self.bgpvpn_rpc.bgpvpn_update_gateways(self.context, updates)

    def bgpvpn_update_devices(self, updates):
        self.bgpvpn_rpc.bgpvpn_update_devices(self.context, updates)


class BgpDrPluginApi(object):
    """Agent side of BgpDrAgent RPC API.

    This class implements the client side of an rpc interface.
    The server side of this interface can be found in
    api.rpc.handlers.bgp_speaker_rpc.BgpSpeakerRpcCallback.
    For more information about changing rpc interfaces, see
    doc/source/devref/rpc_api.rst.

    API version history:
        1.0 - Initial version.
    """
    def __init__(self, topic, context, host):
        self.context = context
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_bgp_speakers(self, context):
        """Make a remote process call to retrieve all BGP speakers info."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_bgp_speakers', host=self.host)

    def get_bgp_speaker_info(self, context, bgp_speaker_id):
        """Make a remote process call to retrieve a BGP speaker info."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_bgp_speaker_info',
                          bgp_speaker_id=bgp_speaker_id)

    def get_bgp_peer_info(self, context, bgp_peer_id):
        """Make a remote process call to retrieve a BGP peer info."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_bgp_peer_info',
                          bgp_peer_id=bgp_peer_id)

    def update_bgp_dragent_peer_state(self, context, host,
                                      remote_ip, remote_as,
                                      peer_state):
        """Make a remote process call to save BGP dragent peer state."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_bgp_dragent_peer_state',
                          host=host, remote_ip=remote_ip, remote_as=remote_as,
                          peer_state=peer_state)


class BgpSpeakerCache(object):
    """Agent cache of the current BGP speaker state.

    This class is designed to support the advertisement for
    multiple BGP speaker via a single driver interface.

    Version history:
        1.0 - Initial version for caching the state of BGP speaker.
    """
    def __init__(self):
        self.cache = {}

    def get_bgp_speaker_ids(self):
        return self.cache.keys()

    def put_bgp_speaker(self, bgp_speaker):
        if bgp_speaker['id'] in self.cache:
            self.remove_bgp_speaker_by_id(self.cache[bgp_speaker['id']])
        self.cache[bgp_speaker['id']] = {'bgp_speaker': bgp_speaker,
                                         'peers': {},
                                         'bgpvpns': {},
                                         'networks': {},
                                         'vnis': {},
                                         'local_devices': {},
                                         'local_gateways': {},
                                         'advertised_routes': []}

    def get_bgp_speaker_by_id(self, bgp_speaker_id):
        if bgp_speaker_id in self.cache:
            return self.cache[bgp_speaker_id]['bgp_speaker']

    def get_bgp_speaker_local_as(self, bgp_speaker_id):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if bgp_speaker:
            return bgp_speaker['local_as']

    def is_bgp_speaker_added(self, bgp_speaker_id):
        return self.get_bgp_speaker_by_id(bgp_speaker_id)

    def remove_bgp_speaker_by_id(self, bgp_speaker_id):
        if bgp_speaker_id in self.cache:
            del self.cache[bgp_speaker_id]

    def put_bgp_peer(self, bgp_speaker_id, bgp_peer):
        if bgp_peer['peer_ip'] in self.get_bgp_peer_ips(bgp_speaker_id):
            del self.cache[bgp_speaker_id]['peers'][bgp_peer['peer_ip']]

        self.cache[bgp_speaker_id]['peers'][bgp_peer['peer_ip']] = bgp_peer

    def is_bgp_peer_added(self, bgp_speaker_id, bgp_peer_ip):
        return self.get_bgp_peer_by_ip(bgp_speaker_id, bgp_peer_ip)

    def get_bgp_peer_ips(self, bgp_speaker_id):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if bgp_speaker:
            return self.cache[bgp_speaker_id]['peers'].keys()

    def get_bgp_peer_by_ip(self, bgp_speaker_id, bgp_peer_ip):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if bgp_speaker:
            return self.cache[bgp_speaker_id]['peers'].get(bgp_peer_ip)

    def remove_bgp_peer_by_ip(self, bgp_speaker_id, bgp_peer_ip):
        if bgp_peer_ip in self.get_bgp_peer_ips(bgp_speaker_id):
            del self.cache[bgp_speaker_id]['peers'][bgp_peer_ip]

    def put_adv_route(self, bgp_speaker_id, route):
        self.cache[bgp_speaker_id]['advertised_routes'].append(route)

    def is_route_advertised(self, bgp_speaker_id, route):
        routes = self.cache[bgp_speaker_id]['advertised_routes']
        for r in routes:
            if r['destination'] == route['destination'] and (
                    route['next_hop'] is None or
                    r['next_hop'] == route['next_hop']):
                return True
        return False

    def remove_adv_route(self, bgp_speaker_id, route):
        routes = self.cache[bgp_speaker_id]['advertised_routes']
        updated_routes = [r for r in routes if (
            r['destination'] != route['destination'])]
        self.cache[bgp_speaker_id]['advertised_routes'] = updated_routes

    def get_adv_routes(self, bgp_speaker_id):
        return self.cache[bgp_speaker_id]['advertised_routes']

    def get_state(self):
        bgp_speaker_ids = self.get_bgp_speaker_ids()
        num_bgp_speakers = len(bgp_speaker_ids)
        num_bgp_peers = 0
        num_advertised_routes = 0
        for bgp_speaker_id in bgp_speaker_ids:
            bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
            num_bgp_peers += len(bgp_speaker['peers'])
            num_advertised_routes += len(bgp_speaker['advertised_routes'])
        return {'bgp_speakers': num_bgp_speakers,
                'bgp_peers': num_bgp_peers,
                'advertise_routes': num_advertised_routes}

    def put_bgpvpn(self, bgp_speaker_id, bgpvpn):
        if bgpvpn['id'] in self.get_bgpvpn_ids(bgp_speaker_id):
            del self.cache[bgp_speaker_id]['bgpvpns'][bgpvpn['id']]

        self.cache[bgp_speaker_id]['bgpvpns'][bgpvpn['id']] = bgpvpn
        for network_id in bgpvpn['networks']:
            # l3vpn can be associated to multiple networks
            self.cache[bgp_speaker_id]['networks'][network_id] = bgpvpn

        vni = bgpvpn['vni']
        self.cache[bgp_speaker_id]['vnis'][vni] = bgpvpn

    def is_bgpvpn_added(self, bgp_speaker_id, bgpvpn_id):
        return self.get_bgpvpn_by_id(bgp_speaker_id, bgpvpn_id)

    def get_bgpvpn_ids(self, bgp_speaker_id):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if bgp_speaker:
            return self.cache[bgp_speaker_id]['bgpvpns'].keys()

    def get_bgpvpn_by_id(self, bgp_speaker_id, bgpvpn_id):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if bgp_speaker:
            return self.cache[bgp_speaker_id]['bgpvpns'].get(bgpvpn_id)

    def get_bgpvpns_by_network_id(self, network_id):
        # NOTE(alegacy): VPNs can be mapped to multiple speakers even though
        # we only need to support a single association.  For the sake of
        # completeness return a list of (speaker_id, bgpvpn) so that we
        # treat each one individually.
        bgpvpns = [(bgp_speaker_id, c['networks'][network_id])
                   for bgp_speaker_id, c in six.iteritems(self.cache)
                   if network_id in c['networks']]
        return bgpvpns

    def get_bgpvpn_by_vni(self, vni):
        # NOTE(alegacy): VPNs can be mapped to multiple speakers even though
        # we only need to support a single association.  For the sake of
        # completeness return a list of (speaker_id, bgpvpn) so that we
        # treat each one individually.
        vnis = [c['vnis'][vni]
                for c in six.itervalues(self.cache)
                if vni in c['vnis']]
        assert len(vnis) <= 1
        return vnis[0] if vnis else None

    def remove_bgpvpn_by_id(self, bgp_speaker_id, bgpvpn_id):
        bgpvpn = self.get_bgpvpn_by_id(bgp_speaker_id, bgpvpn_id)
        if not bgpvpn:
            return
        speaker_cache = self.cache[bgp_speaker_id]
        for network_id in bgpvpn['networks']:
            # l3vpn can be associated to multiple networks
            self.cache[bgp_speaker_id]['networks'].pop(network_id, None)

        vni = bgpvpn['vni']
        speaker_cache['vnis'].pop(vni, None)
        speaker_cache['bgpvpns'].pop(bgpvpn_id, None)
        speaker_cache['local_devices'].pop(vni, None)
        speaker_cache['local_gateways'].pop(vni, None)

    def get_bgpvpn_device_keys(self, bgp_speaker_id, bgpvpn):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if not bgp_speaker:
            return []
        speaker_cache = self.cache[bgp_speaker_id]
        if bgpvpn['vni'] not in speaker_cache['local_devices']:
            return []
        network = speaker_cache['local_devices'][bgpvpn['vni']]
        return network.keys()

    @staticmethod
    def make_device_key(device):
        ip_family = netaddr.IPAddress(device['gateway_ip']).version
        return "v{}-{}-{}".format(
            ip_family, device['ip_address'], device['mac_address'])

    def put_bgpvpn_device(self, bgp_speaker_id, bgpvpn, device):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if not bgp_speaker:
            return
        speaker_cache = self.cache[bgp_speaker_id]
        if bgpvpn['vni'] not in speaker_cache['local_devices']:
            speaker_cache['local_devices'][bgpvpn['vni']] = {}
        network = speaker_cache['local_devices'][bgpvpn['vni']]
        network[self.make_device_key(device)] = device

    def remove_bgpvpn_device(self, bgp_speaker_id, bgpvpn, device):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if not bgp_speaker:
            return
        key = self.make_device_key(device)
        cached_device = self.get_bgpvpn_device(bgp_speaker_id, bgpvpn, key)
        if not cached_device:
            return
        network = self.cache[bgp_speaker_id]['local_devices'][bgpvpn['vni']]
        del network[key]

    def get_bgpvpn_device(self, bgp_speaker_id, bgpvpn, key):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if not bgp_speaker:
            return
        speaker_cache = self.cache[bgp_speaker_id]
        if bgpvpn['vni'] not in speaker_cache['local_devices']:
            return
        network = speaker_cache['local_devices'][bgpvpn['vni']]
        return network.get(key)

    def put_bgpvpn_gateway(self, bgp_speaker_id, bgpvpn, gateway_ip):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if not bgp_speaker:
            return
        speaker_cache = self.cache[bgp_speaker_id]
        if bgpvpn['vni'] not in speaker_cache['local_gateways']:
            speaker_cache['local_gateways'][bgpvpn['vni']] = set()
        speaker_cache['local_gateways'][bgpvpn['vni']].add(gateway_ip)

    def remove_bgpvpn_gateway(self, bgp_speaker_id, bgpvpn, gateway_ip):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if not bgp_speaker:
            return
        speaker_cache = self.cache[bgp_speaker_id]
        if bgpvpn['vni'] not in speaker_cache['local_gateways']:
            return
        gateways = speaker_cache['local_gateways'][bgpvpn['vni']]
        if gateway_ip in gateways:
            gateways.remove(gateway_ip)

    def get_bgpvpn_gateways(self, bgp_speaker_id, bgpvpn):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if not bgp_speaker:
            return set()
        speaker_cache = self.cache[bgp_speaker_id]
        if bgpvpn['vni'] not in speaker_cache['local_gateways']:
            return set()
        return speaker_cache['local_gateways'][bgpvpn['vni']]


class BgpDrAgentWithStateReport(BgpDrAgent):

    def __init__(self, host, conf=None):
        super(BgpDrAgentWithStateReport,
              self).__init__(host, conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self.agent_state = {
            'agent_type': bgp_consts.AGENT_TYPE_BGP_ROUTING,
            'binary': 'neutron-bgp-dragent',
            'configurations': {},
            'host': host,
            'topic': bgp_consts.BGP_DRAGENT,
            'start_flag': True}
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        LOG.debug("Report state task started")
        try:
            self.agent_state.get('configurations').update(
                self.cache.get_state())
            ctx = context.get_admin_context_without_session()
            agent_status = self.state_rpc.report_state(ctx, self.agent_state,
                                                       True)
            if agent_status == n_const.AGENT_REVIVED:
                LOG.info(_LI("Agent has just been revived. "
                             "Scheduling full sync"))
                self.schedule_full_resync(
                        reason=_("Agent has just been revived"))
        except AttributeError:
            # This means the server does not support report_state
            LOG.warning(_LW("Neutron server does not support state report. "
                            "State report for this agent will be disabled."))
            self.heartbeat.stop()
            self.run()
            return
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))
            return
        if self.agent_state.pop('start_flag', None):
            self.run()

    @utils.synchronized('bgp-dr-agent')
    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.schedule_full_resync(
                reason=_("BgpDrAgent updated: %s") % payload)
        LOG.info(_LI("agent_updated by server side %s!"), payload)

    def after_start(self):
        LOG.info(_LI("BGP dynamic routing agent started"))


class BgpDrL2PopHandler(l2population_rpc.L2populationRpcCallBackMixin):

    def __init__(self, manager):
        self.manager = manager

    def fdb_add(self, context, fdb_entries):
        self.manager.fdb_add(context, fdb_entries)

    def fdb_remove(self, context, fdb_entries):
        self.manager.fdb_remove(context, fdb_entries)

    def fdb_update(self, context, fdb_entries):
        self.manager.fdb_update(context, fdb_entries)


class BgpBatchedEventNotifier(object):
    """Batches events received from BGP to minimize RPC calls to the server.

    This call handles incoming events from BGP speakers.  Events are queued
    internal for a configured period of time and then sent to the server for
    processing and distribution to other nodes.

    Conflicting events that are received are merged before sending to the
    server (i.e., a route that is withdrawn and the re-added is only sent up
    as an add to the server).
    """

    # Accumulate events for 5 seconds before sending an RPC event
    BATCH_INTERVAL = 5

    def __init__(self, agent, *args, **kwargs):
        self.agent = agent
        self.batch = batch_notifier.BatchNotifier(
            self.BATCH_INTERVAL, self.batch_callback)
        self.gateway_events = {}
        self.device_events = {}

    def queue_event(self, event):
        self.batch.queue_event(event)

    def queue_retry(self):
        event = {'__retry__': True}
        self.batch.queue_event(event)

    def _merge_gateway_event(self, event):
        bgpvpn_id = event['bgpvpn_id']
        if bgpvpn_id not in self.gateway_events:
            self.gateway_events[bgpvpn_id] = {}
        # replace the latest state for this entry
        self.gateway_events[bgpvpn_id][event['nexthop']] = event

    def _format_gateway_updates(self):
        """Formats VTEP events to comply with the server RPC format.

        see networking_bgp.neutron.api.rpc.py for details.
        """
        updates = {}
        for bgpvpn_id, events in six.iteritems(self.gateway_events):
            updates[bgpvpn_id] = [{'ip_address': e['nexthop'],
                                   'withdrawn': e['is_withdraw']}
                                  for e in six.itervalues(events)]
        return updates

    def _merge_device_event(self, event):
        bgpvpn_id = event['bgpvpn_id']
        if bgpvpn_id not in self.device_events:
            self.device_events[bgpvpn_id] = {}
        # replace the latest state for this entry
        key = "%s-%s" % (event['mac_address'], event['ip_address'])
        self.device_events[bgpvpn_id][key] = event

    def _format_device_updates(self):
        """Formats device events to comply with the server RPC format.

        see networking_bgp.neutron.api.rpc.py for details.
        """
        updates = {}
        for bgpvpn_id, events in six.iteritems(self.device_events):
            records = []
            for key, event in six.iteritems(events):
                records.append({
                    'ip_address': event['ip_address'],
                    'mac_address': event['mac_address'],
                    'gateway_ip': event['nexthop'],
                    'withdrawn': event['is_withdraw']})
            updates[bgpvpn_id] = records
        return updates

    def send_gateway_updates(self):
        updates = self._format_gateway_updates()
        try:
            self.agent.bgpvpn_update_gateways(updates)
            self.gateway_events = {}
        except oslo_messaging.exceptions.MessagingTimeout:
            LOG.error(_LE("Timeout while sending gateway updates; retrying"))
            self.queue_retry()

    def send_device_updates(self):
        updates = self._format_device_updates()
        try:
            self.agent.bgpvpn_update_devices(updates)
            self.device_events = {}
        except oslo_messaging.exceptions.MessagingTimeout:
            LOG.error(_LE("Timeout while sending device updates; retrying"))
            self.queue_retry()

    def merge_event(self, event):
        LOG.debug("New event: {}".format(event))
        if '__retry__' in event:
            return  # internal sentinel value; drop it.
        route_type = event['route_type']
        if route_type == bgpvpn_constants.BGPEVPN_RT_MULTICAST_ETAG_ROUTE:
            self._merge_gateway_event(event)
        elif route_type == bgpvpn_constants.BGPEVPN_RT_MAC_IP_ADV_ROUTE:
            self._merge_device_event(event)
        else:
            LOG.warning(_LW("Ignoring unsupported route type {}: {}").format(
                route_type, event))

    def batch_callback(self, events):
        """Handles all batched events at the end of the batch interval."""
        for event in events:
            self.merge_event(event)
        self.send_gateway_updates()
        self.send_device_updates()


class BgpDrAgentWithL2Pop(BgpDrAgentWithStateReport):

    def __init__(self, host, conf=None):
        super(BgpDrAgentWithL2Pop, self).__init__(host, conf)
        self.l2pop_handler = None
        self.l2pop_rpc = l2population_rpc.L2populationRpcQueryMixin()
        self.l2pop_connection = None
        self.setup_l2pop_rpc_handler()

    def setup_l2pop_rpc_handler(self):
        # We need to listen for l2pop RPC events to distribute the FDB
        # entries to BGP peers.
        self.l2pop_handler = BgpDrL2PopHandler(self)
        consumers = [[topics.L2POPULATION, topics.UPDATE]]
        self.l2pop_connection = agent_rpc.create_consumers(
            [self.l2pop_handler], topics.AGENT, consumers)
        self.l2pop_connection.consume_in_threads()

    @staticmethod
    def _make_device(mac_address, ip_address, gateway_ip):
        return {'mac_address': mac_address,
                'ip_address': ip_address,
                'gateway_ip': gateway_ip}

    def advertise_flooding_entry(self, bgp_speaker_id, bgpvpn, gateway_ip):
        LOG.info((_LI("advertising flooding entry via {}:{} to speaker {}").
                  format(gateway_ip, bgpvpn['vni'], bgp_speaker_id)))
        kwargs = {'ethernet_tag_id': bgpvpn['vni'],
                  'ip_addr': gateway_ip,
                  'next_hop': gateway_ip}

        speaker_as = self.cache.get_bgp_speaker_local_as(bgp_speaker_id)
        route_dist = self._get_route_dist(speaker_as, bgpvpn)

        try:
            self.dr_driver_cls.advertise_evpn_route(
                speaker_as,
                bgpvpn_constants.BGPEVPN_RT_MULTICAST_ETAG_ROUTE,
                route_dist, **kwargs)
        except Exception as e:
            self._handle_driver_failure(bgp_speaker_id,
                                        'advertise_evpn_route', e)
        self.cache.put_bgpvpn_gateway(bgp_speaker_id, bgpvpn, gateway_ip)

    def withdraw_flooding_entry(self, bgp_speaker_id, bgpvpn, gateway_ip):
        LOG.info((_LI("withdrawing flooding entry via {}:{} to speaker {}").
                  format(gateway_ip, bgpvpn['vni'], bgp_speaker_id)))
        kwargs = {'ethernet_tag_id': bgpvpn['vni'],
                  'ip_addr': gateway_ip}

        speaker_as = self.cache.get_bgp_speaker_local_as(bgp_speaker_id)
        route_dist = self._get_route_dist(speaker_as, bgpvpn)

        try:
            self.dr_driver_cls.withdraw_evpn_route(
                speaker_as,
                bgpvpn_constants.BGPEVPN_RT_MULTICAST_ETAG_ROUTE,
                route_dist, **kwargs)
        except Exception as e:
            self._handle_driver_failure(bgp_speaker_id,
                                        'withdraw_evpn_route', e)
        self.cache.remove_bgpvpn_gateway(bgp_speaker_id, bgpvpn, gateway_ip)

    def add_device_to_cache(self, bgp_speaker_id, bgpvpn, gateway_ip,
                            mac_address, ip_address):
        device = self._make_device(mac_address, ip_address, gateway_ip)
        self.cache.put_bgpvpn_device(bgp_speaker_id, bgpvpn, device)

    def advertise_mac_ip_entry(self, bgp_speaker_id, bgpvpn, gateway_ip,
                               mac_address, ip_address):
        LOG.info((_LI("advertising MAC:IP {}:{} via {}:{} to speaker {}").
                 format(mac_address, ip_address, gateway_ip, bgpvpn['vni'],
                        bgp_speaker_id)))
        kwargs = {'esi': 0,
                  'ethernet_tag_id': 0,
                  'ip_addr': ip_address,
                  'mac_addr': mac_address,
                  'vni': bgpvpn['vni'],
                  'next_hop': gateway_ip,
                  'tunnel_type': 'vxlan'}

        speaker_as = self.cache.get_bgp_speaker_local_as(bgp_speaker_id)
        route_dist = self._get_route_dist(speaker_as, bgpvpn)

        try:
            # NOTE(alegacy): regardless of whether we had previously
            # advertised this mac:ip from a different next hop or not we
            # simply advertise it again.  The driver and the peer routers
            # implicitly revoke the previous advertisement and use the
            # current advertised next hop to reach this mac:ip.
            self.dr_driver_cls.advertise_evpn_route(
                speaker_as,
                bgpvpn_constants.BGPEVPN_RT_MAC_IP_ADV_ROUTE,
                route_dist, **kwargs)
        except Exception as e:
            self._handle_driver_failure(bgp_speaker_id,
                                        'advertise_evpn_route', e)
        self.add_device_to_cache(bgp_speaker_id, bgpvpn, gateway_ip,
                                 mac_address, ip_address)

    def device_present_in_cache(self, bgp_speaker_id, bgpvpn, gateway_ip,
                                mac_address, ip_address):
        device = self._make_device(mac_address, ip_address, gateway_ip)
        key = self.cache.make_device_key(device)
        cached_device = self.cache.get_bgpvpn_device(
            bgp_speaker_id, bgpvpn, key)
        if self._same_device(device, cached_device):
            return True
        return False

    def remove_device_from_cache(self, bgp_speaker_id, bgpvpn, gateway_ip,
                                 mac_address, ip_address):
        device = self._make_device(mac_address, ip_address, gateway_ip)
        self.cache.remove_bgpvpn_device(bgp_speaker_id, bgpvpn, device)

    def withdraw_mac_ip_entry(self, bgp_speaker_id, bgpvpn, gateway_ip,
                              mac_address, ip_address):
        if not self.device_present_in_cache(
                bgp_speaker_id, bgpvpn, gateway_ip, mac_address, ip_address):
            LOG.debug(("nothing to withdraw for MAC:IP {}:{} via {}:{} to "
                       "speaker {}").
                      format(mac_address, ip_address, gateway_ip,
                             bgpvpn['vni'], bgp_speaker_id))
            return
        LOG.info((_LI("withdrawing MAC:IP {}:{} via {}:{} to speaker {}").
                 format(mac_address, ip_address, gateway_ip,
                        bgpvpn['vni'], bgp_speaker_id)))
        kwargs = {'esi': 0,
                  'ethernet_tag_id': 0,
                  'ip_addr': ip_address,
                  'mac_addr': mac_address}

        speaker_as = self.cache.get_bgp_speaker_local_as(bgp_speaker_id)
        route_dist = self._get_route_dist(speaker_as, bgpvpn)

        try:
            self.dr_driver_cls.withdraw_evpn_route(
                speaker_as,
                bgpvpn_constants.BGPEVPN_RT_MAC_IP_ADV_ROUTE,
                route_dist, **kwargs)
        except Exception as e:
            self._handle_driver_failure(bgp_speaker_id,
                                        'withdraw_evpn_route', e)
        self.remove_device_from_cache(bgp_speaker_id, bgpvpn, gateway_ip,
                                      mac_address, ip_address)

    @staticmethod
    def select_gateway_ip(agent_ips):
        """Select an VTEP IP address to use for route advertisements.

        Our l2population distribution supports a mixed environment of IPv4
        and IPv6 addresses.  For the purpose of advertising to the BGP
        domain we should only advertise a single nexthop route for each
        destination.  If we were to advertise multiple the driver would only
        publish the first one anyway; therefore, we need to pick one.  To
        facilitate transitions from IPv4 to IPv6 we are going to pick the
        IPv6 address because our assuming is that if IPv6 addresses have
        been added then the customer wants to start using them and
        eventually they will remove the IPv4 addresses.
        """
        agent_list = agent_ips.split(',')
        agent_v6 = [a for a in agent_list if netaddr.IPAddress(a).version == 6]
        if agent_v6:
            return agent_v6[0]
        agent_v4 = [a for a in agent_list if netaddr.IPAddress(a).version == 4]
        if agent_v4:
            return agent_v4[0]
        return None

    def _process_fdb_for_speaker(self, bgp_speaker_id, bgpvpn, fdb_entries,
                                 mac_handler, flood_handler):
        """
        Handle new FDB entries for a given bgp_speaker.
        """
        port_entries = fdb_entries['ports']
        LOG.debug("processing FDB entries for speaker {} bgpvpn {}: {}".format(
            bgp_speaker_id, bgpvpn['id'], fdb_entries))
        for agent_ips, ports in six.iteritems(port_entries):
            gateway_ip = self.select_gateway_ip(agent_ips)
            for p in ports:
                if p != constants.FLOODING_ENTRY:
                    mac_handler(bgp_speaker_id, bgpvpn, gateway_ip,
                                p.mac_address, p.ip_address)
                else:
                    flood_handler(bgp_speaker_id, bgpvpn, gateway_ip)

    @utils.synchronized('bgp-dr-agent')
    def fdb_add(self, context, fdb_entries):
        """
        Handle new FDB entries published to this agent (or all agents).
        """
        LOG.debug("fdb_add received: {}".format(fdb_entries))
        if fdb_entries.get('source') == bgpvpn_constants.BGPVPN:
            return  # Ignore data originating from this BGP agent or another.
        for network_id, fdb_entries in six.iteritems(fdb_entries):
            bgpvpns = self.cache.get_bgpvpns_by_network_id(network_id)
            for bgp_speaker_id, bgpvpn in bgpvpns:
                self._process_fdb_for_speaker(
                    bgp_speaker_id, bgpvpn, fdb_entries,
                    self.advertise_mac_ip_entry,
                    self.advertise_flooding_entry)

    @utils.synchronized('bgp-dr-agent')
    def fdb_remove(self, context, fdb_entries):
        """
        Handle new FDB entries published to this agent (or all agents).
        """
        LOG.debug("fdb_remove received {}".format(fdb_entries))
        if fdb_entries.get('source') == bgpvpn_constants.BGPVPN:
            return  # Ignore data originating from this BGP agent or another.
        for network_id, fdb_entries in six.iteritems(fdb_entries):
            bgpvpns = self.cache.get_bgpvpns_by_network_id(network_id)
            for bgp_speaker_id, bgpvpn in bgpvpns:
                self._process_fdb_for_speaker(
                    bgp_speaker_id, bgpvpn, fdb_entries,
                    self.withdraw_mac_ip_entry,
                    self.withdraw_flooding_entry)

    def _process_ip_change_for_network(self, bgp_speaker_id, bgpvpn,
                                       ip_changes):
        """
        Handle new FDB entries for a given network_id.
        """
        LOG.debug("processing FDB changes for speaker {} bgpvpn {}: {}".format(
            bgp_speaker_id, bgpvpn['id'], ip_changes))
        for agent_ips, changes in six.iteritems(ip_changes):
            gateway_ip = self.select_gateway_ip(agent_ips)
            for p in changes.get('before', []):
                self.withdraw_mac_ip_entry(
                    bgp_speaker_id, bgpvpn, gateway_ip,
                    p.mac_address, p.ip_address)
            for p in changes.get('after', []):
                self.advertise_mac_ip_entry(
                    bgp_speaker_id, bgpvpn, gateway_ip,
                    p.mac_address, p.ip_address)

    @utils.synchronized('bgp-dr-agent')
    def fdb_update(self, context, fdb_entries):
        LOG.debug("fdb_update received {}".format(fdb_entries))
        ip_delta = fdb_entries['chg_ip']
        for network_id, ip_changes in six.iteritems(ip_delta):
            bgpvpns = self.cache.get_bgpvpns_by_network_id(network_id)
            for bgp_speaker_id, bgpvpn in bgpvpns:
                self._process_ip_change_for_network(
                    bgp_speaker_id, bgpvpn, ip_changes)

    @staticmethod
    def _same_device(a, b):
        return (a['ip_address'] == b['ip_address'] and
                a['gateway_ip'] == b['gateway_ip'])

    def _audit_mac_ip_entry(self, bgp_speaker_id, bgpvpn,
                            mac_address, ip_address, gateway_ip, keys):
        device = self._make_device(mac_address, ip_address, gateway_ip)
        key = self.cache.make_device_key(device)
        cached_device = self.cache.get_bgpvpn_device(
            bgp_speaker_id, bgpvpn, key)
        if not cached_device:
            # Add new entry
            self.advertise_mac_ip_entry(
                bgp_speaker_id, bgpvpn, gateway_ip, mac_address, ip_address)
        elif self._same_device(device, cached_device):
            # No action necessary
            keys.remove(self.cache.make_device_key(cached_device))
        else:
            # Replace stale entry
            self.withdraw_mac_ip_entry(
                bgp_speaker_id, bgpvpn,
                cached_device['gateway_ip'],
                cached_device['mac_address'],
                cached_device['ip_address'])
            keys.remove(self.cache.make_device_key(cached_device))
            self.advertise_mac_ip_entry(
                bgp_speaker_id, bgpvpn, gateway_ip, mac_address, ip_address)

    def _audit_flood_entry(self, bgp_speaker_id, bgpvpn, gateway_ip, keys):
        if gateway_ip in keys:
            keys.remove(gateway_ip)
            return
        self.advertise_flooding_entry(bgp_speaker_id, bgpvpn, gateway_ip)

    def _audit_fdb_for_speaker(self, bgp_speaker_id, bgpvpn, fdb_entries):
        original_devices = set(self.cache.get_bgpvpn_device_keys(
            bgp_speaker_id, bgpvpn))
        original_vteps = self.cache.get_bgpvpn_gateways(bgp_speaker_id, bgpvpn)
        port_entries = fdb_entries['ports']
        for agent_ips, ports in six.iteritems(port_entries):
            gateway_ip = self.select_gateway_ip(agent_ips)
            for p in ports:
                if p == constants.FLOODING_ENTRY:
                    self._audit_flood_entry(bgp_speaker_id, bgpvpn,
                                            gateway_ip,
                                            original_vteps)
                else:
                    self._audit_mac_ip_entry(bgp_speaker_id, bgpvpn,
                                             p.mac_address,
                                             p.ip_address,
                                             gateway_ip,
                                             original_devices)
        # Any remaining devices in initial cached set need to be withdrawn
        for key in original_devices:
            cached_device = self.cache.get_bgpvpn_device(
                bgp_speaker_id, bgpvpn, key)
            self.withdraw_mac_ip_entry(
                bgp_speaker_id, bgpvpn,
                cached_device['gateway_ip'],
                cached_device['mac_address'],
                cached_device['ip_address'])
        # Any remaining vteps in initial cached set need to be withdrawn
        for gateway_ip in original_vteps:
            self.withdraw_flooding_entry(bgp_speaker_id, bgpvpn, gateway_ip)

    def add_bgpvpn_to_speaker(self, bgp_speaker_id, bgpvpn):
        if not super(BgpDrAgentWithL2Pop, self).add_bgpvpn_to_speaker(
                bgp_speaker_id, bgpvpn):
            return
        LOG.debug("Auditing FDB for bgpvpn_id {}".format(bgpvpn['id']))
        # Get the latest copy of the FDB entries for this network
        fdb_entries = self.l2pop_rpc.get_fdb_entries(
            self.context, bgpvpn['networks'],
            source=bgpvpn_constants.BGPVPN)
        # Check them against what we have already cached and refresh peers
        for network_id, fdb_entries in six.iteritems(fdb_entries):
            bgpvpns = self.cache.get_bgpvpns_by_network_id(network_id)
            for speaker_id, bgpvpn in bgpvpns:
                if speaker_id != bgp_speaker_id:
                    continue
                self._audit_fdb_for_speaker(
                    bgp_speaker_id, bgpvpn, fdb_entries)
