#
# All Rights Reserved.
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
#
# Copyright (c) 2017 Wind River Systems, Inc.
#


import contextlib
import os
import subprocess

import keyring
from tsconfig import tsconfig as tsc


# Service domain name to access the keyring for password management
NEUTRON_KEYRING_SERVICE = 'neutron'


@contextlib.contextmanager
def _mounted(remote_dir, local_dir):
    local_dir = os.path.abspath(local_dir)
    try:
        subprocess.check_output(
            ["/bin/nfs-mount", remote_dir, local_dir],
            stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        raise OSError(("mount operation failed: "
                       "command={}, retcode={}, output='{}'").format(
            e.cmd, e.returncode, e.output))
    try:
        yield
    finally:
        try:
            subprocess.check_output(
                ["/bin/umount", local_dir],
                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise OSError(("umount operation failed: "
                           "command={}, retcode={}, output='{}'").format(
                e.cmd, e.returncode, e.output))


def mount_keyring(func):
    """Mount the keyring directory if we are running on a node that
    does not have it available as a local directory (i.e., standby controller)
    """
    def _mount_keyring_decorator(*args, **kwargs):
        remote_dir = "controller-platform-nfs:" + tsc.PLATFORM_PATH
        local_dir = os.path.join(tsc.VOLATILE_PATH, 'neutron', 'keyring')
        if not os.path.exists(local_dir):
            os.makedirs(local_dir)
        with _mounted(remote_dir, local_dir):
            os.environ["XDG_DATA_HOME"] = (
                local_dir + "/.keyring/" + tsc.SW_VERSION)
            return func(*args, **kwargs)
    return _mount_keyring_decorator


def store_bgp_peer_password(bgp_peer_id, password):
    if password:
        keyring.set_password(NEUTRON_KEYRING_SERVICE, bgp_peer_id, password)


@mount_keyring
def get_bgp_peer_password(bgp_peer_id):
    return keyring.get_password(NEUTRON_KEYRING_SERVICE, bgp_peer_id)


def delete_bgp_peer_password(bgp_peer_id):
    try:
        keyring.delete_password(NEUTRON_KEYRING_SERVICE, bgp_peer_id)
    except keyring.errors.PasswordDeleteError:
        pass  # password likely not set
