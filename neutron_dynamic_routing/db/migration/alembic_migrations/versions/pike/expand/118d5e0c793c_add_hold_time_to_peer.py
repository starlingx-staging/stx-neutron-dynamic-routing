# Copyright 2016 OpenStack Foundation
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
#
# Copyright (c) 2017 Wind River Systems, Inc.
#

"""Add hold time to BGP Peer table

Revision ID: 118d5e0c793c
Revises: 3e79fd73353d
Create Date: 2017-10-30 16:15:00.00000

"""

# revision identifiers, used by Alembic.
revision = '118d5e0c793c'
down_revision = '3e79fd73353d'

from alembic import op
import sqlalchemy as sa

from neutron_dynamic_routing.services.bgp.common import constants


def upgrade():
    op.add_column('bgp_peers',
                  sa.Column('hold_time', sa.Integer,
                            default=constants.DEFAULT_HOLD_TIME))


def downgrade():
    pass
