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

"""BGP dragent peer table table

Revision ID: 24858e626447
Revises: f399fa0f5f25
Create Date: 2016-02-23 17:26:15.718638

"""

# revision identifiers, used by Alembic.
revision = '24858e626447'
down_revision = 'f399fa0f5f25'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'bgp_dragent_peer_connectivity_states',
        sa.Column('agent_id', sa.String(36), nullable=False),
        sa.Column('bgp_peer_id', sa.String(36), nullable=False),
        sa.Column('peer_connectivity_state', sa.String(16),
                  nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['bgp_peer_id'], ['bgp_peers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('agent_id', 'bgp_peer_id'))


def downgrade():
    pass
