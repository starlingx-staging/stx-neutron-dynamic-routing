#    Copyright 2016 Huawei Technologies India Pvt Limited.
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

"""add table bgp_speaker_vpn_bindings

Revision ID: 3e79fd73353d
Revises: 24858e626447
Create Date: 2016-07-12 01:34:41.466300

"""

# revision identifiers, used by Alembic.
revision = '3e79fd73353d'
down_revision = '24858e626447'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'bgp_speaker_vpn_bindings',
        sa.Column('bgp_speaker_id', sa.String(length=36),
                  sa.ForeignKey('bgp_speakers.id', ondelete='CASCADE'),
                  nullable=False, primary_key=True),
        sa.Column('bgpvpn_id', sa.String(length=36),
                  sa.ForeignKey('bgpvpns.id', ondelete='CASCADE'),
                  nullable=False, primary_key=True),
    )
