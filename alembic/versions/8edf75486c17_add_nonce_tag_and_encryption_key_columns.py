"""Add nonce, tag, and encryption_key columns

Revision ID: 8edf75486c17
Revises: 6db7a1456d33
Create Date: 2024-05-14 22:00:07.689119

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8edf75486c17'
down_revision: Union[str, None] = '6db7a1456d33'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('file_metadata', sa.Column('nonce', sa.String(), nullable=True))
    op.add_column('file_metadata', sa.Column('tag', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('file_metadata', 'tag')
    op.drop_column('file_metadata', 'nonce')
    # ### end Alembic commands ###