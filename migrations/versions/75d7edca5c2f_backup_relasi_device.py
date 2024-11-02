"""backup relasi device

Revision ID: 75d7edca5c2f
Revises: 413f577bb8fb
Create Date: 2024-09-15 02:46:50.685531

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '75d7edca5c2f'
down_revision = '413f577bb8fb'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('backup_data', schema=None) as batch_op:
        batch_op.add_column(sa.Column('device_id', sa.String(length=36), nullable=True))
        
        
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('backup_data', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('device_id')

    # ### end Alembic commands ###
