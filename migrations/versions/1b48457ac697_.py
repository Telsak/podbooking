"""empty message

Revision ID: 1b48457ac697
Revises: fdec0bf0a7f0
Create Date: 2022-07-19 22:13:48.908995

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1b48457ac697'
down_revision = 'fdec0bf0a7f0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('getapod_bookings', sa.Column('confirmation', sa.String(length=64), nullable=True))
    op.add_column('users', sa.Column('created', sa.Integer(), nullable=False))
    op.add_column('users', sa.Column('fullname', sa.String(length=128), nullable=False))
    op.add_column('users', sa.Column('mail', sa.String(length=128), nullable=False))
    op.add_column('users', sa.Column('profile', sa.String(length=64), nullable=True))
    op.alter_column('users', 'username',
               existing_type=sa.VARCHAR(length=64),
               nullable=False)
    op.alter_column('users', 'password',
               existing_type=sa.VARCHAR(length=128),
               nullable=False)
    op.alter_column('users', 'flag',
               existing_type=sa.VARCHAR(length=64),
               nullable=False)
    op.alter_column('users', 'last_login',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.create_unique_constraint(None, 'users', ['password'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='unique')
    op.alter_column('users', 'last_login',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('users', 'flag',
               existing_type=sa.VARCHAR(length=64),
               nullable=True)
    op.alter_column('users', 'password',
               existing_type=sa.VARCHAR(length=128),
               nullable=True)
    op.alter_column('users', 'username',
               existing_type=sa.VARCHAR(length=64),
               nullable=True)
    op.drop_column('users', 'profile')
    op.drop_column('users', 'mail')
    op.drop_column('users', 'fullname')
    op.drop_column('users', 'created')
    op.drop_column('getapod_bookings', 'confirmation')
    # ### end Alembic commands ###
