"""empty message

Revision ID: ab2f1e5fd64d
Revises: 1b48457ac697
Create Date: 2022-07-19 22:18:48.030479

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ab2f1e5fd64d'
down_revision = '1b48457ac697'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('created', sa.Integer(), nullable=True))
    op.add_column('users', sa.Column('fullname', sa.String(length=128), nullable=True))
    op.add_column('users', sa.Column('mail', sa.String(length=128), nullable=True))
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
    # ### end Alembic commands ###
