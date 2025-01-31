"""Description of changes

Revision ID: 58c959a725aa
Revises: a182e15346a1
Create Date: 2024-07-28 19:27:52.257317

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '58c959a725aa'
down_revision = 'a182e15346a1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('comment_reaction',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('comment_id', sa.Integer(), nullable=False),
    sa.Column('reaction', sa.String(length=20), nullable=False),
    sa.ForeignKeyConstraint(['comment_id'], ['comment.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('follows', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_follows_timestamp'), ['timestamp'], unique=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('follows', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_follows_timestamp'))

    op.drop_table('comment_reaction')
    # ### end Alembic commands ###
