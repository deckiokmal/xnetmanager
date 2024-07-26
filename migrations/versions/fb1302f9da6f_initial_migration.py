"""Initial migration

Revision ID: fb1302f9da6f
Revises: 
Create Date: 2024-07-26 23:02:28.338960

"""

from alembic import op
import sqlalchemy as sa
from src import db
from src.models.users_model import User, Role, Permission

# revision identifiers, used by Alembic.
revision = "fb1302f9da6f"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Buat Permissions
    permissions = [
        {"name": "Manage Roles", "description": "Permission to manage roles"},
        {"name": "Manage Users", "description": "Permission to manage users"},
        {"name": "View Reports", "description": "Permission to view reports"},
    ]
    op.bulk_insert(
        sa.table(
            "permissions",
            sa.column("name", sa.String),
            sa.column("description", sa.String),
        ),
        permissions,
    )

    # Buat Roles
    roles = [{"name": "Admin"}, {"name": "User"}, {"name": "View"}]
    op.bulk_insert(sa.table("roles", sa.column("name", sa.String)), roles)

    # Tambahkan Permissions ke Role Admin
    admin_role_id = (
        sa.select([sa.func.max(sa.column("id"))])
        .where(sa.column("name") == "Admin")
        .scalar()
    )
    permission_ids = (
        sa.select([sa.column("id")])
        .where(sa.column("name").in_([perm["name"] for perm in permissions]))
        .execute()
        .fetchall()
    )

    role_permissions = [
        {"role_id": admin_role_id, "permission_id": perm_id[0]}
        for perm_id in permission_ids
    ]
    op.bulk_insert(
        sa.table(
            "role_permissions",
            sa.column("role_id", sa.Integer),
            sa.column("permission_id", sa.Integer),
        ),
        role_permissions,
    )

    # Buat User Default
    if (
        not sa.select([sa.column("id")])
        .where(sa.column("username") == "admin")
        .execute()
        .fetchone()
    ):
        op.execute(
            sa.text(
                "INSERT INTO users (username, password, created_at, is_two_factor_authentication_enabled, secret_token) "
                "VALUES (:username, :password, CURRENT_TIMESTAMP, :is_two_factor_authentication_enabled, :secret_token)"
            ).bindparams(
                username="admin",
                password="admin",
                is_two_factor_authentication_enabled=False,
                secret_token="",
            )
        )

        # Tambahkan User ke Role Admin
        admin_user_id = (
            sa.select([sa.column("id")])
            .where(sa.column("username") == "admin")
            .scalar()
        )
        op.execute(
            sa.text(
                "INSERT INTO user_roles (user_id, role_id) VALUES (:user_id, :role_id)"
            ).bindparams(user_id=admin_user_id, role_id=admin_role_id)
        )


def downgrade():
    # Hapus data dan tabel jika diperlukan
    op.execute("DELETE FROM user_roles")
    op.execute("DELETE FROM role_permissions")
    op.execute("DELETE FROM users")
    op.execute("DELETE FROM roles")
    op.execute("DELETE FROM permissions")

    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_table("users")
    op.drop_table("roles")
    op.drop_table("permissions")
