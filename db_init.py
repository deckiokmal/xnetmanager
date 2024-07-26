from src import db, create_app
from src.models.users_model import User, Role, Permission


def initialize():
    app = create_app()
    with app.app_context():
        # Buat database dan tabel-tabelnya jika belum ada
        db.create_all()

        # Buat role dan permission default
        role_admin = Role(name="Admin")
        permission_manage_roles = Permission(
            name="Manage Roles", description="Dapat mengelola peran dalam sistem"
        )
        permission_manage_users = Permission(
            name="Manage Users", description="Dapat mengelola pengguna dalam sistem"
        )
        permission_manage_devices = Permission(
            name="Manage Devices", description="Dapat mengelola perangkat jaringan"
        )
        permission_manage_templates = Permission(
            name="Manage Templates", description="Dapat mengelola template konfigurasi"
        )
        permission_manage_config = Permission(
            name="Manage Config", description="Dapat mengelola konfigurasi sistem"
        )

        # Tambahkan izin ke dalam peran
        role_admin.permissions.extend(
            [
                permission_manage_roles,
                permission_manage_users,
                permission_manage_devices,
                permission_manage_templates,
                permission_manage_config,
            ]
        )

        # Cek apakah role dan permission sudah ada di database
        if not Role.query.filter_by(name="Admin").first():
            db.session.add(role_admin)
        if not Permission.query.filter_by(name="Manage Roles").first():
            db.session.add(permission_manage_roles)
        if not Permission.query.filter_by(name="Manage Users").first():
            db.session.add(permission_manage_users)
        if not Permission.query.filter_by(name="Manage Devices").first():
            db.session.add(permission_manage_devices)
        if not Permission.query.filter_by(name="Manage Templates").first():
            db.session.add(permission_manage_templates)
        if not Permission.query.filter_by(name="Manage Config").first():
            db.session.add(permission_manage_config)

        # Commit untuk menyimpan role dan permission ke database
        db.session.commit()

        # Buat pengguna default dengan peran admin
        default_username = "xnetmanager"
        default_password = "xnetmanager"

        if not User.query.filter_by(username=default_username).first():
            admin_user = User(username=default_username, password=default_password)
            admin_user.roles.append(role_admin)
            db.session.add(admin_user)

            # Commit untuk menyimpan user ke database
            db.session.commit()

        print(
            "Database initialization complete with default roles, permissions, and admin user."
        )


if __name__ == "__main__":
    initialize()
