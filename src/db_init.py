import logging
from flask import current_app
from src.models.app_models import User, Role, Permission
from src import db


def initialize():
    """
    Inisialisasi database, membuat tabel jika belum ada,
    serta menambahkan peran, izin, dan pengguna default.
    """
    with current_app.app_context():
        try:
            # Buat tabel jika belum ada
            db.create_all()

            # Definisi peran dan izin
            roles_permissions = {
                "Admin": [
                    "Manage Roles",
                    "Manage Users",
                    "Manage Devices",
                    "Manage Templates",
                    "Manage Configuration File",
                    "Config and Backup",
                    "View Devices",
                    "View Templates",
                    "Manage Profile",
                    "Manage Backups",
                ],
                "User": [
                    "Manage Devices",
                    "Manage Templates",
                    "Manage Configuration File",
                    "Config and Backup",
                    "View Devices",
                    "View Templates",
                    "Manage Profile",
                    "Manage Backups",
                ],
                "View": ["View Devices", "View Templates", "Manage Profile"],
            }

            # Tambahkan peran dan izin ke database jika belum ada
            for role_name, permissions in roles_permissions.items():
                role = Role.query.filter_by(name=role_name).first()
                if not role:
                    role = Role(name=role_name)
                    db.session.add(role)

                for perm_name in permissions:
                    permission = Permission.query.filter_by(name=perm_name).first()
                    if not permission:
                        permission = Permission(
                            name=perm_name,
                            description=f"Permission to {perm_name.lower()}",
                        )
                        db.session.add(permission)
                        db.session.commit()

                    if permission not in role.permissions:
                        role.permissions.append(permission)

            db.session.commit()

            # Buat pengguna default jika belum ada
            default_email = "xnetmanager@example.com"
            default_password = (
                "xnetmanager"  # Jangan gunakan password default ini di produksi
            )

            if not User.query.filter_by(email=default_email).first():
                admin_role = Role.query.filter_by(name="Admin").first()
                admin_user = User(
                    first_name="Xnet",
                    last_name="Manager",
                    email=default_email,
                    password_hash=default_password,  # Harus dienkripsi di sistem produksi
                )
                admin_user.roles.append(admin_role)
                db.session.add(admin_user)
                db.session.commit()

            logging.info(
                "Inisialisasi database selesai dengan peran, izin, dan pengguna default."
            )

        except Exception as e:
            db.session.rollback()
            logging.error(f"Error during database initialization: {e}")
            raise
