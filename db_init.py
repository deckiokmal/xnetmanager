from src import db, create_app
from src.models.app_models import User, Role, Permission, UserRoles, RolePermissions

def initialize():
    app = create_app()
    with app.app_context():
        # Buat database dan tabel-tabelnya jika belum ada
        db.create_all()

        # Buat peran dan izin default
        roles_permissions = {
            "Admin": [
                "Manage Roles",
                "Manage Users",
                "Manage Devices",
                "Manage Templates",
                "Manage Config",
                "View Devices",
                "View Templates",
                "Manage Profile",
            ],
            "User": [
                "Manage Devices",
                "Manage Templates",
                "Manage Config",
                "View Devices",
                "View Templates",
                "Manage Profile",
            ],
            "View": ["View Devices", "View Templates", "Manage Profile"],
        }

        # Tambahkan role dan permission ke dalam database
        for role_name, permissions in roles_permissions.items():
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                role = Role(name=role_name)
                db.session.add(role)
                db.session.commit()

            for perm_name in permissions:
                permission = Permission.query.filter_by(name=perm_name).first()
                if not permission:
                    permission = Permission(
                        name=perm_name, description=f"Dapat {perm_name.lower()}"
                    )
                    db.session.add(permission)
                    db.session.commit()

                if permission not in role.permissions:
                    role.permissions.append(permission)

            db.session.commit()

        # Buat pengguna default dengan peran Admin
        default_email = "xnetmanager@example.com"
        default_password = (
            "xnetmanager"  # Jangan gunakan password default seperti ini di produksi
        )

        if not User.query.filter_by(email=default_email).first():
            admin_role = Role.query.filter_by(name="Admin").first()
            # Tambahkan first_name dan last_name di sini
            admin_user = User(
                first_name="Xnet",
                last_name="Manager",
                email=default_email,
                password_hash=default_password
            )
            # Atur atribut tambahan
            admin_user.roles.append(admin_role)
            db.session.add(admin_user)
            db.session.commit()

        print(
            "Inisialisasi database selesai dengan peran dan izin default serta pengguna admin."
        )


if __name__ == "__main__":
    initialize()
