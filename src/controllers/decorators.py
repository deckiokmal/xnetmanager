from functools import wraps
from flask import flash, redirect, request, url_for, session
from flask_login import current_user
from src.models.users_model import Role


# Decorator untuk user yang belum login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Silahkan login terlebih dahulu !", "info")
            return redirect(url_for("main.login"))
        return f(*args, **kwargs)

    return decorated_function


# Decorator untuk memeriksa apakah pengguna memiliki salah satu dari beberapa role
# dan juga memeriksa permissions yang sesuai dengan role yang diperlukan.
def role_required(roles, permissions=None, page=""):
    """
    Dekorator untuk memeriksa apakah pengguna memiliki salah satu dari beberapa role
    dan permissions yang diperlukan untuk mengakses route ini.

    :param roles: Daftar nama role yang diperlukan untuk mengakses route ini.
    :param permissions: Daftar nama permissions yang diperlukan untuk mengakses route ini (opsional).
    :param page: Nama halaman atau fungsi yang digunakan dalam pesan flash (opsional).
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated:
                # Mendapatkan role dari pengguna saat ini
                user_roles = [role.name for role in current_user.roles]

                # Mengecek apakah pengguna memiliki salah satu dari role yang diperlukan
                has_role = any(role in user_roles for role in roles)

                # Mengecek apakah pengguna memiliki permissions yang diperlukan berdasarkan role
                has_permission = True
                if permissions:
                    # Mendapatkan semua role yang dimiliki oleh pengguna saat ini
                    roles_with_permissions = (
                        Role.query.join(Role.permissions)
                        .filter(Role.name.in_(user_roles))
                        .all()
                    )

                    # Mengumpulkan permissions dari semua role yang dimiliki
                    role_permissions = set()
                    for role in roles_with_permissions:
                        role_permissions.update(
                            permission.name for permission in role.permissions
                        )

                    # Mengecek apakah setidaknya satu permission yang diperlukan ada di role_permissions
                    has_permission = any(
                        permission in role_permissions for permission in permissions
                    )

                if not has_role or not has_permission:
                    flash(
                        f"Access Denied. You do not have permission to access the {page}!",
                        "error",
                    )
                    # Menyimpan URL referer sebelum redirect
                    return redirect(request.referrer or url_for("users.dashboard"))
            else:
                flash("You need to login first.", "danger")
                return redirect(url_for("login"))

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Decorator untuk memeriksa apakah pengguna mengaktifkan 2FA atau tidak
def required_2fa(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Cek apakah pengguna sudah login
        if not current_user.is_authenticated:
            return redirect(url_for("main.login"))

        # Cek apakah 2FA diaktifkan untuk pengguna
        if current_user.is_2fa_enabled:
            # Cek apakah pengguna sudah memverifikasi 2FA
            if not session.get("2fa_verified", False):
                return redirect(url_for("main.verify_2fa"))

        return f(*args, **kwargs)

    return decorated_function
