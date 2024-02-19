from functools import wraps
from flask import flash, redirect, request, url_for
from flask_login import current_user


# Decorator untuk user yang belum login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("You need to login first", "info")
            return redirect(url_for("main.login"))
        return f(*args, **kwargs)

    return decorated_function


# Decorator Role Based Access Control menggunakan flask session.
def role_required(role_name, page):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated:
                user_roles = [role.name for role in current_user.roles]
                if role_name not in user_roles:
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
