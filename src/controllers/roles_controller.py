from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    current_app,
)
from flask_login import login_required, current_user
from flask_paginate import Pagination, get_page_args
from src import db
from src.models.app_models import User, Role, Permission, UserRoles
from .decorators import role_required, login_required, required_2fa
import logging

# Membuat blueprint roles_bp dan error_bp
roles_bp = Blueprint("roles", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging untuk aplikasi
logging.basicConfig(level=logging.INFO)


@roles_bp.before_app_request
def setup_logging():
    """
    Mengatur level logging untuk aplikasi.
    """
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


@error_bp.app_errorhandler(404)
def page_not_found(error):
    """
    Menangani error 404 dan menampilkan halaman 404.
    """
    current_app.logger.error(f"Error 404: {error}")
    return render_template("main/404.html"), 404


@roles_bp.before_request
def before_request_func():
    """
    Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan.
    Jika tidak, mengembalikan pesan 'Unauthorized access'.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return jsonify({"message": "Unauthorized access"}), 401


@roles_bp.context_processor
def inject_user():
    """
    Menyediakan first_name dan last_name pengguna yang terotentikasi ke dalam template.
    """
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


# --------------------------------------------------------------------------------
# Roles Management Section
# --------------------------------------------------------------------------------


# Halaman Roles
@roles_bp.route("/user_role", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def index():
    """Menampilkan halaman utama untuk mengelola role dan pengguna."""
    all_roles = Role.query.all()  # Mengambil semua role
    all_users = User.query.all()  # Mengambil semua pengguna

    search_query = request.args.get("search", "").lower()  # Mengambil query pencarian
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    # Menerapkan filter pencarian jika ada
    role_query = (
        Role.query.filter(Role.name.ilike(f"%{search_query}%"))
        if search_query
        else Role.query
    )
    total_roles = role_query.count()  # Menghitung total role yang sesuai
    roles = (
        role_query.limit(per_page).offset(offset).all()
    )  # Mengambil role untuk halaman ini

    pagination = Pagination(
        page=page,
        per_page=per_page,
        total=total_roles,
    )

    return render_template(
        "/role_management/index.html",
        roles=roles,
        page=page,
        per_page=per_page,
        pagination=pagination,
        search_query=search_query,
        total_roles=total_roles,
        all_roles=all_roles,
        all_users=all_users,
    )


# Membuat Role Baru
@roles_bp.route("/create_role", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def create_role():
    """Membuat role baru dan menyimpannya ke dalam database."""
    if request.method == "POST":
        role_name = request.form.get("name")
        role_permissions = request.form.getlist("permissions")

        if not role_name or not role_permissions:
            current_app.logger.warning(
                f"User {current_user.email} gagal membuat role baru."
            )
            flash("Nama role dan permissions tidak boleh kosong!", "warning")
            return redirect(url_for("roles.index"))

        if Role.query.filter_by(name=role_name).first():
            current_app.logger.warning(
                f"User {current_user.email} gagal membuat role baru karena role sudah ada."
            )
            flash("Role sudah ada!", "error")
            return redirect(url_for("roles.index"))

        new_role = Role(
            name=role_name,
            permissions=[Permission.query.get(int(p)) for p in role_permissions],
        )
        db.session.add(new_role)
        db.session.commit()
        current_app.logger.info(
            f"User {current_user.email} berhasil membuat role baru."
        )
        flash("Role berhasil ditambah!", "success")
        return redirect(url_for("roles.index"))

    permissions = Permission.query.all()  # Mengambil semua permissions
    return render_template("/role_management/create_role.html", permissions=permissions)


# Memperbarui Role
@roles_bp.route("/role_update/<int:role_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def role_update(role_id):
    """Memperbarui role yang ada berdasarkan ID."""
    role = Role.query.get_or_404(role_id)  # Mengambil role berdasarkan ID

    if request.method == "POST":
        role_name = request.form.get("name")
        selected_permissions = request.form.getlist("permissions")
        selected_users = request.form.getlist("users")

        if not role_name:
            current_app.logger.warning(
                f"User {current_user.email} gagal memperbarui role {role.name} karena nama role kosong."
            )
            flash("Nama role tidak boleh kosong!", "warning")
            return redirect(url_for("roles.role_update", role_id=role_id))

        if Role.query.filter(Role.id != role.id, Role.name == role_name).first():
            current_app.logger.warning(
                f"User {current_user.email} gagal memperbarui role {role.name} karena role dengan nama tersebut sudah ada."
            )
            flash("Role dengan nama tersebut sudah ada!", "error")
        else:
            role.name = role_name

            # Memperbarui asosiasi permissions
            role.permissions = [
                Permission.query.get(int(permission_id))
                for permission_id in selected_permissions
            ]

            # Memperbarui asosiasi pengguna
            role.users = [User.query.get(int(user_id)) for user_id in selected_users]

            db.session.commit()
            current_app.logger.info(
                f"User {current_user.email} berhasil memperbarui role {role.name}."
            )
            flash("Role berhasil diubah.", "success")
            return redirect(url_for("roles.index"))

    # Mengambil pengguna terkait dan semua permissions
    associated_users = (
        User.query.join(UserRoles).filter(UserRoles.role_id == role_id).all()
    )
    all_permissions = Permission.query.all()

    # Mengambil permissions yang terkait dengan role ini
    associated_permissions = {permission.id for permission in role.permissions}

    return render_template(
        "/role_management/role_update.html",
        role=role,
        associated_users=associated_users,
        all_permissions=all_permissions,
        associated_permissions=associated_permissions,
    )


# Menghapus Role
@roles_bp.route("/role_delete/<int:role_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def role_delete(role_id):
    """Menghapus role dari database jika tidak ada asosiasi pengguna atau permissions."""
    role = Role.query.get_or_404(role_id)  # Mengambil role berdasarkan ID

    if role.users:
        current_app.logger.warning(
            f"User {current_user.email} mencoba menghapus role {role.name}, tetapi role ini terasosiasi dengan pengguna."
        )
        flash(
            "Role tidak dapat dihapus karena masih terasosiasi dengan pengguna.",
            "warning",
        )
        return redirect(url_for("roles.index"))
    elif role.permissions:
        current_app.logger.warning(
            f"User {current_user.email} mencoba menghapus role {role.name}, tetapi role ini terasosiasi dengan permissions."
        )
        flash(
            "Role tidak dapat dihapus karena masih terasosiasi dengan permissions.",
            "warning",
        )
        return redirect(url_for("roles.index"))

    db.session.delete(role)
    db.session.commit()
    current_app.logger.info(
        f"User {current_user.email} berhasil menghapus role {role.name}."
    )
    flash("Role berhasil dihapus.", "success")
    return redirect(url_for("roles.index"))


# Menambahkan Pengguna ke Role
@roles_bp.route("/add_user_to_role", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def add_user_to_role():
    """Menambahkan pengguna ke role tertentu."""
    user_id = request.form.get("user_id")
    role_name = request.form.get("role_name")

    user = User.query.get(user_id)
    role = Role.query.filter_by(name=role_name).first()

    if not user:
        current_app.logger.warning(
            f"User {current_user.email} gagal menambahkan role {role_name} karena pengguna tidak ditemukan."
        )
        flash("Pengguna tidak ditemukan", "error")
        return redirect(url_for("roles.index"))

    if not role:
        current_app.logger.warning(
            f"User {current_user.email} gagal menambahkan role {role_name} karena role tidak ditemukan."
        )
        flash("Role tidak ditemukan", "error")
        return redirect(url_for("roles.index"))

    if role not in user.roles:
        user.roles.append(role)
        db.session.commit()
        current_app.logger.info(
            f"User {current_user.email} berhasil menambahkan role {role_name} ke pengguna {user.email}."
        )
        flash("Pengguna berhasil ditambahkan ke role.", "success")
    else:
        current_app.logger.warning(
            f"User {current_user.email} gagal menambahkan role {role_name} ke pengguna {user.email} karena role ini sudah ada."
        )
        flash(f"User {user.email} sudah memiliki role {role_name}.", "warning")

    return redirect(url_for("roles.index"))


# Menghapus pengguna dari role
@roles_bp.route("/remove_user_from_role", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def remove_user_from_role():
    """Menghapus pengguna dari role tertentu."""
    user_id = request.form.get("user_id")
    role_name = request.form.get("role_name")

    user = User.query.get(user_id)
    role = Role.query.filter_by(name=role_name).first()

    if not user:
        current_app.logger.warning(
            f"User {current_user.email} gagal menghapus role {role_name} dari pengguna karena pengguna tidak ditemukan."
        )
        flash("Pengguna tidak ditemukan", "error")
        return redirect(url_for("roles.index"))

    if not role:
        current_app.logger.warning(
            f"User {current_user.email} gagal menghapus role {role_name} dari pengguna karena role tidak ditemukan."
        )
        flash("Role tidak ditemukan", "error")
        return redirect(url_for("roles.index"))

    user_role = UserRoles.query.filter_by(user_id=user.id, role_id=role.id).first()

    if user_role:
        db.session.delete(user_role)
        db.session.commit()
        current_app.logger.info(
            f"User {current_user.email} berhasil menghapus role {role_name} dari pengguna {user.email}."
        )
        flash("Pengguna berhasil dihapus dari role.", "success")
    else:
        current_app.logger.warning(
            f"User {current_user.email} gagal menghapus role {role_name} dari pengguna {user.email} karena role ini tidak ada."
        )
        flash(f"User {user.email} tidak memiliki role {role_name}.", "warning")

    return redirect(url_for("roles.index"))


# Menambahkan Permission ke Role
@roles_bp.route("/add_permission_to_role", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def add_permission_to_role():
    """menambahkan permission ke dalam role"""
    role_id = request.form.get("role_id")
    permission_id = request.form.get("permission_id")

    role = Role.query.get_or_404(role_id)  # Mengambil role berdasarkan ID
    permission = Permission.query.get_or_404(
        permission_id
    )  # Mengambil permission berdasarkan ID

    if permission not in role.permissions:
        role.permissions.append(permission)
        db.session.commit()
        current_app.logger.info(
            f"User {current_user.email} berhasil menambahkan permission {permission.name} ke role {role.name}"
        )
        flash("Permission berhasil ditambahkan ke role.", "success")
    else:
        current_app.logger.warning(
            f"User {current_user.email} gagal menambahkan permission {permission.name} ke role {role.name}"
        )
        flash("Permission sudah ada dalam role ini.", "warning")

    return redirect(url_for("roles.role_update", role_id=role_id))


# --------------------------------------------------------------------------------
# Permissions Management Section
# --------------------------------------------------------------------------------


# Daftar Permissions
@roles_bp.route("/permissions", methods=["GET"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def list_permissions():
    """Menampilkan daftar Permissions"""
    permissions = Permission.query.all()  # Mengambil semua permissions
    current_app.logger.info(f"User {current_user.email} accesing permissions page.")

    return render_template("role_management/list.html", permissions=permissions)


# Membuat Permission Baru
@roles_bp.route("/permissions/new", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def create_permission():
    """Menambahkan Permissions baru dan menyimpannya ke database"""
    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")

        if not name:
            current_app.logger.warning(
                f"User {current_user.email} gagal menambahkan permission {name} karena nama permission kosong."
            )
            flash("Name is required!", "danger")
            return redirect(url_for("roles.create_permission"))

        if Permission.query.filter_by(name=name).first():
            current_app.logger.warning(
                f"User {current_user.email} gagal menambahkan permission {name} karena nama permission sudah tersedia."
            )
            flash("Permission with this name already exists!", "danger")
            return redirect(url_for("roles.create_permission"))

        new_permission = Permission(name=name, description=description)
        db.session.add(new_permission)
        db.session.commit()
        current_app.logger.info(
            f"User {current_user.email} berhasil menambahkan permission {name}."
        )
        flash(f"berhasil menambahkan permission {name}", "success")
        return redirect(url_for("roles.list_permissions"))

    return render_template("role_management/create.html")


# Memperbarui Permission
@roles_bp.route("/permissions/<int:permission_id>/edit", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def update_permission(permission_id):
    """Memperbarui permission"""
    permission = Permission.query.get_or_404(
        permission_id
    )  # Mengambil permission berdasarkan ID

    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")

        if not name:
            current_app.logger.warning(
                f"User {current_user.email} gagal memperbarui permission {name} karena nama permission kosong."
            )
            flash("Name is required!", "danger")
            return redirect(
                url_for("roles.update_permission", permission_id=permission_id)
            )

        permission.name = name
        permission.description = description
        db.session.commit()
        current_app.logger.info(
            f"User {current_user.email} berhasil memperbarui permission {name}"
        )
        flash("Permission berhasil diperbarui.", "success")
        return redirect(url_for("roles.list_permissions"))

    return render_template("role_management/update.html", permission=permission)


# Menghapus Permission
@roles_bp.route("/permissions/<int:permission_id>/delete", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def delete_permission(permission_id):
    """Menghapus permission"""
    permission = Permission.query.get_or_404(
        permission_id
    )  # Mengambil permission berdasarkan ID
    db.session.delete(permission)
    db.session.commit()
    current_app.logger.info(
        f"User {current_user.email} berhasil menghapus permission: {permission.name}"
    )
    flash("Permission berhaisl dihapus!", "success")
    return redirect(url_for("roles.list_permissions"))


# --------------------------------------------------------------------------------
# API Permission Section
# --------------------------------------------------------------------------------


# api endpoint untuk memberikan seluruh data Permission
@roles_bp.route("/api/permissions", methods=["GET"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="API Permissions")
def api_permissions():
    """API endpoint untuk memberikan seluruh data permission"""
    permissions = Permission.query.all()  # Mengambil semua permissions
    permissions_list = [{"id": p.id, "name": p.name} for p in permissions]
    current_app.logger.warning(
        f"User {current_user.email} access API permissions data."
    )
    return jsonify(permissions_list)


# api endpoint untuk memberikan seluruh data user
@roles_bp.route("/api/users", methods=["GET"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="API Users")
def api_users():
    users = User.query.all()  # Mengambil semua pengguna
    users_list = [{"id": u.id, "name": u.email} for u in users]
    current_app.logger.warning(f"User {current_user.email} access API Users data.")
    return jsonify(users_list)
