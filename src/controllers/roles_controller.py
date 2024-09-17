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
from flask_login import login_required, current_user, logout_user
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


# Middleware untuk autentikasi dan otorisasi sebelum permintaan.
@roles_bp.before_request
def before_request_func():
    """
    Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan.
    Jika pengguna harus logout paksa, lakukan logout dan arahkan ke halaman login.
    Jika tidak terotentikasi, kembalikan pesan 'Unauthorized access'.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return render_template("main/404.html"), 404

    # Jika pengguna terotentikasi dan memiliki flag force_logout, lakukan logout
    if current_user.force_logout:
        current_user.force_logout = False  # Reset the flag
        db.session.commit()
        logout_user()
        flash("Your password has been updated. Please log in again.", "info")
        return redirect(url_for("main.login"))


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
@roles_bp.route("/roles-management", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def index():
    """Menampilkan halaman utama untuk mengelola role dan pengguna."""
    current_app.logger.info(
        f"User {current_user.email} accessed Roles Management page."
    )

    try:
        all_roles = Role.query.all()  # Mengambil semua role
        all_users = User.query.all()  # Mengambil semua pengguna

        search_query = request.args.get(
            "search", ""
        ).lower()  # Mengambil query pencarian
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

    except Exception as e:
        current_app.logger.error(f"Error occurred in Roles Management: {str(e)}")
        flash(
            "Terjadi kesalahan saat memuat halaman Role Management. Silakan coba lagi.",
            "danger",
        )
        return redirect(url_for("users.dashboard"))


# Membuat Role Baru dengan Modal
@roles_bp.route("/create-role", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def create_role():
    """Membuat role baru dan menyimpannya ke dalam database."""
    current_app.logger.info(f"User {current_user.email} accessed Create Role page.")

    role_name = request.form.get("name")
    role_permissions = request.form.getlist("permissions")

    # Validasi input
    if not role_name or not role_permissions:
        current_app.logger.warning(
            f"User {current_user.email} gagal membuat role baru: nama atau permissions kosong."
        )
        flash("Nama role dan permissions tidak boleh kosong!", "warning")
        return redirect(url_for("roles.index"))

    try:
        # Check if role already exists
        if Role.query.filter_by(name=role_name).first():
            current_app.logger.warning(
                f"User {current_user.email} gagal membuat role baru: role '{role_name}' sudah ada."
            )
            flash("Role sudah ada!", "error")
            return redirect(url_for("roles.index"))

        # Create new role with permissions
        new_role = Role(
            name=role_name,
            permissions=[Permission.query.get(p) for p in role_permissions],
        )
        db.session.add(new_role)
        db.session.commit()

        current_app.logger.info(
            f"User {current_user.email} berhasil membuat role baru: {role_name}."
        )
        flash("Role berhasil ditambah!", "success")
        return redirect(url_for("roles.index"))

    except Exception as e:
        current_app.logger.error(
            f"Error creating role '{role_name}' by user {current_user.email}: {str(e)}"
        )
        flash("Terjadi kesalahan saat membuat role baru. Silakan coba lagi.", "danger")
        db.session.rollback()
        return redirect(url_for("roles.index"))


# Memperbarui Role
@roles_bp.route("/update-role/<role_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def update_role(role_id):
    """Memperbarui role yang ada berdasarkan ID."""
    current_app.logger.info(
        f"User {current_user.email} is accessing update role for role ID {role_id}."
    )

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
            return redirect(url_for("roles.update_role", role_id=role_id))

        if Role.query.filter(Role.id != role.id, Role.name == role_name).first():
            current_app.logger.warning(
                f"User {current_user.email} gagal memperbarui role {role.name} karena role dengan nama tersebut sudah ada."
            )
            flash("Role dengan nama tersebut sudah ada!", "error")
            return redirect(url_for("roles.update_role", role_id=role_id))

        try:
            role.name = role_name

            # Memperbarui asosiasi permissions
            role.permissions = [
                Permission.query.get(permission_id)
                for permission_id in selected_permissions
            ]

            # Memperbarui asosiasi pengguna
            role.users = [User.query.get(user_id) for user_id in selected_users]

            db.session.commit()
            current_app.logger.info(
                f"User {current_user.email} berhasil memperbarui role {role.name}."
            )
            flash("Role berhasil diubah.", "success")
            return redirect(url_for("roles.index"))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(
                f"Error updating role '{role.name}' by user {current_user.email}: {str(e)}"
            )
            flash(
                "Terjadi kesalahan saat memperbarui role. Silakan coba lagi.", "danger"
            )
            return redirect(url_for("roles.update_role", role_id=role_id))

    # Mengambil pengguna terkait dan semua permissions
    associated_users = (
        User.query.join(UserRoles).filter(UserRoles.role_id == role_id).all()
    )
    all_permissions = Permission.query.all()

    # Mengambil permissions yang terkait dengan role ini
    associated_permissions = {permission.id for permission in role.permissions}

    return render_template(
        "/role_management/update_role.html",
        role=role,
        associated_users=associated_users,
        all_permissions=all_permissions,
        associated_permissions=associated_permissions,
    )


# Menghapus Role
@roles_bp.route("/delete-role/<role_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def delete_role(role_id):
    """Menghapus role dari database jika tidak ada asosiasi pengguna atau permissions."""
    current_app.logger.info(
        f"User {current_user.email} is attempting to delete role with ID {role_id}."
    )

    role = Role.query.get_or_404(role_id)  # Mengambil role berdasarkan ID

    try:
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

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error deleting role '{role.name}' by user {current_user.email}: {str(e)}"
        )
        flash("Terjadi kesalahan saat menghapus role. Silakan coba lagi.", "danger")
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

    current_app.logger.info(
        f"User {current_user.email} is attempting to add user with ID {user_id} to role {role_name}."
    )

    try:
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

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error adding role '{role_name}' to user with ID {user_id} by user {current_user.email}: {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat menambahkan pengguna ke role. Silakan coba lagi.",
            "danger",
        )

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

    current_app.logger.info(
        f"User {current_user.email} is attempting to remove user with ID {user_id} from role {role_name}."
    )

    try:
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

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error removing role '{role_name}' from user with ID {user_id} by user {current_user.email}: {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat menghapus pengguna dari role. Silakan coba lagi.",
            "danger",
        )

    return redirect(url_for("roles.index"))


# Menambahkan Permission ke Role
@roles_bp.route("/add_permission_to_role", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def add_permission_to_role():
    """Menambahkan permission ke dalam role."""
    role_id = request.form.get("role_id")
    permission_id = request.form.get("permission_id")

    current_app.logger.info(
        f"User {current_user.email} is attempting to add permission with ID {permission_id} to role with ID {role_id}."
    )

    try:
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
                f"User {current_user.email} mencoba menambahkan permission {permission.name} ke role {role.name}, tetapi permission sudah ada."
            )
            flash("Permission sudah ada dalam role ini.", "warning")

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error adding permission ID {permission_id} to role ID {role_id} by user {current_user.email}: {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat menambahkan permission ke role. Silakan coba lagi.",
            "danger",
        )

    return redirect(url_for("roles.role_update", role_id=role_id))


# --------------------------------------------------------------------------------
# Permissions Management Section
# --------------------------------------------------------------------------------


# Daftar Permissions
@roles_bp.route("/roles/permissions", methods=["GET"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def index_permissions():
    """Menampilkan daftar Permissions"""
    try:
        permissions = Permission.query.all()  # Mengambil semua permissions
        current_app.logger.info(
            f"User {current_user.email} accessing permissions page."
        )

    except Exception as e:
        current_app.logger.error(
            f"Error accessing permissions page by user {current_user.email}: {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat mengambil daftar permissions. Silakan coba lagi nanti.",
            "danger",
        )
        permissions = []  # Set permissions to an empty list in case of error

    return render_template(
        "role_management/index_permissions.html", permissions=permissions
    )


# Membuat Permission Baru
@roles_bp.route("/roles/create-permission", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def create_permission():
    """Menambahkan Permissions baru dan menyimpannya ke database"""
    try:
        name = request.form.get("name")
        description = request.form.get("description")

        if not name:
            current_app.logger.warning(
                f"User {current_user.email} gagal menambahkan permission karena nama permission kosong."
            )
            flash("Nama permission tidak boleh kosong!", "warning")
            return redirect(url_for("roles.index_permissions"))

        if Permission.query.filter_by(name=name).first():
            current_app.logger.warning(
                f"User {current_user.email} gagal menambahkan permission karena nama permission '{name}' sudah tersedia."
            )
            flash("Permission dengan nama ini sudah ada!", "warning")
            return redirect(url_for("roles.index_permissions"))

        new_permission = Permission(name=name, description=description)
        db.session.add(new_permission)
        db.session.commit()
        current_app.logger.info(
            f"User {current_user.email} berhasil menambahkan permission '{name}'."
        )
        flash(f"Permission '{name}' berhasil ditambahkan.", "success")
        return redirect(url_for("roles.index_permissions"))

    except Exception as e:
        current_app.logger.error(
            f"Error occurred while user {current_user.email} was creating permission '{name}': {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat menambahkan permission. Silakan coba lagi nanti.",
            "danger",
        )
        return redirect(url_for("roles.index_permissions"))


# Memperbarui Permission
@roles_bp.route("/roles/update-permissions/<permission_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def update_permission(permission_id):
    """Memperbarui permission"""
    permission = Permission.query.get_or_404(
        permission_id
    )  # Mengambil permission berdasarkan ID

    if request.method == "POST":
        try:
            name = request.form.get("name")
            description = request.form.get("description")

            if not name:
                current_app.logger.warning(
                    f"User {current_user.email} gagal memperbarui permission {permission.name} karena nama permission kosong."
                )
                flash("Nama permission tidak boleh kosong!", "warning")
                return redirect(url_for("roles.index_permissions"))

            existing_permission = Permission.query.filter(
                Permission.id != permission_id, Permission.name == name
            ).first()
            if existing_permission:
                current_app.logger.warning(
                    f"User {current_user.email} gagal memperbarui permission karena permission dengan nama '{name}' sudah ada."
                )
                flash("Permission dengan nama ini sudah ada!", "warning")
                return redirect(url_for("roles.index_permissions"))

            permission.name = name
            permission.description = description
            db.session.commit()
            current_app.logger.info(
                f"User {current_user.email} berhasil memperbarui permission '{name}'"
            )
            flash("Permission berhasil diperbarui.", "success")
            return redirect(url_for("roles.index_permissions"))

        except Exception as e:
            current_app.logger.error(
                f"Error occurred while user {current_user.email} was updating permission '{permission.name}': {str(e)}"
            )
            flash(
                "Terjadi kesalahan saat memperbarui permission. Silakan coba lagi nanti.",
                "danger",
            )
            return redirect(url_for("roles.index_permissions"))

    return redirect(url_for("roles.index_permissions"))


# Menghapus Permission
@roles_bp.route("/roles/delete-permissions/<permission_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="Roles Management")
def delete_permission(permission_id):
    """Menghapus permission"""
    try:
        permission = Permission.query.get_or_404(
            permission_id
        )  # Mengambil permission berdasarkan ID

        # Log sebelum pengecekan asosiasi
        current_app.logger.info(
            f"User {current_user.email} mencoba menghapus permission: {permission.name}"
        )

        # Mengecek apakah permission terasosiasi dengan role apa pun
        associated_roles = Role.query.filter(
            Role.permissions.contains(permission)
        ).all()
        if associated_roles:
            role_names = ", ".join([role.name for role in associated_roles])
            current_app.logger.warning(
                f"User {current_user.email} gagal menghapus permission {permission.name} karena terasosiasi dengan role: {role_names}."
            )
            flash(
                f"Permission tidak dapat dihapus karena masih terasosiasi dengan role: {role_names}.",
                "warning",
            )
            return redirect(url_for("roles.index_permissions"))

        # Menghapus permission jika tidak ada asosiasi
        db.session.delete(permission)
        db.session.commit()

        current_app.logger.info(
            f"User {current_user.email} berhasil menghapus permission: {permission.name}"
        )
        flash("Permission berhasil dihapus!", "success")
    except Exception as e:
        # Log error jika terjadi masalah selama penghapusan
        current_app.logger.error(
            f"Error occurred while user {current_user.email} was deleting permission: {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat menghapus permission. Silakan coba lagi nanti.",
            "danger",
        )
        db.session.rollback()

    return redirect(url_for("roles.index_permissions"))


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
