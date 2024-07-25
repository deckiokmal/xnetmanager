from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
)
from flask_login import login_required, current_user
from src import db
from src.models.users_model import User, Role, UserRoles
from .decorators import login_required, role_required
from flask_paginate import Pagination, get_page_args


# Membuat blueprint roles
roles_bp = Blueprint("roles", __name__)
error_bp = Blueprint("error", __name__)
error_bp = Blueprint("error_handlers", __name__)


# Manangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("/main/404.html"), 404


# Context processor untuk menambahkan username ke dalam konteks disemua halaman.
@roles_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        user_id = current_user.id
        user = User.query.get(user_id)
        return dict(username=user.username)
    return dict(username=None)


# roles App Starting


# roles Role Page
@roles_bp.route("/user_role", methods=["GET", "POST"])
@login_required
# @role_required("Admin", "UserRoles")
def index():
    # Mendapatkan parameter pencarian dari URL
    search_query = request.args.get("search", "").lower()

    # Mendapatkan halaman saat ini dan jumlah entri per halaman
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    if search_query:
        # Jika ada pencarian, filter perangkat berdasarkan query
        role_query = Role.query.filter(Role.name.ilike(f"%{search_query}%"))
    else:
        # Jika tidak ada pencarian, ambil semua perangkat
        role_query = Role.query

    # Menghitung total perangkat dan mengambil perangkat untuk halaman saat ini
    total_roles = role_query.count()
    roles = role_query.limit(per_page).offset(offset).all()

    # Membuat objek pagination
    pagination = Pagination(
        page=page, per_page=per_page, total=total_roles, css_framework="bootstrap4"
    )

    return render_template(
        "/role_management/index.html",
        roles=roles,
        page=page,
        per_page=per_page,
        pagination=pagination,
        search_query=search_query,
        total_roles=total_roles,
    )


# Create role
@roles_bp.route("/create_role", methods=["GET", "POST"])
@login_required
# @role_required("Admin", "create_role")
def create_role():
    if request.method == "POST":
        role_name = request.form["name"]
        role_permissions = request.form["permissions"]

        # 1. existing role name check
        exist_role = Role.query.filter_by(name=role_name).first()
        if exist_role:
            flash("Role sudah ada!", "error")

        # 2. name dan permissions field check. - user tidak boleh input data kosong.
        elif not role_name or not role_permissions:
            flash("role name dan permissions tidak boleh kosong!", "warning")

        # jika error checking null, maka eksekusi create_role
        else:
            new_role = Role(
                name=role_name,
                permissions=role_permissions,
            )
            db.session.add(new_role)
            db.session.commit()
            flash("Role berhasil ditambah!", "success")

            # kembali ke index
            return redirect(url_for("roles.index"))

    return redirect(url_for("roles.index"))


# Role Update
@roles_bp.route("/role_update/<int:role_id>", methods=["GET", "POST"])
@login_required
# @role_required("Admin", "role_update")
def role_update(role_id):
    # Mengambil objek Role berdasarkan role_id
    role = Role.query.get(role_id)

    # Jika metode request adalah POST, proses update role
    if request.method == "POST":
        role_name = request.form["name"]
        role_permissions = request.form["permissions"]

        # 1. existing role name check
        exist_role = Role.query.filter(
            Role.id != role.id, Role.name == role_name
        ).first()
        if exist_role:
            flash("Role dengan nama tersebut sudah ada!", "error")
        else:
            # Mengupdate data role name
            role.name = role_name
            role.permissions = role_permissions

            # Commit perubahan ke database
            db.session.commit()
            flash("Role berhasil diubah.", "success")
            return redirect(url_for("roles.roles"))

    # Render halaman update user dengan data user yang akan diupdate
    return render_template("/role_management/role_update.html", role=role)


# Role Delete
@roles_bp.route("/role_delete/<int:role_id>", methods=["POST"])
@login_required
# @role_required("Admin", "role_delete")
def role_delete(role_id):
    role = Role.query.get_or_404(role_id)

    if role.roles.count(role.roles) > 0:
        flash(
            "Role tidak dapat dihapus karena masih terasosiasi dengan pengguna.",
            "warning",
        )
        return redirect(url_for("roles.roles"))

    db.session.delete(role)
    db.session.commit()
    flash("Role berhasil dihapus.", "success")
    return redirect(url_for("roles.roles"))


# tambah user to role
@roles_bp.route("/add_user_to_role", methods=["POST"])
@login_required
# @role_required("Admin", "add_user_to_role")
def add_user_to_role():
    if request.method == "POST":
        username = request.form["username"]
        role_name = request.form["role_name"]

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"})

        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return jsonify({"status": "error", "message": "Role not found"})

        UserRoles = UserRoles(user_id=user.id, role_id=role.id)
        db.session.add(UserRoles)
        db.session.commit()

        return jsonify(
            {
                "status": "success",
                "message": f"User {username} berhasil ditambahkan ke role {role_name}.",
            }
        )

    return jsonify({"status": "error", "message": "Invalid request"})
