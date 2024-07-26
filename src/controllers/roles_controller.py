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
from flask_paginate import Pagination, get_page_args
from src import db
from src.models.users_model import User, Role, Permission
from .decorators import role_required

roles_bp = Blueprint("roles", __name__)
error_bp = Blueprint("error", __name__)


# Handle 404 errors
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("/main/404.html"), 404


# Context processor to inject username
@roles_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        return dict(username=current_user.username)
    return dict(username=None)


# Roles Page
@roles_bp.route("/user_role", methods=["GET", "POST"])
@login_required
# @role_required(
#     "Admin", "Manage Roles"
# )  # Ensure only users with 'Admin' role can access
def index():
    all_roles = Role.query.all()
    all_users = User.query.all()

    search_query = request.args.get("search", "").lower()
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    role_query = (
        Role.query.filter(Role.name.ilike(f"%{search_query}%"))
        if search_query
        else Role.query
    )
    total_roles = role_query.count()
    roles = role_query.limit(per_page).offset(offset).all()

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
        all_roles=all_roles,
        all_users=all_users,
    )


# Create Role
@roles_bp.route("/create_role", methods=["GET", "POST"])
@login_required
# @role_required("Admin", "Manage Roles")
def create_role():
    if request.method == "POST":
        role_name = request.form.get("name")
        role_permissions = request.form.getlist("permissions")

        if not role_name or not role_permissions:
            flash("Role name dan permissions tidak boleh kosong!", "warning")
            return redirect(url_for("roles.index"))

        if Role.query.filter_by(name=role_name).first():
            flash("Role sudah ada!", "error")
            return redirect(url_for("roles.index"))

        new_role = Role(
            name=role_name,
            permissions=[Permission.query.get(int(p)) for p in role_permissions],
        )
        db.session.add(new_role)
        db.session.commit()
        flash("Role berhasil ditambah!", "success")
        return redirect(url_for("roles.index"))

    permissions = Permission.query.all()
    return render_template("/role_management/create_role.html", permissions=permissions)


# Update Role
@roles_bp.route("/role_update/<int:role_id>", methods=["GET", "POST"])
@login_required
# @role_required("Admin", "Manage Roles")
def role_update(role_id):
    role = Role.query.get_or_404(role_id)

    if request.method == "POST":
        role_name = request.form.get("name")
        role_permissions = request.form.getlist("permissions")

        if not role_name or not role_permissions:
            flash("Role name dan permissions tidak boleh kosong!", "warning")
            return redirect(url_for("roles.role_update", role_id=role_id))

        if Role.query.filter(Role.id != role.id, Role.name == role_name).first():
            flash("Role dengan nama tersebut sudah ada!", "error")
        else:
            role.name = role_name
            role.permissions = [Permission.query.get(int(p)) for p in role_permissions]
            db.session.commit()
            flash("Role berhasil diubah.", "success")
            return redirect(url_for("roles.index"))

    permissions = Permission.query.all()
    return render_template(
        "/role_management/role_update.html", role=role, permissions=permissions
    )


# Delete Role
@roles_bp.route("/role_delete/<int:role_id>", methods=["POST"])
@login_required
# @role_required("Admin", "Manage Roles")
def role_delete(role_id):
    role = Role.query.get_or_404(role_id)

    if role.users:
        flash(
            "Role tidak dapat dihapus karena masih terasosiasi dengan pengguna.",
            "warning",
        )
        return redirect(url_for("roles.index"))

    db.session.delete(role)
    db.session.commit()
    flash("Role berhasil dihapus.", "success")
    return redirect(url_for("roles.index"))


# Add User to Role
@roles_bp.route("/add_user_to_role", methods=["POST"])
@login_required
# @role_required("Admin", "Manage Users")
def add_user_to_role():
    user_id = request.form.get("user_id")
    role_name = request.form.get("role_name")

    user = User.query.get(user_id)
    role = Role.query.filter_by(name=role_name).first()

    if not user:
        flash("User not found", "error")
        return redirect(url_for("roles.index"))

    if not role:
        flash("Role not found", "error")
        return redirect(url_for("roles.index"))

    if role not in user.roles:
        user.roles.append(role)
        db.session.commit()
        flash(
            f"User {user.username} berhasil ditambahkan ke role {role_name}.", "success"
        )
    else:
        flash(f"User {user.username} sudah memiliki role {role_name}.", "warning")

    return redirect(url_for("roles.index"))


# List Permissions
@roles_bp.route("/permissions", methods=["GET"])
@login_required
# @role_required("Admin", "Manage Permissions")
def list_permissions():
    permissions = Permission.query.all()
    return render_template("role_management/list.html", permissions=permissions)


# Create Permission
@roles_bp.route("/permissions/new", methods=["GET", "POST"])
@login_required
# @role_required("Admin", "Manage Permissions")
def create_permission():
    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")

        if not name:
            flash("Name is required!", "danger")
            return redirect(url_for("roles.create_permission"))

        if Permission.query.filter_by(name=name).first():
            flash("Permission with this name already exists!", "danger")
            return redirect(url_for("roles.create_permission"))

        new_permission = Permission(name=name, description=description)
        db.session.add(new_permission)
        db.session.commit()
        flash("Permission created successfully!", "success")
        return redirect(url_for("roles.list_permissions"))

    return render_template("role_management/create.html")


# Update Permission
@roles_bp.route("/permissions/<int:permission_id>/edit", methods=["GET", "POST"])
@login_required
# @role_required("Admin", "Manage Permissions")
def update_permission(permission_id):
    permission = Permission.query.get_or_404(permission_id)

    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")

        if not name:
            flash("Name is required!", "danger")
            return redirect(
                url_for("roles.update_permission", permission_id=permission_id)
            )

        permission.name = name
        permission.description = description
        db.session.commit()
        flash("Permission updated successfully!", "success")
        return redirect(url_for("roles.list_permissions"))

    return render_template("role_management/update.html", permission=permission)


# Delete Permission
@roles_bp.route("/permissions/<int:permission_id>/delete", methods=["POST"])
@login_required
# @role_required("Admin", "Manage Permissions")
def delete_permission(permission_id):
    permission = Permission.query.get_or_404(permission_id)
    db.session.delete(permission)
    db.session.commit()
    flash("Permission deleted successfully!", "success")
    return redirect(url_for("roles.list_permissions"))


# Add Permission to Role
@roles_bp.route("/add_permission_to_role", methods=["POST"])
@login_required
# @role_required("Admin", "Manage Roles")
def add_permission_to_role():
    role_id = request.form.get("role_id")
    permission_id = request.form.get("permission_id")

    role = Role.query.get_or_404(role_id)
    permission = Permission.query.get_or_404(permission_id)

    if permission not in role.permissions:
        role.permissions.append(permission)
        db.session.commit()
        flash("Permission berhasil ditambahkan ke role.", "success")
    else:
        flash("Permission sudah ada dalam role ini.", "warning")

    return redirect(url_for("roles.role_update", role_id=role_id))


@roles_bp.route("/api/permissions", methods=["GET"])
@login_required
# @role_required("Admin", "Manage Permissions")
def api_permissions():
    permissions = Permission.query.all()
    permissions_list = [{"id": p.id, "name": p.name} for p in permissions]
    return jsonify(permissions_list)


@roles_bp.route("/api/users", methods=["GET"])
@login_required
# @role_required("Admin", "Manage Roles")
def api_users():
    users = User.query.all()
    users_list = [{"id": u.id, "name": u.username} for u in users]
    return jsonify(users_list)
