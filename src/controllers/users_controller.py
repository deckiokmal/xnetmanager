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
from src import db, bcrypt
from src.models.users_model import User, Role
from src.models.xmanager_model import DeviceManager, TemplateManager
from src.utils.forms_utils import RegisterForm, UserUpdateForm
from .decorators import login_required, role_required, required_2fa
from flask_paginate import Pagination, get_page_args
import logging


# Membuat blueprint users
users_bp = Blueprint("users", __name__)
error_bp = Blueprint("error", __name__)


# Setup logging
logging.basicConfig(level=logging.INFO)


@users_bp.before_app_request
def setup_logging():
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


# Menangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("main/404.html"), 404


# middleware untuk autentikasi dan otorisasi
@users_bp.before_request
def before_request_func():
    if not current_user.is_authenticated:
        return jsonify({"message": "Unauthorized access"}), 401


# Context processor untuk menambahkan first_name dan last_name ke dalam konteks di semua halaman.
@users_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


# Menampilkan halaman dashboard setelah user login success.
@users_bp.route("/dashboard")
@login_required
@required_2fa
def dashboard():
    # Mengambil semua perangkat dan template konfigurasi dari database
    devices = DeviceManager.query.all()
    templates = TemplateManager.query.all()

    # Menghitung jumlah perangkat berdasarkan vendor
    device_vendor_count = {}
    for device in devices:
        vendor = device.vendor
        if vendor in device_vendor_count:
            device_vendor_count[vendor] += 1
        else:
            device_vendor_count[vendor] = 1

    # Menghitung jumlah template berdasarkan vendor
    template_vendor_count = {}
    for template in templates:
        vendor = template.vendor
        if vendor in template_vendor_count:
            template_vendor_count[vendor] += 1
        else:
            template_vendor_count[vendor] = 1

    return render_template(
        "/users_management/dashboard.html",
        device_vendor_keys=list(device_vendor_count.keys()),
        device_vendor_values=list(device_vendor_count.values()),
        template_vendor_keys=list(template_vendor_count.keys()),
        template_vendor_values=list(template_vendor_count.values()),
    )


# Users Management Page
@users_bp.route("/users", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Users"], page="Users Management")
# @role_required("Admin", "users")
def index():
    # Mendapatkan parameter pencarian dari URL
    search_query = request.args.get("search", "").lower()

    # Mendapatkan halaman saat ini dan jumlah entri per halaman
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    if search_query:
        # Jika ada pencarian, filter perangkat berdasarkan query
        user_query = User.query.filter(User.email.ilike(f"%{search_query}%"))
    else:
        # Jika tidak ada pencarian, ambil semua perangkat
        user_query = User.query

    # Menghitung total perangkat dan mengambil perangkat untuk halaman saat ini
    total_user = user_query.count()
    users = user_query.limit(per_page).offset(offset).all()

    # Membuat objek pagination
    pagination = Pagination(page=page, per_page=per_page, total=total_user)

    # Modal Form Create users
    form = RegisterForm()
    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        password = form.password.data

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Alamat email sudah terdaftar", "error")
            return redirect(url_for("users.index"))

        # Create new user with hashed password
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password_hash=password,
        )

        # Add the user to the 'View' role
        view_role = Role.query.filter_by(name="View").first()
        if view_role:
            new_user.roles.append(view_role)

        # Add new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash("User berhasil ditambahkan.", "success")
        return redirect(url_for("users.index"))

    return render_template(
        "/users_management/index.html",
        users=users,
        page=page,
        per_page=per_page,
        pagination=pagination,
        search_query=search_query,
        total_user=total_user,
        form=form,
    )


# User Update Page
@users_bp.route("/user_update/<int:user_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Users"], page="Users Management")
def user_update(user_id):
    user = User.query.get_or_404(user_id)
    form = UserUpdateForm(obj=user)

    if form.validate_on_submit():
        # Memeriksa apakah email baru sudah ada di database
        if User.query.filter(User.email == form.email.data, User.id != user.id).first():
            flash("Email already exists. Please choose another email!", "info")
            return render_template(
                "/users_management/user_update.html", form=form, user=user
            )

        # Mengupdate data user
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.email = form.email.data
        user.phone_number = form.phone_number.data
        user.profile_picture = form.profile_picture.data
        user.company = form.company.data
        user.title = form.title.data
        user.city = form.city.data
        user.division = form.division.data

        # Mengonversi nilai string menjadi boolean
        user.is_verified = form.is_verified.data == "True"
        user.is_2fa_enabled = form.is_2fa_enabled.data == "True"
        user.is_active = form.is_active.data == "True"
        user.time_zone = form.time_zone.data

        # Memperbarui password jika disediakan
        if form.password.data:
            user.password_hash = bcrypt.generate_password_hash(
                form.password.data
            ).decode("utf-8")

        # Commit perubahan ke database
        db.session.commit()
        flash("User updated successfully.", "success")
        return redirect(url_for("users.index"))

    return render_template("/users_management/user_update.html", form=form, user=user)


# Delete user
@users_bp.route("/user_delete/<int:user_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Users"], page="Users Management")
def user_delete(user_id):
    if current_user.id == user_id:
        flash("Anda tidak bisa delete akun anda sendiri.", "warning")
        return redirect(url_for("users.index"))

    user = User.query.get(user_id)
    if not user:
        flash("User tidak ditemukan.", "info")
        return redirect(url_for("users.index"))

    db.session.delete(user)
    db.session.commit()
    flash("User telah dihapus.", "success")
    return redirect(url_for("users.index"))
