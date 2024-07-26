from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
)
from flask_login import login_required, current_user
from src import db, bcrypt
from src.models.users_model import User
from src.models.xmanager_model import DeviceManager, TemplateManager
from src.utils.forms_utils import RegisterForm
from .decorators import login_required, role_required
from flask_paginate import Pagination, get_page_args


# Membuat blueprint users
users_bp = Blueprint("users", __name__)
error_bp = Blueprint("error", __name__)
error_bp = Blueprint("error_handlers", __name__)


# Manangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("/main/404.html"), 404


# Context processor untuk menambahkan username ke dalam konteks disemua halaman.
@users_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        user_id = current_user.id
        user = User.query.get(user_id)
        return dict(username=user.username)
    return dict(username=None)


# Users App Starting


# Menampilkan halaman dashboard setelah user login success.
@users_bp.route("/")
@login_required
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
        user_query = User.query.filter(User.username.ilike(f"%{search_query}%"))
    else:
        # Jika tidak ada pencarian, ambil semua perangkat
        user_query = User.query

    # Menghitung total perangkat dan mengambil perangkat untuk halaman saat ini
    total_user = user_query.count()
    users = user_query.limit(per_page).offset(offset).all()

    # Membuat objek pagination
    pagination = Pagination(
        page=page, per_page=per_page, total=total_user, css_framework="bootstrap4"
    )

    # Modal Form Create users
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        try:
            # Buat objek User baru dan simpan ke database
            user = User(username=form.username.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()

            return redirect(url_for("users.index"))
        except Exception:
            # Jika registrasi gagal, batalkan perubahan dan beri pesan kesalahan
            db.session.rollback()
            flash("Registration failed. Please try again.", "error")

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


# Update user
@users_bp.route("/user_update/<int:user_id>", methods=["GET", "POST"])
@login_required
def user_update(user_id):
    # Mengambil objek User berdasarkan user_id
    user = User.query.get(user_id)

    # Jika metode request adalah POST, proses update user
    if request.method == "POST":
        new_username = request.form["username"]
        old_password = request.form["password_input"]
        new_password = request.form["new_password"]
        repeat_new_password = request.form["retype_password"]

        # Memeriksa apakah username baru sudah ada di database
        exist_user = User.query.filter(
            User.username == new_username, User.id != user.id
        ).first()
        if exist_user:
            flash("Username already exists. Please choose another username!", "info")

        # Memeriksa apakah password lama tidak kosong
        if not old_password:
            flash("Password must not be empty.", "error")
            return render_template("/users_management/user_update.html", user=user)

        # Memeriksa apakah password lama benar
        if not bcrypt.check_password_hash(user.password, old_password):
            flash("Incorrect password!", "error")
            return render_template("/users_management/user_update.html", user=user)
        else:
            # Memeriksa apakah new_password sama dengan repeat_new_password
            if new_password != repeat_new_password:
                flash("New passwords do not match.", "error")
                return render_template("/users_management/user_update.html", user=user)

            # Mengupdate password baru jika valid
            if new_password:
                user.password = bcrypt.generate_password_hash(new_password).decode(
                    "utf-8"
                )

            # Mengupdate username dan password baru jika valid
            user.username = new_username

            # Commit perubahan ke database
            db.session.commit()
            flash("User edited successfully.", "success")
            return redirect(url_for("users.index"))

    # Render halaman update user dengan data user yang akan diupdate
    return render_template("/users_management/user_update.html", user=user)


# Delete user
@users_bp.route("/user_delete/<int:user_id>", methods=["POST"])
@login_required
# @role_required("Admin", "user_delete")
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


# Users profile
@users_bp.route("/user_profile", methods=["GET", "POST"])
@login_required
def user_profile():
    # Get data current user
    user_id = current_user.id
    user = User.query.get(user_id)

    return render_template("/users_management/user_profile.html", user=user)
