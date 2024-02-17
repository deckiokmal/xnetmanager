from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from flask_login import login_required, current_user
from functools import wraps
from src import db, bcrypt
from src.models.users import User
from src.utils.forms import RegisterForm


# Membuat blueprint users
users_bp = Blueprint("users", __name__)


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
    return render_template("/users/dashboard.html")


# Users Management Page
@users_bp.route("/users", methods=["GET", "POST"])
@login_required
def index():
    # Tampilkan all users per_page 10
    page = request.args.get("page", 1, type=int)
    per_page = 10
    all_users = User.query.paginate(page=page, per_page=per_page)

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

    return render_template("/users/user_manager.html", data=all_users, form=form)


# Update user
@users_bp.route("/user_update/<int:user_id>", methods=["GET", "POST"])
@login_required
def user_update(user_id):
    # Mengambil objek User berdasarkan user_id
    user = User.query.get(user_id)

    # Jika metode request adalah POST, proses update user
    if request.method == "POST":
        new_username = request.form["username"]
        old_password = request.form["password-input"]
        new_password = request.form["newpassword-input1"]
        repeat_new_password = request.form["newpassword-input2"]

        # Memeriksa apakah username baru sudah ada di database
        exist_user = User.query.filter(
            User.username == new_username, User.id != user.id
        ).first()
        if exist_user:
            flash("Username already exists. Please choose another username!", "error")

        # Memeriksa apakah password lama tidak kosong
        if not old_password:
            flash("Password must not be empty.", "error")
            return render_template("/users/user_update.html", user=user)

        # Memeriksa apakah password lama benar
        if not bcrypt.check_password_hash(user.password, old_password):
            flash("Incorrect password!", "error")
            return render_template("/users/user_update.html", user=user)
        else:
            # Memeriksa apakah new_password sama dengan repeat_new_password
            if new_password != repeat_new_password:
                flash("New passwords do not match.", "error")
                return render_template("/users/user_update.html", user=user)

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
    return render_template("/users/user_update.html", user=user)


# Delete user
@users_bp.route("/user_delete/<int:user_id>", methods=["POST"])
@login_required
def user_delete(user_id):
    if current_user.id == user_id:
        flash("Anda tidak bisa delete akun anda sendiri.", "error")
        return redirect(url_for("users.index"))

    user = User.query.get(user_id)
    if not user:
        flash("User tidak ditemukan.", "error")
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

    return render_template("/users/user_profile.html", user=user)
