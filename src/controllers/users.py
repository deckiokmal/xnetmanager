from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from src import db
from src.models.users import User


# Membuat blueprint users
users_bp = Blueprint("users", __name__)


# cek login session. jika user belum memiliki login sesi dan mencoba akses url valid maka kembali ke loginpage.
def login_required(func):
    """
    Decorator untuk memeriksa apakah pengguna sudah login sebelum mengakses halaman tertentu.
    Jika belum login, pengguna akan diarahkan ke halaman login.
    """

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("You need to login first.", "warning")
            return redirect(url_for("main.index"))
        return func(*args, **kwargs)

    return decorated_view


# Context processor untuk menambahkan username ke dalam konteks disemua halaman.
@users_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        user_id = current_user.id
        user = User.query.get(user_id)
        return dict(username=user.username)
    return dict(username=None)


# Users App Starting


# Users Management Page
@users_bp.route("/users", methods=["GET"])
@login_required
def index():
    # Tampilkan all users per_page 10
    page = request.args.get("page", 1, type=int)
    per_page = 10
    all_users = User.query.paginate(page=page, per_page=per_page)

    return render_template("/users/user_manager.html", data=all_users)


# Create user
@users_bp.route("/user_create", methods=["GET", "POST"])
@login_required
def user_create():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # 1. existing user checking
        exist_user = User.query.filter_by(username=username).first()
        if exist_user:
            flash("User sudah terdaftar!", "error")

        # 2. username dan password field check. - user tidak boleh input data kosong.
        elif not username or not password:
            flash("Username dan password tidak boleh kosong!", "error")

        # jika error checking null, maka eksekusi user_create
        else:
            new_user = User(
                username=username,
                password=generate_password_hash(password, method="pbkdf2:sha256"),
            )
            db.session.add(new_user)
            db.session.commit()
            flash("User berhasil dibuat.", "success")

            # kembali ke index
            return redirect(url_for("users.index"))

    return render_template("/users/user_create.html")


# Update user
@users_bp.route("/user_update/<int:user_id>", methods=["GET", "POST"])
@login_required
def user_update(user_id):

    # Get data user by id
    user = User.query.get(user_id)

    if request.method == "POST":
        new_username = request.form["username"]
        new_password = request.form["password"]
        old_password = request.form["old_password"]

        # Check jika username yang dimasukan sudah tersedia dan bukan user saat ini.
        exist_user = User.query.filter(
            User.username == new_username, User.id != user.id
        ).first()
        if exist_user:
            flash("Username sudah ada. Silahkan masukkan username yang lain!", "error")

        # Check jika password lama terisi
        elif not old_password:
            flash("Old password tidak boleh kosong.", "error")
            return render_template("/users/user_update.html", user=user)

        elif not check_password_hash(user.password, old_password):
            flash("Password tidak match!", "error")
            return render_template("/users/user_update.html", user=user)
        else:
            # Update the user's username and password
            user.username = new_username
            if new_password:
                user.password = generate_password_hash(
                    new_password, method="pbkdf2:sha256"
                )

            db.session.commit()
            flash("User edited successfully.", "success")
            return redirect(url_for("users.index"))

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
@users_bp.route("/user_profile", methods=["GET","POST"])
@login_required
def user_profile():
    # Get data current user
    user_id = current_user.id
    user = User.query.get(user_id)

    return render_template("/users/user_profile.html", user=user)
