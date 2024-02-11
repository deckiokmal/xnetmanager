from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from app import db
from app.models.users import User
from functools import wraps


# Membuat blueprint main_bp dan error_bp
main_bp = Blueprint("main", __name__)
error_bp = Blueprint("error", __name__)
error_bp = Blueprint("error_handlers", __name__)


# Manangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("/main/404.html"), 404


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
@main_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        user_id = current_user.id
        user = User.query.get(user_id)
        return dict(username=user.username)
    return dict(username=None)


# Main APP starting


# Login Page
@main_bp.route("/")
@main_bp.route("/login", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # check login user.
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("main.dashboard"))
        else:
            flash("Login gagal. periksa kembali credential anda!", "error")

    return render_template("/main/login.html")


# Register Page
@main_bp.route("/register", methods=["GET", "POST"])
def register():
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
            return redirect(url_for("main.index"))

    return render_template("/main/register.html")


# Menampilkan halaman dashboard setelah user login success.
@main_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("/main/dashboard.html")


# Log Out
@main_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))


# Main App End
