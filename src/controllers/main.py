from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from src import db, bcrypt
from src.models.users import User
from functools import wraps
from src.utils.forms import RegisterForm, LoginForm, TwoFactorForm
from src.utils.qrcode import get_b64encoded_qr_image


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
HOME_URL = "main.dashboard"
SETUP_2FA_URL = "main.setup_two_factor_auth"
VERIFY_2FA_URL = "main.verify_two_factor_auth"


# Login Page
@main_bp.route("/")
@main_bp.route("/login", methods=["GET", "POST"])
def index():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash("You are already logged in.", "info")
            return redirect(url_for(HOME_URL))
        else:
            flash(
                "You have not enabled 2-Factor Authentication. Please enable first to login.",
                "info",
            )
            return redirect(url_for(SETUP_2FA_URL))

    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, request.form["password"]):
            login_user(user)
            if not current_user.is_two_factor_authentication_enabled:
                flash(
                    "You have not enabled 2-Factor Authentication. Please enable first to login.",
                    "info",
                )
                return redirect(url_for(SETUP_2FA_URL))
            return redirect(url_for(VERIFY_2FA_URL))
        elif not user:
            flash("You are not registered. Please register.", "danger")
        else:
            flash("Invalid username and/or password.", "danger")

    return render_template("/main/login.html")


# Register Page
@main_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash("You are already registered.", "info")
            return redirect(url_for(HOME_URL))
        else:
            flash(
                "You have not enabled 2-Factor Authentication. Please enable first to login.",
                "info",
            )
            return redirect(url_for(SETUP_2FA_URL))
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        try:
            user = User(username=form.username.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()

            login_user(user)
            flash(
                "You are registered. You have to enable 2-Factor Authentication first to login.",
                "success",
            )

            return redirect(url_for(SETUP_2FA_URL))
        except Exception:
            db.session.rollback()
            flash("Registration failed. Please try again.", "danger")

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


@main_bp.route("/setup-2fa")
@login_required
def setup_two_factor_auth():
    secret = current_user.secret_token
    uri = current_user.get_authentication_setup_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)
    return render_template(
        "main/setup-2fa.html", secret=secret, qr_image=base64_qr_image
    )


@main_bp.route("/verify-2fa", methods=["GET", "POST"])
@login_required
def verify_two_factor_auth():
    form = TwoFactorForm(request.form)
    if form.validate_on_submit():
        if current_user.is_otp_valid(form.otp.data):
            if current_user.is_two_factor_authentication_enabled:
                flash("2FA verification successful. You are logged in!", "success")
                return redirect(url_for(HOME_URL))
            else:
                try:
                    current_user.is_two_factor_authentication_enabled = True
                    db.session.commit()
                    flash("2FA setup successful. You are logged in!", "success")
                    return redirect(url_for(HOME_URL))
                except Exception:
                    db.session.rollback()
                    flash("2FA setup failed. Please try again.", "danger")
                    return redirect(url_for(VERIFY_2FA_URL))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for(VERIFY_2FA_URL))
    else:
        if not current_user.is_two_factor_authentication_enabled:
            flash(
                "You have not enabled 2-Factor Authentication. Please enable it first.",
                "info",
            )
        return render_template("main/verify-2fa.html", form=form)


# Main App End
