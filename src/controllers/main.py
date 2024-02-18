from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user, login_required
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


# Context processor untuk menambahkan username ke dalam konteks disemua halaman.
@main_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        user_id = current_user.id
        user = User.query.get(user_id)
        return dict(username=user.username)
    return dict(username=None)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('You need to login first', 'info')
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function


# Main APP starting
HOME_URL = "users.dashboard"
SETUP_2FA_URL = "main.setup_two_factor_auth"
VERIFY_2FA_URL = "main.verify_two_factor_auth"


# Register Page
@main_bp.route("/register", methods=["GET", "POST"])
def register():
    # Jika pengguna sudah terautentikasi, alihkan ke beranda jika 2FA sudah diaktifkan
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash("You are already registered.", "info")
            return redirect(url_for(HOME_URL))
        else:
            # Jika 2FA belum diaktifkan, arahkan pengguna untuk mengaktifkannya
            flash(
                "You have not enabled 2-Factor Authentication. Please enable first to login.",
                "warning",
            )
            return redirect(url_for(SETUP_2FA_URL))

    # Validasi form registrasi
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        try:
            # Buat objek User baru dan simpan ke database
            user = User(username=form.username.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()

            # Autentikasi pengguna setelah registrasi sukses
            login_user(user)
            flash(
                "You are registered. You have to enable 2-Factor Authentication first to login.",
                "success",
            )

            # Alihkan pengguna untuk mengatur 2FA setelah registrasi sukses
            return redirect(url_for(SETUP_2FA_URL))
        except Exception:
            # Jika registrasi gagal, batalkan perubahan dan beri pesan kesalahan
            db.session.rollback()
            flash("Registration failed. Please try again.", "error")

    # Render template registrasi dengan form
    return render_template("/main/register.html", form=form)


# Login Page
@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash("You are already logged in.", "success")
            return redirect(url_for(HOME_URL))
        else:
            flash(
                "You have not enabled 2-Factor Authentication. Please enable first to login.",
                "warning",
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
                    "warning",
                )
                return redirect(url_for(SETUP_2FA_URL))
            return redirect(url_for(VERIFY_2FA_URL))
        elif not user:
            flash("You are not registered. Please register.", "error")
        else:
            flash("Invalid username and/or password.", "error")

    return render_template("/main/login.html", form=form)


# Log Out
@main_bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("authenticated", None)
    return redirect(url_for("main.login"))


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
                    flash("2FA setup failed. Please try again.", "error")
                    return redirect(url_for(VERIFY_2FA_URL))
        else:
            flash("Invalid OTP. Please try again.", "error")
            return redirect(url_for(VERIFY_2FA_URL))
    else:
        if not current_user.is_two_factor_authentication_enabled:
            flash(
                "You have not enabled 2-Factor Authentication. Please enable it first.",
                "warning",
            )
        return render_template("main/verify-2fa.html", form=form)


# Main App End
