from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    session,
    current_app,
    jsonify,
)
from flask_login import login_user, logout_user, current_user, login_required
from src import db, bcrypt
from src.models.users_model import User, Role
from src.utils.forms_utils import RegisterForm, LoginForm, TwoFactorForm
import logging
from datetime import datetime

# Membuat blueprint main_bp dan error_bp
main_bp = Blueprint("main", __name__)
error_bp = Blueprint("error", __name__)


# Middleware untuk autentikasi dan otorisasi
@main_bp.before_request
def before_request_func():
    # List halaman yang tidak perlu autentikasi (seperti login)
    exempt_pages = ["main.login", "main.register"]  # Tambahkan halaman lain jika perlu

    # Mengecek apakah halaman saat ini termasuk dalam halaman yang tidak perlu autentikasi
    if request.endpoint in exempt_pages:
        return None

    # Mengecek apakah pengguna sudah terautentikasi
    if not current_user.is_authenticated:
        # Menampilkan pesan flash
        flash("Unauthorized access. Please log in to access this page.", "danger")
        # Mengarahkan pengguna ke halaman login
        return redirect(url_for("main.login"))


# Setup logging
logging.basicConfig(level=logging.INFO)


@main_bp.before_app_request
def setup_logging():
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


# Menangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("main/404.html"), 404


# Context processor untuk menambahkan first_name dan last_name ke dalam konteks di semua halaman.
@main_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


# Main APP starting
HOME_URL = "users.dashboard"
SETUP_2FA_URL = "main.setup_two_factor_auth"
VERIFY_2FA_URL = "main.verify_two_factor_auth"


# Register Page
@main_bp.route("/register", methods=["GET", "POST"])
def register():
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
            return redirect(url_for("main.register"))

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

        # Log the user in after successful registration
        login_user(new_user)
        flash("Pendaftaran berhasil! Anda telah masuk.", "success")
        return redirect(url_for(HOME_URL))

    return render_template("/main/register.html", form=form)


# Login Page
@main_bp.route("/", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for(HOME_URL))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)

            # Update last_login
            user.last_login = datetime.utcnow()
            db.session.commit()

            # Check if user needs to verify their email
            if not user.is_verified:
                flash("Silakan verifikasi email Anda untuk akses penuh.", "warning")
            if user.is_2fa_enabled:
                return redirect(url_for(VERIFY_2FA_URL))
            return redirect(url_for(HOME_URL))
        else:
            flash("Email atau kata sandi tidak valid.", "error")

    return render_template("/main/login.html", form=form)


# Log Out
@main_bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("authenticated", None)
    return redirect(url_for("main.login"))


# verifikasi kode OTP Google Authenticator jika user mengaktifkan 2fa di user profile
@main_bp.route("/verify-2fa", methods=["GET", "POST"])
@login_required
def verify_two_factor_auth():
    form = TwoFactorForm(request.form)
    if form.validate_on_submit():
        if current_user.is_otp_valid(form.otp.data):
            if not current_user.is_2fa_enabled:
                current_user.is_2fa_enabled = True
                db.session.commit()
                flash("2FA setup berhasil. Anda telah masuk!", "success")
            else:
                flash("2FA verification successful. You are logged in!", "success")
            return redirect(url_for(HOME_URL))
        else:
            flash("OTP tidak valid. Silakan coba lagi.", "error")
    return render_template("main/verify-2fa.html", form=form)
