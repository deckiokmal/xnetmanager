from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    session,
    current_app,
)
from flask_login import login_user, logout_user, current_user, login_required
from src import db, bcrypt
from src.models.app_models import User
from src.utils.forms_utils import LoginForm, TwoFactorForm
from .decorators import required_2fa
from src.utils.LoginUtils import LoginUtils
import logging
from datetime import datetime
import pytz
import pyotp
import qrcode
import io
import base64

# Membuat blueprint main_bp dan error_bp
main_bp = Blueprint("main", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging untuk aplikasi
logging.basicConfig(level=logging.INFO)


@main_bp.before_app_request
def setup_logging():
    """
    Mengatur level logging untuk aplikasi.
    """
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


@error_bp.app_errorhandler(404)
def page_not_found(error):
    """
    Menangani error 404 dan menampilkan halaman 404.
    """
    current_app.logger.error(f"Error 404: {error}")
    return render_template("main/404.html"), 404


# Middleware untuk autentikasi dan otorisasi sebelum permintaan.
@main_bp.before_request
def before_request_func():
    """
    Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan.
    Jika pengguna harus logout paksa, lakukan logout dan arahkan ke halaman login.
    Jika tidak terotentikasi, kembalikan pesan 'Unauthorized access'.
    """

    # Exempt pages that should not trigger authentication or force logout
    exempt_pages = [url_for("main.login")]

    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
    current_app.logger.info(f"Request received from IP: {ip_address}")

    if request.path in exempt_pages:
        return  # Allow access to exempted pages without further checks

    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return render_template("main/404.html"), 404

    # If the user is authenticated but needs to be logged out due to force_logout
    if current_user.force_logout:
        current_user.force_logout = False  # Reset the flag
        db.session.commit()
        logout_user()
        flash("Your password has been updated. Please log in again.", "info")
        return redirect(url_for("main.login"))


@main_bp.context_processor
def inject_user():
    """
    Menyediakan first_name dan last_name pengguna yang terotentikasi ke dalam template.
    """
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


# --------------------------------------------------------------------------------
# Main Page Section
# --------------------------------------------------------------------------------


# Main APP starting
DASHBOARD_URL = "users.dashboard"
SETUP_VERIFY_2FA_URL = "main.setup_and_verify_2fa"


# Login Page
@main_bp.route("/", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        # Cek apakah pengguna sudah memverifikasi 2FA
        if current_user.is_2fa_enabled:
            if session.get("2fa_verified", False):
                return redirect(url_for(DASHBOARD_URL))
            else:
                return redirect(url_for(SETUP_VERIFY_2FA_URL))
        else:
            return redirect(url_for(SETUP_VERIFY_2FA_URL))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.email.data
        if not LoginUtils.check_login_attempts(username):
            return redirect(url_for("main.login"))

        try:
            user = User.query.filter_by(email=username).first()
            if not user:
                flash("Invalid username or password", "danger")
                return redirect(url_for("main.login"))
            elif user and bcrypt.check_password_hash(
                user.password_hash, form.password.data
            ):
                login_user(user)

                current_app.logger.info(f"User {user.email} has authenticate.")

                LoginUtils.reset_login_attempts(
                    username
                )  # Reset percobaan login setelah berhasil

                # Cek apakah pengguna sudah mengaktifkan 2FA
                if user.is_2fa_enabled:
                    session["pre_2fa"] = True
                    return redirect(url_for(SETUP_VERIFY_2FA_URL))
                else:
                    return redirect(url_for(SETUP_VERIFY_2FA_URL))

            else:
                current_app.logger.warning(f"Failed login attempt for {username}.")
                LoginUtils.increment_login_attempts(
                    username
                )  # Tambahkan percobaan login gagal
        except Exception as e:
            current_app.logger.error(f"Login error: {str(e)}")
            flash("Terjadi kesalahan saat login. Silakan coba lagi.", "danger")

    return render_template("/main/login.html", form=form)


# --------------------------------------------------------------------------------
# Logout and 2FA Section
# --------------------------------------------------------------------------------


# Log Out
@main_bp.route("/logout")
@login_required
@required_2fa
def logout():
    try:
        user_email = current_user.email
        logout_user()
        session.pop("authenticated", None)
        session.pop("2fa_verified", None)
        current_app.logger.info(f"User {user_email} logged out.")
    except Exception as e:
        current_app.logger.error(f"Logout error: {str(e)}")
        flash("Terjadi kesalahan saat logout. Silakan coba lagi.", "danger")

    return redirect(url_for("main.login"))


# --------------------------------------------------------------------------------
# 2FA Page Section
# --------------------------------------------------------------------------------
@main_bp.route("/setup-verify-2fa", methods=["GET", "POST"])
@login_required
def setup_and_verify_2fa():
    timezone = pytz.timezone("Asia/Jakarta")
    current_time = datetime.now(timezone)
    user = current_user
    form = TwoFactorForm()

    # Generate Secret Token & QR Code
    try:
        if not user.secret_token:
            user.secret_token = pyotp.random_base32()
            db.session.commit()

        totp = pyotp.TOTP(user.secret_token)
        uri = totp.provisioning_uri(user.email, issuer_name="XNETMANAGER")

        # Generate QR Code
        qr = qrcode.QRCode()
        qr.add_data(uri)
        qr.make()
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf)
        img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    except Exception as e:
        current_app.logger.error(f"2FA setup error for {user.email}: {str(e)}")
        flash("Terjadi kesalahan saat setup 2FA. Silakan coba lagi.", "danger")
        return redirect(url_for("main.setup_and_verify_2fa"))

    # Handle OTP Verification
    if form.validate_on_submit():
        try:
            if user.is_otp_valid(form.otp.data):
                user.is_2fa_enabled = True
                user.last_login = current_time
                db.session.commit()
                session.pop("pre_2fa", None)
                session["2fa_verified"] = True
                flash("Verifikasi 2FA berhasil! Anda sekarang masuk.", "success")
                current_app.logger.info(f"User {user.email} berhasil verifikasi 2FA.")
                return redirect(url_for(DASHBOARD_URL))
            else:
                current_app.logger.warning(
                    f"Percobaan OTP tidak valid untuk {user.email}."
                )
                flash("Kode OTP tidak valid. Silakan coba lagi.", "danger")
        except Exception as e:
            current_app.logger.error(f"Error verifikasi 2FA: {str(e)}")
            flash("Terjadi kesalahan saat verifikasi. Silakan coba lagi.", "danger")

    return render_template(
        "main/setup_verify_2fa.html",  # Template yang sudah digabung
        qr_image=img_b64,
        secret=user.secret_token,
        form=form,
    )
