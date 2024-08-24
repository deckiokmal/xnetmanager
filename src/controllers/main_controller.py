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


# Middleware untuk autentikasi dan otorisasi
@main_bp.before_request
def before_request_func():
    exempt_pages = ["main.login", "main.register"]
    if request.endpoint in exempt_pages:
        return None

    if not current_user.is_authenticated:
        current_app.logger.info(f"Unauthorize Access, Redirect to Login.")
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
HOME_URL = "users.dashboard"
SETUP_2FA_URL = "main.setup_2fa"
VERIFY_2FA_URL = "main.verify_2fa"


# Login Page
@main_bp.route("/", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        # Cek apakah pengguna sudah memverifikasi 2FA
        if current_user.is_2fa_enabled:
            if session.get("2fa_verified", False):
                return redirect(url_for(HOME_URL))
            else:
                return redirect(url_for(VERIFY_2FA_URL))
        else:
            return redirect(url_for(SETUP_2FA_URL))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.email.data
        if not LoginUtils.check_login_attempts(username):
            return redirect(url_for("main.login"))

        try:
            user = User.query.filter_by(email=username).first()
            if not user:
                flash(f"User belum terdaftar!. Silahkan register", "warning")
            elif user and bcrypt.check_password_hash(
                user.password_hash, form.password.data
            ):
                login_user(user)

                user.last_login = datetime.utcnow()
                db.session.commit()

                current_app.logger.info(f"User {user.email} logged in.")

                LoginUtils.reset_login_attempts(
                    username
                )  # Reset percobaan login setelah berhasil

                # Cek apakah pengguna sudah mengaktifkan 2FA
                if user.is_2fa_enabled:
                    session["pre_2fa"] = True
                    return redirect(url_for(VERIFY_2FA_URL))
                else:
                    return redirect(url_for(SETUP_2FA_URL))

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


# Setup 2FA Google Authenticator dan Scan QR Code
@main_bp.route("/setup-2fa")
@login_required
def setup_2fa():
    user = current_user
    try:
        if not user.secret_token:
            user.secret_token = pyotp.random_base32()
            db.session.commit()

        totp = pyotp.TOTP(user.secret_token)
        uri = totp.provisioning_uri(user.email, issuer_name="XNETMANAGER")

        qr = qrcode.QRCode()
        qr.add_data(uri)
        qr.make()
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf)
        img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

        current_app.logger.info(f"User {user.email} set up 2FA.")
        return render_template(
            "main/setup_2fa.html", qr_image=img_b64, secret=user.secret_token
        )
    except Exception as e:
        current_app.logger.error(f"2FA setup error for {user.email}: {str(e)}")
        flash("Terjadi kesalahan saat setup 2FA. Silakan coba lagi.", "danger")
        return redirect(url_for(HOME_URL))


# Verifikasi kode OTP Google Authenticator jika user mengaktifkan 2FA di user profile
@main_bp.route("/verify-2fa", methods=["GET", "POST"])
@login_required
def verify_2fa():
    form = TwoFactorForm()
    if form.validate_on_submit():
        try:
            if current_user.is_otp_valid(form.otp.data):
                current_user.is_2fa_enabled = True
                db.session.commit()
                session.pop("pre_2fa", None)
                session["2fa_verified"] = True
                flash("2FA verification successful. You are logged in!", "success")
                current_app.logger.info(
                    f"User {current_user.email} successfully verified 2FA."
                )
                return redirect(url_for(HOME_URL))
            else:
                current_app.logger.warning(
                    f"Invalid OTP attempt for {current_user.email}."
                )
                flash("Invalid OTP. Please try again.", "error")
        except Exception as e:
            current_app.logger.error(f"2FA verification error: {str(e)}")
            flash("Terjadi kesalahan saat verifikasi 2FA. Silakan coba lagi.", "danger")

    return render_template("main/verify_2fa.html", form=form)
