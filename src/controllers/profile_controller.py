from flask import (
    Blueprint,
    render_template,
    jsonify,
    request,
    redirect,
    url_for,
    flash,
    current_app,
)
from flask_login import login_required, current_user
from src.models.users_model import User
from .decorators import login_required, role_required
from src import db
from src.utils.qrcode_utils import get_b64encoded_qr_image
from src.utils.forms_utils import ProfileUpdateForm
import logging


# Membuat blueprint users
profile_bp = Blueprint("profile", __name__)
error_bp = Blueprint("error", __name__)


# Setup logging
logging.basicConfig(level=logging.INFO)


@profile_bp.before_app_request
def setup_logging():
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


# Menangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("main/404.html"), 404


# middleware untuk autentikasi dan otorisasi
@profile_bp.before_request
def before_request_func():
    if not current_user.is_authenticated:
        return jsonify({"message": "Unauthorized access"}), 401


# Context processor untuk menambahkan first_name dan last_name ke dalam konteks di semua halaman.
@profile_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


# Users profile
@profile_bp.route("/profile_user", methods=["GET", "POST"])
@login_required
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Users", "Manage Profile"],
    page="Users Management",
)
def index():
    # Get data current user
    user_id = current_user.id
    user = User.query.get(user_id)

    return render_template("/users_management/profile_user.html", user=user)


# Halaman update data user berdasarkan current_user
@profile_bp.route("/profile_update", methods=["GET", "POST"])
@login_required
def profile_update():
    user = User.query.get_or_404(current_user.id)
    form = ProfileUpdateForm(obj=user)  # Pre-populate form with existing data

    if form.validate_on_submit():

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
        user.time_zone = form.time_zone.data

        # Commit perubahan ke database
        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile.index"))

    return render_template("/users_management/profile_update.html", form=form, user=user)


# kirim link email verifikasi
@profile_bp.route("/verify-email")
@login_required
def verify_email():
    # Send verification email
    return redirect(url_for("dashboard"))


# Halaman confirm verifikasi
@profile_bp.route("/confirm-verification/<token>")
@login_required
def confirm_verification(token):
    user = User.query.filter_by(secret_token=token).first_or_404()
    user.is_verified = True
    user.role = "User"
    db.session.commit()
    flash("Email verified successfully.", "success")
    return redirect(url_for("dashboard"))


# mengaktifkan 2fa
@profile_bp.route("/enable-2fa", methods=["GET", "POST"])
@login_required
def enable_2fa():
    if request.method == "POST":
        current_user.is_2fa_enabled = True
        db.session.commit()
        return redirect(url_for("verify_2fa"))
    return render_template("enable_2fa.html")


# Setup 2fa Google Authenticator dan Scan QR Code
@profile_bp.route("/setup-2fa")
@login_required
def setup_two_factor_auth():
    secret = current_user.secret_token
    uri = current_user.get_authentication_setup_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)
    return render_template(
        "main/setup-2fa.html", secret=secret, qr_image=base64_qr_image
    )
