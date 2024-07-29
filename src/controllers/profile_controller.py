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
from src import db, bcrypt
from src.utils.qrcode_utils import get_b64encoded_qr_image
from src.utils.forms_utils import (
    ProfileUpdateForm,
    ChangePasswordForm,
    ProfilePictureForm,
)
import logging
from werkzeug.utils import secure_filename
import os


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
    form = ChangePasswordForm()
    form_picture = ProfilePictureForm()

    return render_template(
        "/users_management/profile_user.html",
        user=user,
        form=form,
        form_picture=form_picture,
    )


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

    return render_template(
        "/users_management/profile_update.html", form=form, user=user
    )


@profile_bp.route("/change_password", methods=["POST"])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        # Check old password
        if not bcrypt.check_password_hash(
            current_user.password_hash, form.old_password.data
        ):
            flash("Old password is incorrect.", "error")
            return redirect(url_for("profile.index"))

        # Check if new passwords match
        if form.new_password.data != form.repeat_password.data:
            flash("New passwords do not match.", "error")
            return redirect(url_for("profile.index"))

        # Update password
        current_user.password_hash = bcrypt.generate_password_hash(
            form.new_password.data
        ).decode("utf-8")
        db.session.commit()
        flash("Password updated successfully.", "success")
        return redirect(url_for("profile.index"))

    # Handle form validation errors and return to profile page
    for field, errors in form.errors.items():
        for error in errors:
            flash(error, "error")

    return redirect(url_for("profile.index"))


# Define a directory for storing uploaded files
PROFILE_PICTURE_DIRECTORY = "profile_pictures"


@profile_bp.route("/upload_profile_picture", methods=["POST"])
@login_required
def upload_profile_picture():
    form_picture = ProfilePictureForm()

    if form_picture.validate_on_submit():
        file = form_picture.profile_picture.data

        if file:
            # Ambil nama file dan ekstensi
            file_extension = os.path.splitext(file.filename)[
                1
            ]  # Mengambil ekstensi file
            # Format nama file
            filename = (
                f"{current_user.first_name} {current_user.last_name}{file_extension}"
            )
            # Path lengkap untuk menyimpan file
            file_path = os.path.join(
                current_app.static_folder, PROFILE_PICTURE_DIRECTORY, filename
            )
            file.save(file_path)

            # Simpan path relatif dengan slash
            current_user.profile_picture = os.path.join(
                PROFILE_PICTURE_DIRECTORY, filename
            ).replace("\\", "/")
            db.session.commit()

            flash("Profile picture updated successfully.", "success")
        else:
            flash("No file selected.", "error")

    return redirect(url_for("profile.index"))


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
