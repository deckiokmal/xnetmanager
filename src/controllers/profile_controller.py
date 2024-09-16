from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app,
)
from flask_login import login_required, current_user, logout_user
from src.models.app_models import User
from .decorators import login_required, role_required, required_2fa
from src import db, bcrypt
from src.utils.forms_utils import (
    ProfileUpdateForm,
    ChangePasswordForm,
    ProfilePictureForm,
    User2FAEnableForm,
)
import logging
import os
from src.utils.mail_utils import (
    send_verification_email,
)

# Membuat blueprint users
profile_bp = Blueprint("profile", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging untuk aplikasi
logging.basicConfig(level=logging.INFO)


@profile_bp.before_app_request
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
@profile_bp.before_request
def before_request_func():
    """
    Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan.
    Jika pengguna harus logout paksa, lakukan logout dan arahkan ke halaman login.
    Jika tidak terotentikasi, kembalikan pesan 'Unauthorized access'.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return render_template("main/404.html"), 404

    # Jika pengguna terotentikasi dan memiliki flag force_logout, lakukan logout
    if current_user.force_logout:
        current_user.force_logout = False  # Reset the flag
        db.session.commit()
        logout_user()
        flash("Your password has been updated. Please log in again.", "info")
        return redirect(url_for("main.login"))


# Context processor untuk menambahkan first_name dan last_name ke dalam konteks di semua halaman.
@profile_bp.context_processor
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
# User Profile Section
# --------------------------------------------------------------------------------


# Users profile
@profile_bp.route("/profile", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Users", "Manage Profile"],
    page="Users Management",
)
def index():
    try:
        # Get data current user
        user_id = current_user.id
        user = User.query.get(user_id)

        if not user:
            current_app.logger.error(
                f"User {current_user.email} tried to access profile, but user data was not found."
            )
            flash(
                "Terjadi kesalahan saat mengakses data profil. Silakan coba lagi.",
                "danger",
            )
            return redirect(url_for("main.dashboard"))  # Redirect to a safe page

        form = ChangePasswordForm()
        towfactorform = User2FAEnableForm()
        form_picture = ProfilePictureForm()

        # Set the default value of the form based on the user's 2FA status
        towfactorform.is_2fa_enabled.data = "True" if user.is_2fa_enabled else "False"

        current_app.logger.info(f"User {current_user.email} accessed profile page.")
    except Exception as e:
        current_app.logger.error(
            f"Error occurred while user {current_user.email} accessed profile page: {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat mengakses halaman profil. Silakan coba lagi.",
            "danger",
        )
        return redirect(url_for("main.dashboard"))  # Redirect to a safe page

    return render_template(
        "/users_management/index_profile.html",
        user=user,
        form=form,
        form_picture=form_picture,
        towfactorform=towfactorform,
    )


# Halaman update data user berdasarkan current_user
@profile_bp.route("/profile/settings", methods=["GET", "POST"])
@login_required
@required_2fa
def update_profile():
    user = User.query.get_or_404(current_user.id)
    form = ProfileUpdateForm(obj=user)  # Pre-populate form with existing data

    if form.validate_on_submit():
        try:
            # Mengupdate data user
            user.first_name = form.first_name.data.strip()
            user.last_name = form.last_name.data.strip()
            user.email = form.email.data.strip()
            user.phone_number = form.phone_number.data.strip()
            user.profile_picture = form.profile_picture.data.strip()
            user.company = form.company.data.strip()
            user.title = form.title.data.strip()
            user.city = form.city.data.strip()
            user.division = form.division.data.strip()
            user.time_zone = form.time_zone.data.strip()

            # Commit perubahan ke database
            db.session.commit()

            # Logging sukses
            current_app.logger.info(f"User {current_user.email} updated their profile.")
            flash("Profile updated successfully.", "success")
            return redirect(url_for("profile.index"))

        except Exception as e:
            db.session.rollback()
            # Logging error
            current_app.logger.error(
                f"Error updating profile for user {current_user.email}: {str(e)}"
            )
            flash(
                "An error occurred while updating your profile. Please try again later.",
                "danger",
            )

    elif request.method == "POST" and not form.validate():
        # Logging validasi error
        for field, errors in form.errors.items():
            for error in errors:
                current_app.logger.warning(
                    f"Validation error on {field} for user {current_user.email}: {error}"
                )
                flash(f"Error in {field}: {error}", "danger")

    return render_template(
        "/users_management/profile_settings.html", form=form, user=user
    )


@profile_bp.route("/change-password", methods=["POST"])
@login_required
@required_2fa
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        try:
            # Check old password
            if not bcrypt.check_password_hash(
                current_user.password_hash, form.old_password.data
            ):
                flash("Old password is incorrect.", "error")
                current_app.logger.warning(
                    f"User {current_user.email} provided an incorrect old password."
                )
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
            current_app.logger.info(
                f"User {current_user.email} changed their password."
            )
            return redirect(url_for("profile.index"))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(
                f"Error changing password for user {current_user.email}: {e}"
            )
            flash(
                "An error occurred while changing your password. Please try again later.",
                "danger",
            )

    # Handle form validation errors and return to profile page
    for field, errors in form.errors.items():
        for error in errors:
            flash(error, "error")

    return redirect(url_for("profile.index"))


# Define a directory for storing uploaded files
PROFILE_PICTURE_DIRECTORY = "profile_pictures"


# Change profile Pictures
@profile_bp.route("/upload-profile-picture", methods=["POST"])
@login_required
@required_2fa
def upload_profile_picture():
    form_picture = ProfilePictureForm()

    if form_picture.validate_on_submit():
        try:
            file = form_picture.profile_picture.data

            if file:
                # Ambil nama file dan ekstensi
                file_extension = os.path.splitext(file.filename)[
                    1
                ]  # Mengambil ekstensi file
                # Format nama file
                filename = f"{current_user.first_name} {current_user.last_name}{file_extension}"
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
                current_app.logger.info(
                    f"User {current_user.email} updated their profile picture."
                )
            else:
                flash("No file selected.", "error")
                current_app.logger.warning(
                    f"User {current_user.email} attempted to upload an empty profile picture."
                )
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(
                f"Error uploading profile picture for user {current_user.email}: {e}"
            )
            flash(
                "An error occurred while uploading your profile picture. Please try again later.",
                "danger",
            )

    return redirect(url_for("profile.index"))


# Enable disable 2FA
@profile_bp.route("/toggle_2fa", methods=["POST"])
@login_required
def toggle_2fa():
    form = User2FAEnableForm()

    if form.validate_on_submit():
        try:
            new_2fa_status = form.is_2fa_enabled.data == "True"

            # Cek apakah status baru berbeda dari status saat ini
            if current_user.is_2fa_enabled == new_2fa_status:
                flash("Tidak ada perubahan pada pengaturan 2FA.", "info")
                return redirect(url_for("profile.index"))

            # Update status 2FA pada pengguna
            current_user.is_2fa_enabled = new_2fa_status
            db.session.commit()

            # Arahkan ke halaman yang sesuai
            if new_2fa_status:
                flash("2FA telah diaktifkan. Silakan setup 2FA.", "success")
                current_app.logger.info(f"User {current_user.email} enabled 2FA.")
                return redirect(url_for("main.setup_2fa"))
            else:
                flash("2FA telah dinonaktifkan.", "success")
                current_app.logger.info(f"User {current_user.email} disabled 2FA.")
                return redirect(url_for("profile.index"))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(
                f"Error toggling 2FA for user {current_user.email}: {e}"
            )
            flash("Terjadi kesalahan saat memperbarui pengaturan 2FA.", "danger")

    return redirect(url_for("profile.index"))


# Mail aktif/nonaktif
@profile_bp.route("/mail_enabled", methods=["POST"])
@login_required
def mail_enabled():
    try:
        email_verification = "email_verification" in request.form
        user = User.query.get(current_user.id)

        if email_verification and not user.is_verified:
            send_verification_email(user)
            flash("A verification email has been sent to your email address.", "info")
            current_app.logger.info(
                f"Verification email sent to user {current_user.email}."
            )
        else:
            flash("Your email is already verified.", "warning")
            current_app.logger.warning(
                f"User {current_user.email} attempted to verify an already verified email."
            )

    except Exception as e:
        current_app.logger.error(
            f"Error in email verification for user {current_user.email}: {e}"
        )
        flash(
            "An error occurred while sending the verification email. Please try again later.",
            "danger",
        )

    return redirect(url_for("profile.index"))
