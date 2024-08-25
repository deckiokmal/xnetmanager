from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app,
    jsonify,
)
from flask_login import login_required, current_user
from src import db, bcrypt
from src.models.app_models import (
    User,
    Role,
    DeviceManager,
    TemplateManager,
    ConfigurationManager,
    BackupData,
)
from src.utils.forms_utils import RegisterForm, UserUpdateForm
from .decorators import login_required, role_required, required_2fa
from flask_paginate import Pagination, get_page_args
import logging

# Membuat blueprint users dan error
users_bp = Blueprint("users", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging untuk aplikasi
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")


@users_bp.before_app_request
def setup_logging():
    """
    Mengatur level logging untuk aplikasi.
    """
    if not current_app.debug:  # Only add handler when not in debug mode
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
        )
        current_app.logger.addHandler(handler)


@error_bp.app_errorhandler(404)
def page_not_found(error):
    """
    Menangani error 404 dan menampilkan halaman 404.
    """
    current_app.logger.error(f"Error 404: {error}")
    return render_template("main/404.html"), 404


@users_bp.before_request
def before_request_func():
    """
    Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan.
    Jika tidak, mengembalikan pesan 'Unauthorized access'.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return render_template("main/404.html"), 404


@users_bp.context_processor
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
# Dashboard
# --------------------------------------------------------------------------------


@users_bp.route("/dashboard")
@login_required
@required_2fa
def dashboard():
    try:
        # Mengambil semua perangkat dan template konfigurasi dari database
        devices = DeviceManager.query.filter_by(user_id=current_user.id)
        templates = TemplateManager.query.all()
        configuration_file = ConfigurationManager.query.filter_by(
            user_id=current_user.id
        )
        backupdata = BackupData.query.filter_by(user_id=current_user.id)

        # Menghitung jumlah total
        total_devices = devices.count()
        total_templates = len(templates)
        total_configuration_file = configuration_file.count()
        total_backupdata = backupdata.count()

        # Menghitung jumlah perangkat berdasarkan vendor
        device_vendor_count = {}
        for device in devices:
            vendor = device.vendor
            if vendor in device_vendor_count:
                device_vendor_count[vendor] += 1
            else:
                device_vendor_count[vendor] = 1

        # Menghitung jumlah template berdasarkan vendor
        template_vendor_count = {}
        for template in templates:
            vendor = template.vendor
            if vendor in template_vendor_count:
                template_vendor_count[vendor] += 1
            else:
                template_vendor_count[vendor] = 1

        current_app.logger.info(f"Dashboard accessed by {current_user.email}")

        return render_template(
            "/users_management/dashboard.html",
            device_vendor_keys=list(device_vendor_count.keys()),
            device_vendor_values=list(device_vendor_count.values()),
            template_vendor_keys=list(template_vendor_count.keys()),
            template_vendor_values=list(template_vendor_count.values()),
            total_devices=total_devices,
            total_templates=total_templates,
            total_configuration_file=total_configuration_file,
            total_backupdata=total_backupdata,
        )
    except Exception as e:
        current_app.logger.error(f"Error loading dashboard: {str(e)}")
        flash("Terjadi kesalahan saat memuat dashboard.", "danger")
        return redirect(url_for("main.login"))


# --------------------------------------------------------------------------------
# User Management Section
# --------------------------------------------------------------------------------


@users_bp.route("/users-management", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Users"], page="Users Management")
def index():
    """
    Display the main page of the User Management.
    This page includes a list of users and supports pagination and searching.
    """
    try:
        form = RegisterForm(request.form)  # Initialize the form for creating new users

        search_query = request.args.get("search", "").lower()  # Get the search query

        page, per_page, offset = get_page_args(
            page_parameter="page", per_page_parameter="per_page", per_page=10
        )

        # Filtering users based on search query
        if search_query:
            user_query = User.query.filter(User.email.ilike(f"%{search_query}%"))
            current_app.logger.info(
                f"Search query '{search_query}' performed by {current_user.email}."
            )
        else:
            user_query = User.query

        total_user = user_query.count()
        users = user_query.limit(per_page).offset(offset).all()

        pagination = Pagination(page=page, per_page=per_page, total=total_user)

        current_app.logger.info(
            f"User management page accessed by {current_user.email}"
        )

        return render_template(
            "/users_management/index.html",
            users=users,
            page=page,
            per_page=per_page,
            pagination=pagination,
            search_query=search_query,
            total_user=total_user,
            form=form,
        )

    except Exception as e:
        current_app.logger.error(
            f"An error occurred on the user management page accessed by {current_user.email}: {str(e)}"
        )
        flash(
            "An unexpected error occurred while accessing the user management page. Please try again later.",
            "danger",
        )
        return render_template(
            "/users_management/index.html",
            users=[],
            page=1,
            per_page=10,
            pagination=Pagination(page=1, per_page=10, total=0),
            search_query="",
            total_user=0,
            form=form,
        )


@users_bp.route("/create-user", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Users"], page="Users Management")
def create_user():
    form = RegisterForm(request.form)

    try:
        if form.validate_on_submit():
            existing_user = User.query.filter_by(email=form.email.data.strip()).first()
            if existing_user:
                flash("Alamat email sudah terdaftar", "warning")
                current_app.logger.warning(
                    f"Registration attempt failed: {form.email.data.strip()} already exists"
                )
            else:
                # Create a new user with provided data
                new_user = User(
                    first_name=form.first_name.data.strip(),
                    last_name=form.last_name.data.strip(),
                    email=form.email.data.strip(),
                    password_hash=form.password.data.strip(),
                )

                # Assign the 'User' role to the new user
                view_role = Role.query.filter_by(name="User").first()
                if view_role:
                    new_user.roles.append(view_role)

                db.session.add(new_user)
                db.session.commit()

                flash("User berhasil ditambahkan.", "success")
                current_app.logger.info(f"New user created: {form.email.data.strip()}")
                return redirect(url_for("users.index"))
        else:
            # Log and flash form validation errors
            for field, errors in form.errors.items():
                for error in errors:
                    flash(
                        f"Kesalahan pada {getattr(form, field).label.text}: {error}",
                        "danger",
                    )
            current_app.logger.warning("Form validation failed during user creation.")

    except Exception as e:
        current_app.logger.error(
            f"Error creating user {form.email.data.strip()}: {str(e)}"
        )
        flash("Terjadi kesalahan saat membuat user. Silakan coba lagi.", "danger")
        db.session.rollback()  # Rollback the session to maintain data integrity

    return redirect(url_for("users.index"))


@users_bp.route("/update-user/<user_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Users"], page="Users Management")
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserUpdateForm(obj=user)

    current_app.logger.info(
        f"User {current_user.email} is attempting to update user with ID: {user_id}"
    )

    try:
        if form.validate_on_submit():
            if User.query.filter(
                User.email == form.email.data, User.id != user.id
            ).first():
                flash(
                    "Email sudah terdaftar!. silahkan pilih email yang lain.", "warning"
                )
                current_app.logger.warning(
                    f"Update attempt by user {current_user.email} failed: {form.email.data} already exists."
                )
                return render_template(
                    "/users_management/update_user.html", form=form, user=user
                )

            # Update user details
            user.first_name = form.first_name.data
            user.last_name = form.last_name.data
            user.email = form.email.data
            user.phone_number = form.phone_number.data
            user.profile_picture = form.profile_picture.data
            user.company = form.company.data
            user.title = form.title.data
            user.city = form.city.data
            user.division = form.division.data

            user.is_verified = form.is_verified.data == "True"
            user.is_2fa_enabled = form.is_2fa_enabled.data == "True"
            user.is_active = form.is_active.data == "True"
            user.time_zone = form.time_zone.data

            # Update password if provided
            if form.password.data:
                user.password_hash = bcrypt.generate_password_hash(
                    form.password.data
                ).decode("utf-8")
                current_app.logger.info(f"Password updated for user: {user.email}")

            db.session.commit()
            flash("User updated successfully.", "success")
            current_app.logger.info(
                f"User {current_user.email} successfully updated user with ID: {user_id}"
            )
            return redirect(url_for("users.index"))
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(
                        f"Kesalahan pada {getattr(form, field).label.text}: {error}",
                        "danger",
                    )
            current_app.logger.warning(
                f"Form validation failed for user update by {current_user.email}."
            )
    except Exception as e:
        current_app.logger.error(
            f"Error occurred while user {current_user.email} was updating user {user.email}: {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat memperbarui pengguna. Silakan coba lagi.", "danger"
        )
        db.session.rollback()  # Rollback the session to maintain data integrity

    return render_template("/users_management/update_user.html", form=form, user=user)


@users_bp.route("/delete-user/<user_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Users"], page="Users Management")
def delete_user(user_id):
    """
    Menghapus pengguna berdasarkan ID jika pengguna tersebut bukan akun yang sedang login.
    Menyediakan logging, feedback pengguna, dan error handling.
    """
    try:
        current_app.logger.info(
            f"User {current_user.email} is attempting to delete user with ID: {user_id}"
        )

        # Mencegah pengguna menghapus akun mereka sendiri
        if current_user.id == user_id:
            flash("Anda tidak bisa delete akun anda sendiri.", "warning")
            current_app.logger.warning(
                f"User {current_user.email} attempted to delete their own account with ID: {user_id}"
            )
            return redirect(url_for("users.index"))

        # Mendapatkan pengguna berdasarkan ID
        user = User.query.get(user_id)
        if not user:
            flash("User tidak ditemukan.", "info")
            current_app.logger.info(
                f"User {current_user.email} attempted to delete non-existing user with ID: {user_id}"
            )
            return redirect(url_for("users.index"))

        # Melakukan penghapusan pengguna
        db.session.delete(user)
        db.session.commit()

        flash("User telah dihapus.", "success")
        current_app.logger.info(
            f"User {current_user.email} successfully deleted user with ID: {user_id}"
        )
    except Exception as e:
        current_app.logger.error(
            f"Error occurred while user {current_user.email} was deleting user with ID {user_id}: {str(e)}"
        )
        flash("Terjadi kesalahan saat menghapus pengguna. Silakan coba lagi.", "danger")
        db.session.rollback()  # Rollback session untuk menjaga integritas data

    return redirect(url_for("users.index"))


# --------------------------------------------------------------------------------
# API Users Section
# --------------------------------------------------------------------------------


# api endpoint untuk memberikan seluruh data user
@users_bp.route("/api/users", methods=["GET"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Roles"], page="API Users")
def api_users():
    users = User.query.all()  # Mengambil semua pengguna
    users_list = [{"id": u.id, "name": u.email} for u in users]
    current_app.logger.warning(f"User {current_user.email} access API Users data.")
    return jsonify(users_list)
