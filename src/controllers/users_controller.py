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
from flask_login import login_required, current_user, logout_user
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


# Middleware untuk autentikasi dan otorisasi sebelum permintaan.
@users_bp.before_request
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
        # Filter perangkat berdasarkan peran user
        if current_user.has_role("Admin"):
            devices = DeviceManager.query  # Admin dapat melihat semua perangkat
        else:
            devices = DeviceManager.query.filter_by(
                user_id=current_user.id
            )  # Non-Admin hanya dapat melihat perangkat miliknya

        # Filter template berdasarkan peran user
        if current_user.has_role("Admin"):
            templates = (
                TemplateManager.query.all()
            )  # Admin dapat melihat semua template
        else:
            templates = TemplateManager.query.all()

        # Filter file konfigurasi berdasarkan peran user
        if current_user.has_role("Admin"):
            configuration_file = (
                ConfigurationManager.query
            )  # Admin dapat melihat semua konfigurasi
        else:
            configuration_file = ConfigurationManager.query.filter_by(
                user_id=current_user.id
            )  # Non-Admin hanya dapat melihat konfigurasi miliknya

        # Filter backup data berdasarkan peran user
        if current_user.has_role("Admin"):
            backupdata = BackupData.query  # Admin dapat melihat semua backup data
        else:
            backupdata = BackupData.query.filter_by(
                user_id=current_user.id
            )  # Non-Admin hanya dapat melihat backup data miliknya

        # Menghitung jumlah total
        total_devices = devices.count()
        total_templates = len(
            templates
        )  # .all() menghasilkan list, jadi menggunakan len() untuk menghitung jumlahnya
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
# User Management Section CRUD Operation
# --------------------------------------------------------------------------------


@users_bp.route("/users-management", methods=["GET"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Users"], page="Users Management")
def index():
    """
    Display the main page of the User Management.
    This page includes a list of users and supports pagination and searching.
    """
    # Logging untuk akses ke endpoint
    current_app.logger.info(f"{current_user.email} accessed users-management")

    # Menginisialisasi form untuk pendaftaran pengguna baru
    form = RegisterForm()

    # Mengambil parameter search dari query string URL (jika ada) dan mengubahnya menjadi huruf kecil.
    search_query = request.args.get("search", "").lower()
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )
    if page < 1 or per_page < 1:
        flash("Invalid pagination values.", "danger")

    try:
        # Memulai query untuk mengambil semua data
        user_query = User.query

        if search_query:
            user_query = user_query.filter(
                User.email.ilike(f"%{search_query}%")
                | User.company.ilike(f"%{search_query}%")
            )

        # Pagination dan User query
        total_user = user_query.count()
        users = user_query.limit(per_page).offset(offset).all()
        pagination = Pagination(page=page, per_page=per_page, total=total_user)

        if total_user == 0:
            flash("Tidak ada data apapun di halaman ini.", "info")

        return render_template(
            "/users_management/index.html",
            form=form,
            search_query=search_query,
            page=page,
            per_page=per_page,
            total_user=total_user,
            users=users,
            pagination=pagination,
            open_modal=False,  # Pastikan modal tidak terbuka di halaman awal
        )

    except Exception as e:
        current_app.logger.error(
            f"An error occurred on the user management page accessed by {current_user.email}: {str(e)}"
        )
        flash(
            "An unexpected error occurred while accessing the user management page. Please try again later.",
            "danger",
        )
        return redirect(url_for("users.dashboard"))


@users_bp.route("/create-user", methods=["POST"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Users"], page="Users Management")
def create_user():
    form = RegisterForm(request.form)

    try:
        if form.validate_on_submit():
            # Buat user baru setelah validasi berhasil
            new_user = User(
                first_name=form.first_name.data.strip(),
                last_name=form.last_name.data.strip(),
                email=form.email.data.strip(),
                password_hash=form.password.data.strip(),
            )

            # Assign role 'User'
            user_role = Role.query.filter_by(name="User").first()
            if user_role:
                new_user.roles.append(user_role)

            db.session.add(new_user)
            db.session.commit()

            flash("User berhasil ditambahkan.", "success")
            return redirect(url_for("users.index"))
        else:
            # Jika validasi form gagal, render ulang halaman dengan modal terbuka
            search_query = request.args.get("search", "").lower()
            page, per_page, offset = get_page_args(
                page_parameter="page", per_page_parameter="per_page", per_page=10
            )
            user_query = User.query

            if search_query:
                user_query = user_query.filter(
                    User.email.ilike(f"%{search_query}%")
                    | User.company.ilike(f"%{search_query}%")
                )

            total_user = user_query.count()
            users = user_query.limit(per_page).offset(offset).all()
            pagination = Pagination(page=page, per_page=per_page, total=total_user)

            return render_template(
                "users_management/index.html",
                form=form,
                users=users,
                search_query=search_query,
                page=page,
                per_page=per_page,
                total_user=total_user,
                pagination=pagination,
                open_modal=True,  # Modal tetap terbuka
            )

    except Exception as e:
        current_app.logger.error(
            f"Error creating user {form.email.data.strip()}: {str(e)}"
        )
        flash("Terjadi kesalahan saat membuat user. Silakan coba lagi.", "danger")
        db.session.rollback()
        return redirect(url_for("users.index"))


@users_bp.route("/detail-user/<user_id>", methods=["GET"])
@login_required
@required_2fa
@role_required(roles=["Admin"], permissions=["Manage Users"], page="Users Management")
def detail_user(user_id):
    user = User.query.get_or_404(user_id)

    # Format datetime fields
    date_joined = (
        user.date_joined.strftime("%Y-%m-%d %H:%M:%S") if user.date_joined else None
    )
    last_login = (
        user.last_login.strftime("%Y-%m-%d %H:%M:%S") if user.last_login else None
    )

    # Convert roles to a string or list of roles
    roles = ", ".join([role.name for role in user.roles])

    return jsonify(
        {
            "email": user.email,
            "password": "*****",  # Mask the password for security
            "first_name": user.first_name,
            "last_name": user.last_name,
            "roles": roles,
            "is_2fa_enabled": "Yes" if user.is_2fa_enabled else "No",
            "date_joined": date_joined,
            "last_login": last_login,
        }
    )


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

            # Track if the password was updated
            password_changed = False

            # Update password if provided
            if form.password.data:
                user.password_hash = bcrypt.generate_password_hash(
                    form.password.data
                ).decode("utf-8")
                password_changed = True  # Mark that the password has been updated
                current_app.logger.info(f"Password updated for user: {user.email}")

            db.session.commit()
            flash("User updated successfully.", "success")
            current_app.logger.info(
                f"User {current_user.email} successfully updated user with ID: {user_id}"
            )

            # If password was changed, force the user to log out by setting `force_logout`
            if password_changed:
                user.force_logout = True  # Force logout the user on next request
                db.session.commit()
                current_app.logger.info(
                    f"User {user.email} will be forced to log out on next request."
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
        db.session.rollback()

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
