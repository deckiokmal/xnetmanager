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
from src import db
from src.models.app_models import TemplateManager, ConfigurationManager
from src.utils.config_manager_utils import ConfigurationManagerUtils

from werkzeug.utils import secure_filename
import os
from datetime import datetime
from .decorators import login_required, role_required, required_2fa
import random
import string
from flask_paginate import Pagination, get_page_args
import logging
from src.utils.forms_utils import (
    TemplateForm,
    TemplateUpdateForm,
    ManualTemplateForm,
    TemplateDeleteForm,
)
from src.utils.ai_agent_utilities import ConfigurationFileManagement
from src.utils.forms_utils import (
    ManualConfigurationForm,
    AIConfigurationForm,
    UpdateConfigurationForm,
    TalitaQuestionForm,
)
from src.utils.ConfigurationFileUtils import (
    check_ownership,
    read_file,
    generate_random_filename,
    is_safe_path,
    delete_file_safely,
)

# ----------------------------------------------------------------------------------------
# Buat Blueprint untuk endpoint templating management as template_bp
# ----------------------------------------------------------------------------------------
template_bp = Blueprint("template_bp", __name__)
error_bp = Blueprint("error", __name__)


# ----------------------------------------------------------------------------------------
# Middleware and Endpoint security
# ----------------------------------------------------------------------------------------
@template_bp.before_app_request
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
@template_bp.before_request
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


@template_bp.context_processor
def inject_user():
    """
    Menyediakan first_name dan last_name pengguna yang terotentikasi ke dalam template.
    """
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


# ----------------------------------------------------------------------------------------
# Utility
# ----------------------------------------------------------------------------------------
def allowed_file(filename, allowed_extensions):
    """Memeriksa apakah ekstensi file termasuk dalam ekstensi yang diperbolehkan."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def save_uploaded_file(file, upload_folder):
    filename = secure_filename(file.filename)
    file_path = os.path.join(upload_folder, filename)
    file.save(file_path)
    current_app.logger.info(f"File uploaded: {filename}")
    return filename


def read_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        current_app.logger.error(f"File not found: {filepath}")
        return None
    except Exception as e:
        current_app.logger.error(f"Error reading file {filepath}: {e}")
        return None


def generate_random_filename(vendor_name):
    random_str = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    date_str = datetime.now().strftime("%d_%m_%Y")
    filename = f"{vendor_name}_{random_str}_{date_str}"
    current_app.logger.info(f"Generated random filename: {filename}")
    return filename


TEMPLATE_EXTENSIONS = {"j2"}
PARAMS_EXTENSIONS = {"yml", "yaml"}


# ----------------------------------------------------------------------------------------
# Mainpage Section
# ----------------------------------------------------------------------------------------
@template_bp.route("/templates-management", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Templates", "View Templates"],
    page="Templates Management",
)
def template_index():
    """
    Display the main page of the Templates File Manager.
    This page includes a list of Templates file and supports pagination and searching.
    """
    # Logging untuk akses ke endpoint
    current_app.logger.info(f"{current_user.email} accessed index template management")

    form = TemplateForm(request.form)
    form_manual_create = ManualTemplateForm(request.form)
    delete_form = TemplateDeleteForm()

    search_query = request.args.get("search", "").lower()
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )
    if page < 1 or per_page < 1:
        raise ValueError("Page and per_page must be positive integers.")

    try:
        # Inisialisasi query default agar selalu ada nilai
        query = TemplateManager.query

        if search_query:
            query = query.filter(
                TemplateManager.template_name.ilike(f"%{search_query}%")
                | TemplateManager.parameter_name.ilike(f"%{search_query}%")
                | TemplateManager.vendor.ilike(f"%{search_query}%")
                | TemplateManager.version.ilike(f"%{search_query}%")
            )

        total_templates = query.count()
        templates = query.limit(per_page).offset(offset).all()
        pagination = Pagination(page=page, per_page=per_page, total=total_templates)

        # Logging jika tidak ada hasil pencarian
        if total_templates == 0:
            current_app.logger.info(
                f"No template file found for user {current_user.email} with query '{search_query}'"
            )
            flash("No template found matching your search criteria.", "info")

        return render_template(
            "/template_managers/template_index.html",
            form=form,
            form_manual_create=form_manual_create,
            page=page,
            per_page=per_page,
            search_query=search_query,
            total_templates=total_templates,
            templates=templates,
            pagination=pagination,
            delete_form=delete_form,
        )
    except Exception as e:
        # Handle any unexpected errors that occur during the query or pagination
        current_app.logger.error(f"Error accessing Template Manager page: {str(e)}")
        flash(
            "Terjadi kesalahan saat mengakses template. Silakan coba lagi nanti.",
            "danger",
        )
        return redirect(
            url_for("users.dashboard")
        )  # Redirect to a safe page like dashboard


@template_bp.route("/template_detail/<template_id>", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Templates", "View Templates"],
    page="Templates Management",
)
def template_detail(template_id):
    template = TemplateManager.query.get_or_404(template_id)
    try:
        # Ensure paths are safe
        template_dir = current_app.config["TEMPLATE_DIR"]
        template_file_path = os.path.join(template_dir, template.template_name)
        parameter_file_path = os.path.join(template_dir, template.parameter_name)

        # Reading template and parameter files
        if not os.path.isfile(template_file_path) or not os.path.isfile(
            parameter_file_path
        ):
            current_app.logger.error(
                f"Template or parameter file not found for template ID {template_id} accessed by {current_user.email}"
            )
            return (
                jsonify({"error": "Template atau parameter file tidak ditemukan."}),
                404,
            )

        template_content = read_file(template_file_path)
        parameter_content = read_file(parameter_file_path)

        if template_content is None or parameter_content is None:
            current_app.logger.error(
                f"Error reading files for template ID {template_id} by {current_user.email}"
            )
            return (
                jsonify(
                    {
                        "error": "Terjadi kesalahan saat membaca konten template atau parameter."
                    }
                ),
                500,
            )

        current_app.logger.info(
            f"User {current_user.email} accessed details for template ID {template_id}"
        )
        return jsonify(
            {
                "template_name": template.template_name,
                "parameter_name": template.parameter_name,
                "vendor": template.vendor,
                "version": template.version,
                "description": template.description,
                "template_content": template_content,
                "parameter_content": parameter_content,
                "created_by": template.created_by,
            }
        )

    except Exception as e:
        current_app.logger.error(
            f"Unexpected error in template_detail for template ID {template_id} by {current_user.email}: {str(e)}"
        )
        return (
            jsonify(
                {
                    "error": "Terjadi kesalahan yang tidak terduga. Silakan coba lagi nanti."
                }
            ),
            500,
        )


# ----------------------------------------------------------------------------------------
# CRUD Templating Management Section
# ----------------------------------------------------------------------------------------
@template_bp.route("/upload-template", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def upload_template():
    """Handles file uploads for template and parameter files, saving them to the database with enhanced security checks."""
    try:
        form = TemplateForm()  # Inisialisasi form tanpa data terlebih dahulu

        # Mengisi form data dari request
        form = TemplateForm(request.form)  # Menyertakan request.form dalam form
        form.j2 = request.files.get("j2")  # Mengambil file template
        form.yaml = request.files.get("yaml")  # Mengambil file parameter

        # Validasi form dengan WTForms (CSRF, vendor, version, dll.)
        if not form.validate():
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{getattr(form, field).label.text}: {error}", "danger")
            current_app.logger.warning(
                f"User {current_user.email} submitted invalid template form data."
            )
            return redirect(url_for("template_bp.template_index"))

        # Retrieve files and form data
        j2 = request.files.get("j2")
        yaml = request.files.get("yaml")
        vendor = form.vendor.data
        version = form.version.data
        description = form.description.data

        # Pastikan kedua file disertakan
        if not j2 or j2.filename == "":
            flash("File template tidak ada.", "danger")
            current_app.logger.warning(
                f"User {current_user.email} attempted to upload without providing a template file."
            )
            return redirect(url_for("template_bp.template_index"))

        if not yaml or yaml.filename == "":
            flash("File parameter tidak ada.", "danger")
            current_app.logger.warning(
                f"User {current_user.email} attempted to upload without providing a parameter file."
            )
            return redirect(url_for("template_bp.template_index"))

        # Validasi dan simpan file template
        template_dir = current_app.config["TEMPLATE_DIR"]
        if j2.filename and allowed_file(j2.filename, TEMPLATE_EXTENSIONS):
            template_name = secure_filename(j2.filename)
            template_path = save_uploaded_file(j2, template_dir)
        else:
            flash("Jenis file template tidak valid. Diizinkan: j2.", "danger")
            current_app.logger.warning(
                f"User {current_user.email} uploaded an invalid template file type: {j2.filename}"
            )
            return redirect(url_for("template_bp.template_index"))

        # Validasi dan simpan file parameter
        if yaml.filename and allowed_file(yaml.filename, PARAMS_EXTENSIONS):
            parameter_name = secure_filename(yaml.filename)
            parameter_path = save_uploaded_file(yaml, template_dir)
        else:
            flash("Jenis file parameter tidak valid. Diizinkan: yml, yaml.", "danger")
            current_app.logger.warning(
                f"User {current_user.email} uploaded an invalid parameter file type: {yaml.filename}"
            )
            return redirect(url_for("template_bp.template_index"))

        # Periksa duplikasi nama template
        existing_template = TemplateManager.query.filter_by(
            template_name=template_name
        ).first()
        if existing_template:
            flash("Nama template sudah ada!", "danger")
            current_app.logger.warning(
                f"User {current_user.email} attempted to upload a duplicate template: {template_name}."
            )
            return redirect(url_for("template_bp.template_index"))

        # Periksa duplikasi nama parameter
        existing_parameter = TemplateManager.query.filter_by(
            parameter_name=parameter_name
        ).first()
        if existing_parameter:
            flash("Nama parameter sudah ada!", "danger")
            current_app.logger.warning(
                f"User {current_user.email} attempted to upload a duplicate parameter: {parameter_name}."
            )
            return redirect(url_for("template_bp.template_index"))

        # Simpan data template baru ke database
        new_template = TemplateManager(
            template_name=template_name,
            parameter_name=parameter_name,
            vendor=vendor,
            version=version,
            description=description,
            created_by=current_user.email,
        )
        db.session.add(new_template)
        db.session.commit()
        current_app.logger.info(
            f"User {current_user.email} successfully uploaded new template: {template_name}."
        )
        flash("File berhasil diunggah.", "success")

    except Exception as e:
        # Rollback jika terjadi error dan berikan feedback ke pengguna
        db.session.rollback()
        current_app.logger.error(
            f"Error uploading template for user {current_user.email}: {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat mengunggah file. Silakan coba lagi nanti.",
            "danger",
        )

    return redirect(url_for("template_bp.template_index"))


@template_bp.route("/create-template-manual", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def create_template_manual():
    """Meng-handle pembuatan template manual dari input pengguna."""
    form_manual_create = ManualTemplateForm(request.form)

    current_app.logger.info(
        f"Attempting to create a manual template by {current_user.email}"
    )

    if not form_manual_create.validate_on_submit():
        for field, errors in form_manual_create.errors.items():
            for error in errors:
                flash(
                    f"{getattr(form_manual_create, field).label.text}: {error}",
                    "danger",
                )
        current_app.logger.warning(
            f"User {current_user.email} submitted invalid manual template form data."
        )
        return redirect(url_for("template_bp.template_index"))

    try:
        # Extracting form data
        vendor = form_manual_create.vendor.data
        version = form_manual_create.version.data
        description = form_manual_create.description.data
        template_content = (
            form_manual_create.template_content.data.replace("\r\n", "\n")
            .replace("\r", "\n")
            .strip()
        )
        parameter_content = (
            form_manual_create.parameter_content.data.replace("\r\n", "\n")
            .replace("\r", "\n")
            .strip()
        )

        # Generate filenames for saving the content
        gen_filename = generate_random_filename(vendor)
        template_filename = f"{gen_filename}.j2"
        parameter_filename = f"{gen_filename}.yml"

        template_dir = current_app.config["TEMPLATE_DIR"]
        template_path = os.path.join(template_dir, template_filename)
        parameter_path = os.path.join(template_dir, parameter_filename)

        # Save template content to file
        with open(template_path, "w", encoding="utf-8") as template_file:
            template_file.write(template_content)
        current_app.logger.info(
            f"Successfully saved template content to file: {template_path}"
        )

        # Save parameter content to file
        with open(parameter_path, "w", encoding="utf-8") as parameter_file:
            parameter_file.write(parameter_content)
        current_app.logger.info(
            f"Successfully saved parameter content to file: {parameter_path}"
        )

        # Save new template to the database
        new_template = TemplateManager(
            template_name=template_filename,
            parameter_name=parameter_filename,
            vendor=vendor,
            version=version,
            description=description,
            created_by=current_user.email,
        )
        db.session.add(new_template)
        db.session.commit()
        current_app.logger.info(
            f"Successfully added new template to database: {template_filename}"
        )
        flash("Template berhasil dibuat.", "success")

    except Exception as e:
        current_app.logger.error(
            f"Error creating template for user {current_user.email}: {e}"
        )
        flash(
            "Terjadi kesalahan saat membuat template. Silakan coba lagi nanti.",
            "danger",
        )
        db.session.rollback()

    return redirect(url_for("template_bp.template_index"))


@template_bp.route("/update-template/<template_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def update_template(template_id):
    """Handles updating a template based on its ID."""
    template = TemplateManager.query.get_or_404(template_id)
    current_app.logger.info(f"Accessed template update for template_id: {template_id}")

    template_dir = current_app.config["TEMPLATE_DIR"]
    template_content = read_file(os.path.join(template_dir, template.template_name))
    parameter_content = read_file(os.path.join(template_dir, template.parameter_name))

    if template_content is None or parameter_content is None:
        flash("Terjadi kesalahan saat memuat template atau konten parameter.", "error")
        return redirect(url_for("template_bp.template_index"))

    # Create a form instance and pre-fill it with existing template data
    form = TemplateUpdateForm(obj=template)
    if request.method == "GET":
        form.template_content.data = template_content
        form.parameter_content.data = parameter_content

    if form.validate_on_submit():
        try:
            # Secure filenames and retrieve updated data
            new_template_name = secure_filename(form.template_name.data)
            new_parameter_name = secure_filename(form.parameter_name.data)
            new_vendor = form.vendor.data
            new_version = form.version.data
            new_description = form.description.data
            new_template_content = form.template_content.data.replace(
                "\r\n", "\n"
            ).strip()
            new_parameter_content = form.parameter_content.data.replace(
                "\r\n", "\n"
            ).strip()

            # Validate uniqueness of template and parameter names
            if TemplateManager.query.filter(
                TemplateManager.template_name == new_template_name,
                TemplateManager.id != template.id,
            ).first():
                flash(f"Nama template '{new_template_name}' sudah ada.", "danger")
                return redirect(url_for("template_bp.update_template", template_id=template_id))

            if TemplateManager.query.filter(
                TemplateManager.parameter_name == new_parameter_name,
                TemplateManager.id != template.id,
            ).first():
                flash(f"Nama parameter '{new_parameter_name}' sudah ada.", "danger")
                return redirect(url_for("template_bp.update_template", template_id=template_id))

            # Handle file content changes
            template_dir = current_app.config["TEMPLATE_DIR"]
            if new_template_content != template_content:
                template_path = os.path.join(
                    template_dir,
                    template.template_name,
                )
                with open(template_path, "w", encoding="utf-8") as file:
                    file.write(new_template_content)
                current_app.logger.info(
                    f"Template content updated: {template.template_name}"
                )

            if new_parameter_content != parameter_content:
                parameter_path = os.path.join(
                    template_dir,
                    template.parameter_name,
                )
                with open(parameter_path, "w", encoding="utf-8") as file:
                    file.write(new_parameter_content)
                current_app.logger.info(
                    f"Parameter content updated: {template.parameter_name}"
                )

            # Handle filename changes
            if new_template_name != template.template_name:
                new_path_template = os.path.join(template_dir, new_template_name)
                old_path_template = os.path.join(
                    template_dir,
                    template.template_name,
                )
                os.rename(old_path_template, new_path_template)
                template.template_name = new_template_name
                current_app.logger.info(
                    f"Template file renamed from {template.template_name} to {new_template_name}"
                )

            if new_parameter_name != template.parameter_name:
                new_path_parameter = os.path.join(template_dir, new_parameter_name)
                old_path_parameter = os.path.join(
                    template_dir,
                    template.parameter_name,
                )
                os.rename(old_path_parameter, new_path_parameter)
                template.parameter_name = new_parameter_name
                current_app.logger.info(
                    f"Parameter file renamed from {template.parameter_name} to {new_parameter_name}"
                )

            # Update other fields
            template.vendor = new_vendor
            template.version = new_version
            template.description = new_description

            db.session.commit()
            current_app.logger.info(f"Template updated successfully: {template_id}")
            flash("Pembaruan template berhasil.", "success")
            return redirect(url_for("template_bp.template_index"))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating template: {e}")
            flash("Gagal memperbarui template.", "error")
            return redirect(url_for("template_bp.update_template", template_id=template_id))

    return render_template(
        "/template_managers/update_template.html",
        form=form,
        template=template,
        template_content=template_content,
        parameter_content=parameter_content,
    )


@template_bp.route("/delete-template/<template_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def delete_template(template_id):
    """Handles the deletion of a template based on its ID."""
    form = TemplateDeleteForm()
    if form.validate_on_submit():
        template = TemplateManager.query.get_or_404(template_id)

        try:
            # Define paths for the template and parameter files
            template_dir = current_app.config["TEMPLATE_DIR"]
            template_file_path = os.path.join(template_dir, template.template_name)
            parameter_file_path = os.path.join(template_dir, template.parameter_name)

            # Try deleting the template file, log appropriately
            if os.path.exists(template_file_path):
                os.remove(template_file_path)
                current_app.logger.info(
                    f"Template file deleted: {template_file_path} by {current_user.email}"
                )
            else:
                current_app.logger.warning(
                    f"Template file not found for deletion: {template_file_path} by {current_user.email}"
                )

            # Try deleting the parameter file, log appropriately
            if os.path.exists(parameter_file_path):
                os.remove(parameter_file_path)
                current_app.logger.info(
                    f"Parameter file deleted: {parameter_file_path} by {current_user.email}"
                )
            else:
                current_app.logger.warning(
                    f"Parameter file not found for deletion: {parameter_file_path} by {current_user.email}"
                )

            # Delete the template from the database
            db.session.delete(template)
            db.session.commit()
            current_app.logger.info(
                f"Template with ID {template_id} successfully deleted by {current_user.email}"
            )
            flash("Template berhasil dihapus.", "success")

        except OSError as os_error:
            current_app.logger.error(
                f"OS error while deleting files for template ID {template_id}: {os_error} by {current_user.email}"
            )
            flash(
                "Terjadi kesalahan sistem saat menghapus file. Silakan coba lagi.",
                "danger",
            )
            db.session.rollback()

        except Exception as e:
            current_app.logger.error(
                f"Unexpected error while deleting template ID {template_id}: {e} by {current_user.email}"
            )
            flash("Gagal menghapus template. Silakan coba lagi.", "danger")
            db.session.rollback()

        return redirect(url_for("template_bp.template_index"))


# ----------------------------------------------------------------------------------------
# Generator Configuration File from Template and AI Validation
# ----------------------------------------------------------------------------------------
@template_bp.route("/template-generator/<template_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def template_generator(template_id):
    """Handles template generation, rendering, validation, and saving."""

    # Ambil data template dari database
    template = TemplateManager.query.get_or_404(template_id)
    vendor = template.vendor

    template_dir = current_app.config["TEMPLATE_DIR"]
    jinja_template_path = os.path.join(template_dir, template.template_name)
    yaml_params_path = os.path.join(template_dir, template.parameter_name)

    try:
        # Baca isi template dan parameter YAML
        jinja_template = read_file(jinja_template_path)
        yaml_params = read_file(yaml_params_path)

        if jinja_template is None or yaml_params is None:
            flash("Gagal memuat konten template atau parameter.", "error")
            current_app.logger.error(
                f"[ERROR] Failed to load template or parameter for template ID {template_id} by {current_user.email}."
            )
            return jsonify({"error": "Failed to load template or parameter"}), 400

        current_app.logger.info(
            f"[INFO] Successfully loaded Jinja template and YAML parameters for template ID {template_id} by {current_user.email}."
        )

        # Render template dengan parameter YAML
        net_auto = ConfigurationManagerUtils(
            ip_address="0.0.0.0", username="none", password="none", ssh=22
        )
        rendered_config = net_auto.render_template_config(jinja_template, yaml_params)

        current_app.logger.info(
            f"[INFO] Successfully rendered Jinja template for template ID {template_id}."
        )

        # Validasi konfigurasi menggunakan OpenAI API
        current_app.logger.info(
            f"[INFO] Validating rendered template with OpenAI for template ID {template_id}..."
        )

        config_manager = ConfigurationFileManagement()
        config_validated = config_manager.process_validated(
            configuration=rendered_config, device_vendor=vendor
        )

        data = config_validated["is_valid"]

        # Tidak perlu json.loads(), cukup gunakan dictionary yang dikembalikan
        if not data:
            return (
                jsonify(
                    {
                        "is_valid": False,
                        "errors": config_validated["errors"],
                        "suggestions": config_validated["suggestions"],
                    }
                ),
                200,
            )

    except Exception as e:
        current_app.logger.error(
            f"[ERROR] Exception occurred during template rendering/validation for template ID {template_id}: {e}"
        )
        return (
            jsonify({"error": f"Failed to render or validate template: {str(e)}"}),
            500,
        )

    try:
        # Generate nama file unik untuk konfigurasi
        gen_filename = generate_random_filename(template.vendor)
        new_file_name = f"{gen_filename}"
        config_dir = current_app.config["CONFIG_DIR"]
        new_file_path = os.path.join(config_dir, new_file_name)

        # Simpan konfigurasi yang dihasilkan ke file
        with open(new_file_path, "w", encoding="utf-8") as new_file:
            new_file.write(rendered_config)

        current_app.logger.info(
            f"[INFO] Successfully saved rendered config to file: {new_file_path}."
        )

        # Simpan metadata konfigurasi ke database
        new_template_generate = ConfigurationManager(
            config_name=new_file_name,
            description=f"{gen_filename} created by {current_user.email}",
            created_by=current_user.email,
            user_id=current_user.id,
            vendor=vendor,
        )
        db.session.add(new_template_generate)
        db.session.commit()

        current_app.logger.info(
            f"[INFO] Successfully saved generated template to database: {new_file_name}."
        )

        return jsonify(
            {
                "is_valid": True,
                "file_name": new_file_name,
                "file_path": new_file_path,
                "message": "Template successfully generated and validated.",
            }
        )

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"[ERROR] Failed to save rendered config or template for template ID {template_id}: {e}"
        )
        return (
            jsonify({"error": f"Failed to save configuration or template: {str(e)}"}),
            500,
        )


# ----------------------------------------------------------------------------------------
# Configuration File Section
# ----------------------------------------------------------------------------------------
@template_bp.route("/configuration-file")
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def configuration_file_index():
    current_app.logger.info(
        f"User {current_user.email} accessed the Configuration File Manager index"
    )

    # Forms
    formManualConfiguration = ManualConfigurationForm(request.form)
    formAIconfiguration = AIConfigurationForm(request.form)
    formTalita = TalitaQuestionForm()

    search_query = request.args.get("search", "").lower()
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    try:
        query = (
            ConfigurationManager.query.filter_by(user_id=current_user.id)
            if not current_user.has_role("Admin")
            else ConfigurationManager.query
        )

        if search_query:
            query = query.filter(
                ConfigurationManager.config_name.ilike(f"%{search_query}%")
                | ConfigurationManager.vendor.ilike(f"%{search_query}%")
                | ConfigurationManager.description.ilike(f"%{search_query}%")
            )

        total_configuration_file = query.count()
        configurations = query.limit(per_page).offset(offset).all()
        pagination_info = Pagination(
            page=page, per_page=per_page, total=total_configuration_file
        )

        return render_template(
            "template_managers/configuration_file_index.html",
            formManualConfiguration=formManualConfiguration,
            formAIconfiguration=formAIconfiguration,
            formTalita=formTalita,
            page=page,
            per_page=per_page,
            search_query=search_query,
            total_configuration_file=total_configuration_file,
            configurations=configurations,
            pagination=pagination_info,
        )

    except Exception as e:
        current_app.logger.error(
            f"Error accessing Configuration Manager page: {str(e)}"
        )
        return (
            jsonify(
                {
                    "is_valid": False,
                    "error_message": "Failed to access Configuration Management.",
                }
            ),
            500,
        )


@template_bp.route("/configuration-file/get-detail/<config_id>", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def get_detail_configuration(config_id):
    configuration = ConfigurationManager.query.get_or_404(config_id)

    if not check_ownership(configuration, current_user):
        return jsonify({"error": "Unauthorized access to configuration."}), 403

    try:
        config_dir = current_app.config["CONFIG_DIR"]
        configuration_file_path = os.path.join(config_dir, configuration.config_name)
        if not is_safe_path(configuration_file_path, config_dir):
            return jsonify({"error": "Unauthorized access to file path."}), 403

        configuration_content = read_file(configuration_file_path)
        if configuration_content is None:
            return jsonify({"error": "Configuration file not found."}), 404

        return (
            jsonify(
                {
                    "config_name": configuration.config_name,
                    "vendor": configuration.vendor,
                    "description": configuration.description,
                    "created_by": configuration.created_by,
                    "configuration_content": configuration_content,
                }
            ),
            200,
        )

    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "An error occurred. Please try again later."}), 500


@template_bp.route("/configuration-file/update/<config_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def update_configuration(config_id):
    current_app.logger.info(
        f"Attempting to update configuration file with ID {config_id} by {current_user.email}"
    )

    # Query the config
    config = ConfigurationManager.query.get_or_404(config_id)

    # Forms
    form = UpdateConfigurationForm()

    # Ownership check
    if not check_ownership(config, current_user):
        current_app.logger.warning(
            f"Unauthorized update attempt by {current_user.email} on configuration ID {config.id}"
        )
        return jsonify({"error": "Unauthorized access to configuration."}), 403

    # Reading the content from the file
    config_dir = current_app.config["CONFIG_DIR"]
    config_content = read_file(os.path.join(config_dir, config.config_name))
    if config_content is None:
        current_app.logger.error(
            f"Error loading config content for ID {config_id} by {current_user.email}"
        )
        return jsonify({"error": "Error loading config content."}), 500

    # Processing form submission
    if request.method == "POST" and form.validate_on_submit():
        new_config_name = secure_filename(form.config_name.data)
        new_vendor = form.vendor.data
        new_description = form.description.data
        new_config_content = form.config_content.data.strip()
        processed_content = "\n".join(
            line.rstrip() for line in new_config_content.splitlines()
        )

        # If no changes are detected, redirect silently to the index page
        if (
            new_config_name == config.config_name
            and new_vendor == config.vendor
            and new_description == config.description
            and new_config_content == config_content
        ):
            current_app.logger.info(
                f"No changes detected for configuration ID {config_id}"
            )
            return jsonify(
                {"is_valid": True, "redirect_url": url_for("template_bp.configuration_file_index")}
            )

        # Check if the new config name already exists
        if new_config_name != config.config_name:
            existing_config = ConfigurationManager.query.filter_by(
                config_name=new_config_name
            ).first()
            if existing_config:
                current_app.logger.warning(
                    f"File with the new name '{new_config_name}' already exists."
                )
                return (
                    jsonify(
                        {
                            "is_valid": False,
                            "error_message": "File with the new name already exists.",
                        }
                    ),
                    400,
                )

        try:
            # Update file content if changed
            config_dir = current_app.config["CONFIG_DIR"]
            if new_config_content != config_content:
                config_path = os.path.join(config_dir, config.config_name)
                with open(config_path, "w", encoding="utf-8") as file:
                    file.write(processed_content)
                current_app.logger.info(
                    f"Successfully updated config content by user {current_user.email}"
                )

            # Rename the file if necessary
            if new_config_name != config.config_name:
                old_path = os.path.join(config_dir, config.config_name)
                new_path = os.path.join(config_dir, new_config_name)

                os.makedirs(os.path.dirname(new_path), exist_ok=True)
                os.rename(old_path, new_path)
                config.config_name = new_config_name
                current_app.logger.info(
                    f"Successfully renamed file by user {current_user.email}"
                )

            # Update database fields
            config.vendor = new_vendor
            config.description = new_description
            db.session.commit()
            current_app.logger.info(
                f"Successfully updated config data in database for ID {config_id}"
            )

            flash("Update file konfigurasi berhasil!", "success")
            return jsonify(
                {"is_valid": True, "redirect_url": url_for("template_bp.configuration_file_index")}
            )

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating configuration: {e}")
            return (
                jsonify(
                    {
                        "is_valid": False,
                        "error_message": "Failed to update configuration.",
                    }
                ),
                500,
            )

    # If GET request, pre-populate the form with current values
    elif request.method == "GET":
        form.config_name.data = config.config_name
        form.vendor.data = config.vendor
        form.description.data = config.description
        form.config_content.data = config_content

    # Handle form validation errors
    elif request.method == "POST" and not form.validate_on_submit():
        errors = {field: error for field, error in form.errors.items()}
        current_app.logger.warning(f"Form validation failed: {errors}")
        return jsonify({"is_valid": False, "errors": errors}), 400

    return render_template(
        "template_managers/update_configuration_file.html", config=config, form=form
    )


@template_bp.route("/configuration-file/delete/<config_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def delete_configuration(config_id):
    config = ConfigurationManager.query.get_or_404(config_id)

    if not check_ownership(config, current_user):
        return jsonify({"error": "Unauthorized access to configuration."}), 403

    try:
        config_dir = current_app.config["CONFIG_DIR"]
        file_path = os.path.join(config_dir, config.config_name)
        success, message = delete_file_safely(file_path)
        if not success:
            return jsonify({"error": message}), 400

        db.session.delete(config)
        db.session.commit()

        flash("Delete file konfigurasi berhasil!", "success")
        jsonify({"success": True, "redirect_url": url_for("template_bp.configuration_file_index")})
        return redirect(url_for("template_bp.configuration_file_index"))

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting configuration: {e}")
        return (
            jsonify({"error": "Failed to delete configuration due to an error."}),
            500,
        )
