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
from src.utils.openai_utils import (
    validate_generated_template_with_openai,
)
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
)

# Blueprint untuk template manager
tm_bp = Blueprint("tm", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging untuk aplikasi
logging.basicConfig(level=logging.INFO)


@tm_bp.before_app_request
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
@tm_bp.before_request
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


@tm_bp.context_processor
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
# Bagian Template Management
# --------------------------------------------------------------------------------


def allowed_file(filename, allowed_extensions):
    """Memeriksa apakah ekstensi file termasuk dalam ekstensi yang diperbolehkan."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def save_uploaded_file(file, upload_folder):
    filename = secure_filename(file.filename)
    file_path = os.path.join(current_app.static_folder, upload_folder, filename)
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


RAW_TEMPLATE_FOLDER = "xmanager/templates"
GEN_TEMPLATE_FOLDER = "xmanager/configurations"
TEMPLATE_EXTENSIONS = {"j2"}
PARAMS_EXTENSIONS = {"yml", "yaml"}


@tm_bp.route("/templates-management", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Templates", "View Templates"],
    page="Templates Management",
)
def index():
    """
    Display the main page of the Templates File Manager.
    This page includes a list of Templates file and supports pagination and searching.
    """
    # Logging untuk akses ke endpoint
    current_app.logger.info(f"{current_user.email} accessed index template management")

    form = TemplateForm(request.form)
    form_manual_create = ManualTemplateForm(request.form)

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
            "/template_managers/index.html",
            form=form,
            form_manual_create=form_manual_create,
            page=page,
            per_page=per_page,
            search_query=search_query,
            total_templates=total_templates,
            templates=templates,
            pagination=pagination,
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


@tm_bp.route("/template_detail/<template_id>", methods=["GET"])
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
        template_file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
        )
        parameter_file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
        )

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


@tm_bp.route("/upload-template", methods=["POST"])
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
        form = TemplateForm(request.form)

        # Validate input vendor and version using WTForms
        if not form.validate():
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{getattr(form, field).label.text}: {error}", "danger")
            current_app.logger.warning(
                f"User {current_user.email} submitted invalid template form data."
            )
            return redirect(url_for("tm.index"))

        # Retrieve files and data from the form
        j2 = request.files.get("j2")
        yaml = request.files.get("yaml")
        vendor = form.vendor.data
        version = form.version.data
        description = form.description.data

        # Check if both files are provided and not empty
        if not j2 or j2.filename == "":
            flash("File template tidak ada.", "error")
            current_app.logger.warning(
                f"User {current_user.email} attempted to upload without providing a template file."
            )
            return redirect(url_for("tm.index"))

        if not yaml or yaml.filename == "":
            flash("File parameter tidak ada.", "error")
            current_app.logger.warning(
                f"User {current_user.email} attempted to upload without providing a parameter file."
            )
            return redirect(url_for("tm.index"))

        # Validate and save template file
        if j2.filename and allowed_file(j2.filename, TEMPLATE_EXTENSIONS):
            template_name = secure_filename(j2.filename)
            template_path = save_uploaded_file(j2, RAW_TEMPLATE_FOLDER)
        else:
            flash("Jenis file template tidak valid. Diizinkan: j2.", "error")
            current_app.logger.warning(
                f"User {current_user.email} uploaded an invalid template file type: {j2.filename}"
            )
            return redirect(url_for("tm.index"))

        # Validate and save parameter file
        if yaml.filename and allowed_file(yaml.filename, PARAMS_EXTENSIONS):
            parameter_name = secure_filename(yaml.filename)
            parameter_path = save_uploaded_file(yaml, RAW_TEMPLATE_FOLDER)
        else:
            flash("Jenis file parameter tidak valid. Diizinkan: yml, yaml.", "error")
            current_app.logger.warning(
                f"User {current_user.email} uploaded an invalid parameter file type: {yaml.filename}"
            )
            return redirect(url_for("tm.index"))

        # Check for duplicate template name
        existing_template = TemplateManager.query.filter_by(
            template_name=template_name
        ).first()
        if existing_template:
            flash(f"Nama template sudah ada!", "danger")
            current_app.logger.warning(
                f"User {current_user.email} attempted to upload a duplicate template: {template_name}."
            )
            return redirect(url_for("tm.index"))

        # Check for duplicate parameter name
        existing_parameter = TemplateManager.query.filter_by(
            parameter_name=parameter_name
        ).first()
        if existing_parameter:
            flash(f"Nama template sudah ada!", "danger")
            current_app.logger.warning(
                f"User {current_user.email} attempted to upload a duplicate parameter: {parameter_name}."
            )
            return redirect(url_for("tm.index"))

        # Create and save new template data to the database
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
        # Log the error and provide error feedback to the user
        db.session.rollback()  # Ensure any changes are rolled back if an error occurs
        current_app.logger.error(
            f"Error uploading template for user {current_user.email}: {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat mengunggah file. Silakan coba lagi nanti.",
            "danger",
        )

    return redirect(url_for("tm.index"))


@tm_bp.route("/create-template-manual", methods=["POST"])
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
        return redirect(url_for("tm.index"))

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

        template_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template_filename
        )
        parameter_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, parameter_filename
        )

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

    return redirect(url_for("tm.index"))


@tm_bp.route("/update-template/<template_id>", methods=["GET", "POST"])
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

    template_content = read_file(
        os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
        )
    )
    parameter_content = read_file(
        os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
        )
    )

    if template_content is None or parameter_content is None:
        flash("Terjadi kesalahan saat memuat template atau konten parameter.", "error")
        return redirect(url_for("tm.index"))

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
                return redirect(url_for("tm.update_template", template_id=template_id))

            if TemplateManager.query.filter(
                TemplateManager.parameter_name == new_parameter_name,
                TemplateManager.id != template.id,
            ).first():
                flash(f"Nama parameter '{new_parameter_name}' sudah ada.", "danger")
                return redirect(url_for("tm.update_template", template_id=template_id))

            # Handle file content changes
            if new_template_content != template_content:
                template_path = os.path.join(
                    current_app.static_folder,
                    RAW_TEMPLATE_FOLDER,
                    template.template_name,
                )
                with open(template_path, "w", encoding="utf-8") as file:
                    file.write(new_template_content)
                current_app.logger.info(
                    f"Template content updated: {template.template_name}"
                )

            if new_parameter_content != parameter_content:
                parameter_path = os.path.join(
                    current_app.static_folder,
                    RAW_TEMPLATE_FOLDER,
                    template.parameter_name,
                )
                with open(parameter_path, "w", encoding="utf-8") as file:
                    file.write(new_parameter_content)
                current_app.logger.info(
                    f"Parameter content updated: {template.parameter_name}"
                )

            # Handle filename changes
            if new_template_name != template.template_name:
                new_path_template = os.path.join(
                    current_app.static_folder, RAW_TEMPLATE_FOLDER, new_template_name
                )
                old_path_template = os.path.join(
                    current_app.static_folder,
                    RAW_TEMPLATE_FOLDER,
                    template.template_name,
                )
                os.rename(old_path_template, new_path_template)
                template.template_name = new_template_name
                current_app.logger.info(
                    f"Template file renamed from {template.template_name} to {new_template_name}"
                )

            if new_parameter_name != template.parameter_name:
                new_path_parameter = os.path.join(
                    current_app.static_folder, RAW_TEMPLATE_FOLDER, new_parameter_name
                )
                old_path_parameter = os.path.join(
                    current_app.static_folder,
                    RAW_TEMPLATE_FOLDER,
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
            return redirect(url_for("tm.index"))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating template: {e}")
            flash("Gagal memperbarui template.", "error")
            return redirect(url_for("tm.update_template", template_id=template_id))

    return render_template(
        "/template_managers/update_template.html",
        form=form,
        template=template,
        template_content=template_content,
        parameter_content=parameter_content,
    )


@tm_bp.route("/delete-template/<template_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def delete_template(template_id):
    """Handles the deletion of a template based on its ID."""
    template = TemplateManager.query.get_or_404(template_id)

    try:
        # Define paths for the template and parameter files
        template_file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
        )
        parameter_file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
        )

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
            "Terjadi kesalahan sistem saat menghapus file. Silakan coba lagi.", "danger"
        )
        db.session.rollback()

    except Exception as e:
        current_app.logger.error(
            f"Unexpected error while deleting template ID {template_id}: {e} by {current_user.email}"
        )
        flash("Gagal menghapus template. Silakan coba lagi.", "danger")
        db.session.rollback()

    return redirect(url_for("tm.index"))


@tm_bp.route("/template-generator/<template_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def template_generator(template_id):
    """Handles template generation, rendering, and saving."""
    template = TemplateManager.query.get_or_404(template_id)
    vendor = template.vendor

    jinja_template_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
    )
    yaml_params_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
    )

    try:
        jinja_template = read_file(jinja_template_path)
        yaml_params = read_file(yaml_params_path)

        if jinja_template is None or yaml_params is None:
            flash("Gagal memuat konten template atau parameter.", "error")
            current_app.logger.error(
                f"Failed to load template or parameter content for template ID {template_id} by {current_user.email}."
            )
            return redirect(url_for("tm.index"))

        current_app.logger.info(
            f"Successfully read Jinja template and YAML parameters for template ID {template_id} by {current_user.email}."
        )

        net_auto = ConfigurationManagerUtils(
            ip_address="0.0.0.0", username="none", password="none", ssh=22
        )
        rendered_config = net_auto.render_template_config(jinja_template, yaml_params)
        current_app.logger.info(
            f"Successfully rendered Jinja template for template ID {template_id} by {current_user.email}."
        )

        current_app.logger.info(
            f"Validating rendered template with OpenAI for template ID {template_id} by {current_user.email}..."
        )
        config_validated = validate_generated_template_with_openai(
            config=rendered_config, vendor=vendor
        )

        if not config_validated.get("is_valid"):
            error_message = config_validated.get("error_message")
            current_app.logger.error(
                f"Template validation failed for template ID {template_id} by {current_user.email}"
            )
            return jsonify({"is_valid": False, "error_message": error_message})

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error rendering or validating template ID {template_id} by {current_user.email}: {e}"
        )
        flash("Gagal merender atau memvalidasi template. Silakan coba lagi.", "error")
        return jsonify(
            {
                "is_valid": False,
                "error_message": f"Gagal merender atau memvalidasi template: {e}",
            }
        )

    try:
        gen_filename = generate_random_filename(template.vendor)
        newFileName = f"{gen_filename}"
        new_file_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, newFileName
        )

        with open(new_file_path, "w", encoding="utf-8") as new_file:
            new_file.write(rendered_config)
        current_app.logger.info(
            f"Successfully saved rendered config to file: {new_file_path} for template ID {template_id} by {current_user.email}."
        )

        new_template_generate = ConfigurationManager(
            config_name=newFileName,
            description=f"{gen_filename} created by {current_user.email}",
            created_by=current_user.email,
            user_id=current_user.id,
            vendor=vendor,
        )
        db.session.add(new_template_generate)
        db.session.commit()
        current_app.logger.info(
            f"Successfully saved generated template to database: {newFileName} for template ID {template_id} by {current_user.email}."
        )
        flash("Template berhasil digenerate.", "success")
        return jsonify({"is_valid": True})

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error saving rendered config or template to database for template ID {template_id} by {current_user.email}: {e}"
        )
        flash(
            "Gagal menyimpan konfigurasi atau template ke database. Silakan coba lagi.",
            "error",
        )

    return redirect(url_for("tm.index"))
