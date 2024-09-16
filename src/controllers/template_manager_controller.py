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
from src import db
from src.models.app_models import TemplateManager, ConfigurationManager
from src.utils.config_manager_utils import ConfigurationManagerUtils
from src.utils.openai_utils import (
    validate_generated_template_with_openai,
    create_configuration_with_openai,
)
from src.utils.talita_ai_utils import talita_chat_completion
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
    ManualConfigurationForm,
    AIConfigurationForm,
    UpdateConfigurationForm,
    TalitaQuestionForm,
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


@tm_bp.before_request
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


# --------------------------------------------------------------------------------
# Bagian File konfigurasi (hasil dari generate template yang telah di validasi AI)
# --------------------------------------------------------------------------------


@tm_bp.route("/templates-management/configuration-file")
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Templates", "View Templates"],
    page="Configuration File Management",
)
def index_configuration_file():
    """
    Display the main page of the Configuration File Manager.
    This page includes a list of configuration file and supports pagination and searching.
    """
    # Logging untuk akses ke endpoint
    current_app.logger.info(f"{current_user.email} accessed index_configuration_file")

    formManualConfiguration = ManualConfigurationForm(request.form)
    formAIconfiguration = AIConfigurationForm(request.form)
    formTalita = TalitaQuestionForm()

    search_query = request.args.get("search", "").lower()
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )
    if page < 1 or per_page < 1:
        raise ValueError("Page and per_page must be positive integers.")

    try:
        if current_user.has_role("Admin"):
            if search_query:
                query = ConfigurationManager.query.filter(
                    ConfigurationManager.user_id == current_user.id,
                    ConfigurationManager.config_name.ilike(f"%{search_query}%")
                    | ConfigurationManager.vendor.ilike(f"%{search_query}%")
                    | ConfigurationManager.description.ilike(f"%{search_query}%"),
                )
            else:
                query = ConfigurationManager.query
        else:
            if search_query:
                query = ConfigurationManager.query.filter(
                    ConfigurationManager.user_id == current_user.id,
                    (
                        ConfigurationManager.config_name.ilike(f"%{search_query}%")
                        | ConfigurationManager.vendor.ilike(f"%{search_query}%")
                        | ConfigurationManager.description.ilike(f"%{search_query}%"),
                    ),
                )
            else:
                query = ConfigurationManager.query.filter_by(user_id=current_user.id)

        total_configuration_file = query.count()
        configurations = query.limit(per_page).offset(offset).all()
        pagination = Pagination(
            page=page, per_page=per_page, total=total_configuration_file
        )

        # Logging jika tidak ada hasil pencarian
        if total_configuration_file == 0:
            current_app.logger.info(
                f"No configuration file found for user {current_user.email} with query '{search_query}'"
            )
            flash("No configuration found matching your search criteria.", "info")

        return render_template(
            "/template_managers/index_configuration_file.html",
            formManualConfiguration=formManualConfiguration,
            formAIconfiguration=formAIconfiguration,
            formTalita=formTalita,
            page=page,
            per_page=per_page,
            search_query=search_query,
            total_configuration_file=total_configuration_file,
            configurations=configurations,
            pagination=pagination,
        )
    except Exception as e:
        # Handle exceptions and log the error
        current_app.logger.error(
            f"Error accessing configuration Manager page by user {current_user.email}: {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat mengakses configuration Managament, silahkan coba lagi nanti.",
            "danger",
        )
        return redirect(
            url_for("users.dashboard")
        )  # Redirect to a safe page like dashboard


@tm_bp.route("/configuration_detail/<config_id>", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Templates", "View Templates"],
    page="Templates Management",
)
def configuration_detail(config_id):
    configuration = ConfigurationManager.query.get_or_404(config_id)
    try:
        # Ensure paths are safe
        configuration_file_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, configuration.config_name
        )

        # Reading configuration files
        if not os.path.isfile(configuration_file_path):
            return (
                jsonify({"error": "Configuration file tidak ditemukan."}),
                404,
            )

        configuration_content = read_file(configuration_file_path)

        if configuration_content is None:
            current_app.logger.error(
                f"Error reading files for configuration ID {config_id} by {current_user.email}"
            )
            return (
                jsonify(
                    {"error": "Terjadi kesalahan saat membaca konten konfigurasi."}
                ),
                500,
            )

        current_app.logger.info(
            f"User {current_user.email} accessed details for configuration ID {config_id}"
        )
        return jsonify(
            {
                "config_name": configuration.config_name,
                "vendor": configuration.vendor,
                "description": configuration.description,
                "created_by": configuration.created_by,
                "configuration_content": configuration_content,
            }
        )

    except Exception as e:
        current_app.logger.error(
            f"Unexpected error in configuration_detail for configuration ID {config_id} by {current_user.email}: {str(e)}"
        )
        return (
            jsonify(
                {
                    "error": "Terjadi kesalahan yang tidak terduga. Silakan coba lagi nanti."
                }
            ),
            500,
        )


@tm_bp.route("/templates-management/create-manual-configuration", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Configuration File Management",
)
def create_manual_configuration():
    """Membuat file konfigurasi manual dan menyimpannya ke dalam database."""
    formManualConfiguration = ManualConfigurationForm()

    if formManualConfiguration.validate_on_submit():
        filename = secure_filename(formManualConfiguration.filename.data)
        vendor = formManualConfiguration.vendor.data
        configuration_description = (
            formManualConfiguration.configuration_description.data
        )
        configuration_content = (
            formManualConfiguration.configuration_content.data.replace("\r\n", "\n")
            .replace("\r", "\n")
            .strip()
        )

        current_app.logger.info(
            f"Attempting to create a manual configuration file by {current_user.email}"
        )

        if not filename or not vendor:
            flash("Filename and vendor cannot be empty!", "info")
            current_app.logger.warning("Filename is empty.")
            return redirect(url_for("tm.index_configuration_file"))

        gen_filename = generate_random_filename(vendor)

        configuration_name = f"{gen_filename}"
        file_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, configuration_name
        )

        try:
            # Validasi konfigurasi dengan OpenAI API (pastikan fungsi ini aman dan memadai)
            config_validated = validate_generated_template_with_openai(
                config=configuration_content, vendor=vendor
            )

            if config_validated.get("is_valid"):
                # Menulis file konfigurasi ke disk dan menyimpan ke database
                with open(file_path, "w", encoding="utf-8") as configuration_file:
                    configuration_file.write(configuration_content)

                new_configuration = ConfigurationManager(
                    config_name=configuration_name,
                    vendor=vendor,
                    description=configuration_description,
                    created_by=current_user.email,
                    user_id=current_user.id,
                )
                db.session.add(new_configuration)
                db.session.commit()

                flash("Berhasil membuat configuration file.", "success")
                return jsonify(
                    {"is_valid": True}
                )  # Respond with JSON indicating success
            else:
                error_message = config_validated.get("error_message")
                return jsonify({"is_valid": False, "error_message": error_message})

        except Exception as e:
            # Rolling back session jika terjadi kesalahan
            db.session.rollback()
            current_app.logger.error(f"Error creating configuration file: {e}")
            flash("Failed to create configuration file.", "error")
            return redirect(url_for("tm.index_configuration_file"))

    else:
        for field, errors in formManualConfiguration.errors.items():
            for error in errors:
                flash(
                    f"Error in the {getattr(formManualConfiguration, field).label.text} field - {error}",
                    "danger",
                )
        return redirect(url_for("tm.index_configuration_file"))


@tm_bp.route("/templates-management/create-configuration-with-ai", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Configuration File Management",
)
def create_configuration_with_ai():
    """Membuat file konfigurasi dengan bantuan AI dan menyimpannya ke dalam database."""

    formAIconfiguration = AIConfigurationForm()

    if formAIconfiguration.validate_on_submit():
        filename = secure_filename(formAIconfiguration.filename.data)
        vendor = formAIconfiguration.vendor.data
        description = formAIconfiguration.description.data
        ask_configuration = formAIconfiguration.ask_configuration.data

        current_app.logger.info(
            f"Attempting to create an AI-generated configuration file by {current_user.email}"
        )

        gen_filename = generate_random_filename(vendor)

        configuration_name = f"{gen_filename}"
        file_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, configuration_name
        )

        try:
            # Menghasilkan konfigurasi dengan OpenAI API
            configuration_content, error = create_configuration_with_openai(
                question=ask_configuration, vendor=vendor
            )

            if error:
                # Return the error message in JSON format
                current_app.logger.error(f"AI configuration error: {error}")
                return jsonify({"is_valid": False, "error_message": error}), 400

            # Menulis file konfigurasi ke disk dan menyimpan ke database
            with open(file_path, "w", encoding="utf-8") as configuration_file:
                configuration_file.write(configuration_content)

            new_configuration = ConfigurationManager(
                config_name=configuration_name,
                vendor=vendor,
                description=description,
                created_by=current_user.email,
                user_id=current_user.id,
            )
            db.session.add(new_configuration)
            db.session.commit()

            flash(
                "Configuration created successfully with AI, please verify the configuration.",
                "info",
            )
            return jsonify({"is_valid": True})  # Respond with JSON indicating success

        except Exception as e:
            # Rolling back session jika terjadi kesalahan
            db.session.rollback()
            current_app.logger.error(f"Error creating configuration file: {e}")
            flash("Failed to create configuration file.", "error")
            return redirect(url_for("tm.index_configuration_file"))
    else:
        for field, errors in formAIconfiguration.errors.items():
            for error in errors:
                flash(
                    f"Error in the {getattr(formAIconfiguration, field).label.text} field - {error}",
                    "danger",
                )
        return redirect(url_for("tm.index_configuration_file"))


@tm_bp.route(
    "/templates-management/update-configuration/<template_result_id>",
    methods=["GET", "POST"],
)
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Configuration File Management",
)
def update_configuration(template_result_id):
    """Meng-handle pembaruan file konfigurasi template yang ada."""
    current_app.logger.info(
        f"Attempting to update configuration file with ID {template_result_id} by {current_user.email}"
    )

    template = ConfigurationManager.query.get_or_404(template_result_id)

    # Verifikasi kepemilikan file konfigurasi
    if template.user_id != current_user.id and not current_user.has_role("Admin"):
        flash("You do not have permission to update this configuration file.", "danger")
        current_app.logger.warning(
            f"Unauthorized update attempt by user {current_user.email} on configuration ID {template.id}"
        )
        return redirect(url_for("tm.index_configuration_file"))

    template_content = read_file(
        os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, template.config_name
        )
    )

    if template_content is None:
        flash("Error loading template content.", "error")
        current_app.logger.error(
            f"Error loading template content for ID {template_result_id} by {current_user.email}"
        )
        return redirect(url_for("tm.index_configuration_file"))

    form = UpdateConfigurationForm()

    if request.method == "POST" and form.validate_on_submit():
        new_template_name = secure_filename(form.template_name.data)
        new_vendor = form.vendor.data
        new_description = form.description.data
        new_template_content = (
            form.template_content.data.replace("\r\n", "\n").replace("\r", "\n").strip()
        )

        # Validasi jika tidak ada perubahan
        if (
            new_template_name == template.config_name
            and new_vendor == template.vendor
            and new_description == template.description
            and new_template_content == template_content
        ):
            return redirect(url_for("tm.index_configuration_file"))

        # Validasi jika `config_name` sudah ada
        if new_template_name != template.config_name:
            existing_template = ConfigurationManager.query.filter_by(
                config_name=new_template_name
            ).first()
            if existing_template:
                flash("File with the new name already exists.", "error")
                current_app.logger.warning(
                    f"File with the new name '{new_template_name}' already exists, requested by user {current_user.email}"
                )
                return redirect(request.url)

        try:
            # Update content file jika ada perubahan
            if new_template_content != template_content:
                template_path = os.path.join(
                    current_app.static_folder, GEN_TEMPLATE_FOLDER, template.config_name
                )
                with open(template_path, "w", encoding="utf-8") as file:
                    file.write(new_template_content)
                current_app.logger.info(
                    f"Successfully updated template content in file: {template_path} by user {current_user.email}"
                )

            # Update nama file jika ada perubahan dan nama baru tidak ada konflik
            if new_template_name != template.config_name:
                new_path_template = os.path.join(
                    current_app.static_folder, GEN_TEMPLATE_FOLDER, new_template_name
                )
                old_path_template = os.path.join(
                    current_app.static_folder,
                    GEN_TEMPLATE_FOLDER,
                    template.config_name,
                )
                os.rename(old_path_template, new_path_template)
                template.config_name = new_template_name
                current_app.logger.info(
                    f"Successfully renamed file from {old_path_template} to {new_path_template} by user {current_user.email}"
                )

            template.vendor = new_vendor
            template.description = new_description
            db.session.commit()
            current_app.logger.info(
                f"Successfully updated template data in database: ID {template_result_id} by user {current_user.email}"
            )
            flash("Template update successful.", "success")
            return redirect(url_for("tm.index_configuration_file"))

        except Exception as e:
            db.session.rollback()  # Ensure rollback on error
            current_app.logger.error(
                f"Error updating template: {e} by user {current_user.email}"
            )
            flash("Failed to update template.", "error")
            return redirect(request.url)

    elif request.method == "GET":
        # Isi form dengan data dari database dan file pada saat permintaan GET
        form.template_name.data = template.config_name
        form.vendor.data = template.vendor
        form.description.data = template.description
        form.template_content.data = template_content

    elif request.method == "POST":
        for field, errors in form.errors.items():
            for error in errors:
                flash(
                    f"Error in the {getattr(form, field).label.text} field - {error}",
                    "danger",
                )
                current_app.logger.warning(f"Validation error on {field}: {error}")

    return render_template(
        "/template_managers/update_configuration_file.html",
        template=template,
        form=form,
    )


@tm_bp.route(
    "/templates-management/delete-configuration/<template_id>", methods=["POST"]
)
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Configuration File Management",
)
def delete_configuration(template_id):
    template = ConfigurationManager.query.get_or_404(template_id)

    # Logika pengecekan: apakah user adalah admin atau pemilik konfigurasi
    if current_user.has_role("Admin") or template.user_id == current_user.id:
        try:
            file_path = os.path.join(
                current_app.static_folder,
                GEN_TEMPLATE_FOLDER,
                str(template.config_name),
            )
            if os.path.exists(file_path):
                os.remove(file_path)
                current_app.logger.info(
                    f"Deleted configuration file: {file_path} by user {current_user.email}"
                )
            else:
                current_app.logger.warning(
                    f"Configuration file not found: {file_path} requested by user {current_user.email}"
                )

            db.session.delete(template)
            db.session.commit()
            current_app.logger.info(
                f"Configuration file successfully deleted: ID {template.id} by user {current_user.email}"
            )
            flash("Configuration file successfully deleted.", "success")

        except Exception as e:
            db.session.rollback()  # Rolling back session jika terjadi kesalahan
            current_app.logger.error(
                f"Error deleting configuration file: {e} by user {current_user.email}"
            )
            flash("Failed to delete configuration file.", "error")
    else:
        flash("You do not have permission to delete this configuration file.", "danger")
        current_app.logger.warning(
            f"Unauthorized delete attempt by user {current_user.email} on configuration ID {template.id}"
        )

    return redirect(url_for("tm.index_configuration_file"))


# --------------------------------------------------------------------------------
# Talita Lintasarta Section
# --------------------------------------------------------------------------------


@tm_bp.route("/ask_talita", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Configuration File Management",
)
def ask_talita():
    formTalita = TalitaQuestionForm()

    current_app.logger.warning(
        f"Attempting Talita AI Endpoint for user {current_user.email} (ID: {current_user.id})"
    )

    if formTalita.validate_on_submit():
        config_name = formTalita.config_name.data
        vendor = formTalita.vendor.data
        description = formTalita.description.data
        question = formTalita.question.data

        context = (
            f"Berikan hanya sintaks konfigurasi yang tepat untuk {vendor}.\n"
            "Keluaran harus berupa teks polos dan tidak mengandung deskripsi atau placeholder.\n"
            f"Hanya sertakan perintah konfigurasi yang spesifik tanpa pemformatan tambahan dan tanpa penjelasan tambahan untuk {vendor} vendor."
            f"Jika permintaan tidak dapat di aplikasikan atau jika sintaks tidak valid untuk vendor {vendor}, Anda harus merespons dengan kata 'Gagal' persis pada baris pertama. Lalu lanjutkan penjelasan rinci tentang kesalahan tersebut.\n"
            "Kata pertama dari respons Anda harus selalu 'Gagal' jika permintaan tidak dapat dipenuhi persis seperti yang ditentukan. Jangan memberikan konten atau penjelasan lain sebelum 'Gagal'. Berikut adalah permintaannya:\n"
            f"{question}\n"
        )

        user_id = str(current_user.id)  # Using the actual current_user ID

        current_app.logger.info(
            f"User {current_user.email} (ID: {current_user.id}) is asking TALITA a question."
        )

        try:
            response = talita_chat_completion(context, user_id)

            if response is None:
                current_app.logger.warning(
                    f"Failed to connect to Talita AI for user {current_user.email} (ID: {current_user.id})"
                )
                return (
                    jsonify(
                        {
                            "is_valid": False,
                            "error_message": "Tidak dapat terhubung dengan TALITA. Silakan coba lagi nanti.",
                        }
                    ),
                    400,
                )
            elif response.startswith("Gagal"):
                return (
                    jsonify(
                        {
                            "is_valid": False,
                            "error_message": response,
                        }
                    ),
                    400,
                )
            elif not response.startswith("Gagal"):
                gen_filename = generate_random_filename(config_name)
                filename = f"{gen_filename}"
                file_path = os.path.join(
                    current_app.static_folder, GEN_TEMPLATE_FOLDER, filename
                )

                with open(file_path, "w") as file:
                    file.write(response)

                new_configuration = ConfigurationManager(
                    config_name=filename,
                    vendor=vendor,
                    description=description,
                    created_by=current_user.email,
                    user_id=current_user.id,
                )
                db.session.add(new_configuration)
                db.session.commit()

                current_app.logger.info(
                    f"User {current_user.email} (ID: {current_user.id}) successfully saved response from TALITA to file {filename}."
                )

                return jsonify({"is_valid": True}), 200
            else:
                current_app.logger.error(
                    f"Failed to get a valid response from TALITA for user {current_user.email} (ID: {current_user.id}): {response}"
                )
                return (
                    jsonify(
                        {
                            "is_valid": False,
                            "error_message": f"Gagal mendapatkan jawaban dari TALITA: {response}",
                        }
                    ),
                    400,
                )
        except Exception as e:
            current_app.logger.error(
                f"An error occurred while processing TALITA request for user {current_user.email} (ID: {current_user.id}): {str(e)}"
            )
            return (
                jsonify(
                    {
                        "is_valid": False,
                        "error_message": "Terjadi kesalahan saat memproses permintaan Anda. Silakan coba lagi.",
                    }
                ),
                500,
            )

    return (
        jsonify(
            {
                "is_valid": False,
                "error_message": "Form is not valid. Please check the inputs.",
            }
        ),
        400,
    )
