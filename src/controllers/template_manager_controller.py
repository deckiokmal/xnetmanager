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
from flask_paginate import Pagination
import logging
from src.utils.forms_utils import TemplateForm

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
    date_str = datetime.now().strftime("%d.%m.%Y_%H.%M.%S")
    filename = f"{vendor_name}_{random_str}_{date_str}"
    current_app.logger.info(f"Generated random filename: {filename}")
    return filename


RAW_TEMPLATE_FOLDER = "xmanager/raw_templates"
GEN_TEMPLATE_FOLDER = "xmanager/gen_templates"
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
    form = TemplateForm(request.form)
    try:
        # Retrieve pagination and search parameters from request
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 10, type=int)
        search_query = request.args.get("search", "")

        # Log user access to the template management page
        current_app.logger.info(
            f"User {current_user.email} accessed Template Manager page."
        )

        # Build the query for fetching templates
        query = TemplateManager.query
        if search_query:
            query = query.filter(
                TemplateManager.template_name.ilike(f"%{search_query}%")
                | TemplateManager.parameter_name.ilike(f"%{search_query}%")
                | TemplateManager.vendor.ilike(f"%{search_query}%")
                | TemplateManager.version.ilike(f"%{search_query}%")
            )
            current_app.logger.info(
                f"User {current_user.email} searched for '{search_query}' in Template Manager."
            )

        # Paginate the query results
        try:
            all_templates = query.paginate(page=page, per_page=per_page)
        except ValueError as ve:
            current_app.logger.error(
                f"Pagination error in Template Manager page for user {current_user.email}: {str(ve)}"
            )
            flash("Invalid page number. Please try again.", "danger")
            return redirect(url_for("tm.index", page=1, per_page=10))

    except Exception as e:
        # Handle any unexpected errors that occur during the query or pagination
        current_app.logger.error(f"Error accessing Template Manager page: {str(e)}")
        flash(
            "An error occurred while accessing the templates. Please try again later.",
            "danger",
        )
        all_templates = []  # Set an empty list to avoid breaking the template

    # Render the template management page with the retrieved templates
    return render_template(
        "/template_managers/index.html",
        per_page=per_page,
        search_query=search_query,
        all_templates=all_templates,
        form=form,
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
            flash("Template file is missing.", "error")
            current_app.logger.warning(
                f"User {current_user.email} attempted to upload without providing a template file."
            )
            return redirect(url_for("tm.index"))

        if not yaml or yaml.filename == "":
            flash("Parameter file is missing.", "error")
            current_app.logger.warning(
                f"User {current_user.email} attempted to upload without providing a parameter file."
            )
            return redirect(url_for("tm.index"))

        # Validate and save template file
        if j2.filename and allowed_file(j2.filename, TEMPLATE_EXTENSIONS):
            template_name = secure_filename(j2.filename)
            template_path = save_uploaded_file(j2, RAW_TEMPLATE_FOLDER)
        else:
            flash("Invalid template file type. Allowed: j2.", "error")
            current_app.logger.warning(
                f"User {current_user.email} uploaded an invalid template file type: {j2.filename}"
            )
            return redirect(url_for("tm.index"))

        # Validate and save parameter file
        if yaml.filename and allowed_file(yaml.filename, PARAMS_EXTENSIONS):
            parameter_name = secure_filename(yaml.filename)
            parameter_path = save_uploaded_file(yaml, RAW_TEMPLATE_FOLDER)
        else:
            flash("Invalid parameter file type. Allowed: yml, yaml.", "error")
            current_app.logger.warning(
                f"User {current_user.email} uploaded an invalid parameter file type: {yaml.filename}"
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
        flash("File successfully uploaded.", "success")

    except Exception as e:
        # Log the error and provide error feedback to the user
        current_app.logger.error(
            f"Error uploading template for user {current_user.email}: {str(e)}"
        )
        flash(
            "Terjadi kesalahan saat mengupload file. Silakan coba lagi nanti.",
            "danger",
        )
        db.session.rollback()  # Ensure any changes are rolled back if an error occurs

    return redirect(url_for("tm.index"))


@tm_bp.route("/template_update/<template_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def template_update(template_id):
    """Meng-handle pembaruan template berdasarkan ID template."""
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
        flash("Error loading template or parameter content.", "error")
        return redirect(url_for("tm.index"))

    if request.method == "POST":
        new_template_name = secure_filename(request.form["template_name"])
        new_parameter_name = secure_filename(request.form["parameter_name"])
        new_vendor = request.form["vendor"]
        new_version = request.form["version"]
        new_description = request.form["description"]
        new_template_content = (
            request.form["template_content"]
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .strip()
        )
        new_parameter_content = (
            request.form["parameter_content"]
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .strip()
        )

        existing_template = TemplateManager.query.filter(
            TemplateManager.template_name == new_template_name,
            TemplateManager.id != template.id,
        ).first()
        existing_parameter = TemplateManager.query.filter(
            TemplateManager.parameter_name == new_parameter_name,
            TemplateManager.id != template.id,
        ).first()

        if existing_template:
            current_app.logger.warning(
                f"Update failed: Template name '{new_template_name}' already exists"
            )
            flash(f"Template name '{new_template_name}' already exists.", "danger")
            return redirect(url_for("tm.template_update", template_id=template_id))

        if existing_parameter:
            current_app.logger.warning(
                f"Update failed: Parameter name '{new_parameter_name}' already exists"
            )
            flash(f"Parameter name '{new_parameter_name}' already exists.", "danger")
            return redirect(url_for("tm.template_update", template_id=template_id))

        try:
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

            template.vendor = new_vendor
            template.version = new_version
            template.description = new_description

            db.session.commit()
            current_app.logger.info(f"Template updated successfully: {template_id}")
            flash("Template update successful.", "success")
            return redirect(url_for("tm.index"))

        except Exception as e:
            current_app.logger.error(f"Error updating template: {e}")
            flash("Failed to update template.", "error")
            return redirect(url_for("tm.template_update", template_id=template_id))

    return render_template(
        "/template_managers/template_update.html",
        template=template,
        template_content=template_content,
        parameter_content=parameter_content,
    )


@tm_bp.route("/template_delete/<template_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def template_delete(template_id):
    """Meng-handle penghapusan template berdasarkan ID template."""
    template = TemplateManager.query.get_or_404(template_id)

    try:
        template_file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
        )
        parameter_file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
        )

        if os.path.exists(template_file_path):
            os.remove(template_file_path)
            current_app.logger.info(f"Deleted template file: {template_file_path}")
        else:
            current_app.logger.warning(f"Template file not found: {template_file_path}")

        if os.path.exists(parameter_file_path):
            os.remove(parameter_file_path)
            current_app.logger.info(f"Deleted parameter file: {parameter_file_path}")
        else:
            current_app.logger.warning(
                f"Parameter file not found: {parameter_file_path}"
            )

        db.session.delete(template)
        db.session.commit()
        current_app.logger.info(f"Template deleted successfully: {template_id}")
        flash(f"Template successfully deleted by {current_user.email}", "success")

    except Exception as e:
        current_app.logger.error(f"Error deleting template: {e}")
        flash("Failed to delete template.", "error")

    return redirect(url_for("tm.index"))


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
        flash("Error loading template or parameter content.", "error")
        return redirect(url_for("tm.index"))

    return render_template(
        "/template_managers/template_detail.html",
        template=template,
        template_content=template_content,
        parameter_content=parameter_content,
    )


@tm_bp.route("/template_manual_create", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def template_manual_create():
    """Meng-handle pembuatan template manual dari input pengguna."""
    vendor = request.form.get("vendor")
    version = request.form.get("version")
    description = request.form.get("description")
    template_content = (
        request.form.get("template_content")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .strip()
    )
    parameter_content = (
        request.form.get("parameter_content")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .strip()
    )

    current_app.logger.info(
        f"Attempting to create a manual template by {current_user.email}"
    )

    if not vendor:
        flash("Vendor field cannot be empty!", "info")
        current_app.logger.warning("Vendor field is empty")
        return redirect(request.url)

    gen_filename = generate_random_filename(vendor)
    template_filename = f"{gen_filename}.j2"
    parameter_filename = f"{gen_filename}.yml"

    template_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, template_filename
    )
    parameter_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, parameter_filename
    )

    try:
        with open(template_path, "w", encoding="utf-8") as template_file:
            template_file.write(template_content)
        current_app.logger.info(
            f"Successfully saved template content to file: {template_path}"
        )

        with open(parameter_path, "w", encoding="utf-8") as parameter_file:
            parameter_file.write(parameter_content)
        current_app.logger.info(
            f"Successfully saved parameter content to file: {parameter_path}"
        )

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
        flash("Template successfully created.", "success")
        return redirect(url_for("tm.index"))

    except Exception as e:
        current_app.logger.error(f"Error creating template: {e}")
        flash("Failed to create template.", "error")
        return redirect(request.url)


@tm_bp.route("/template_generator/<template_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def template_generator(template_id):
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
            flash("Error loading template or parameter content.", "error")
            return redirect(url_for("tm.index"))

        current_app.logger.info("Successfully read Jinja template and YAML parameters")

        net_auto = ConfigurationManagerUtils(
            ip_address="0.0.0.0", username="none", password="none", ssh=22
        )
        rendered_config = net_auto.render_template_config(jinja_template, yaml_params)
        current_app.logger.info("Successfully rendered Jinja template")

        current_app.logger.info("Validating rendered template with OpenAI...")
        config_validated = validate_generated_template_with_openai(
            config=rendered_config, vendor=vendor
        )

        if not config_validated.get("is_valid"):
            error_message = config_validated.get("error_message")
            current_app.logger.error(
                f"Template validation failed for: ID {template_id}"
            )
            return jsonify({"is_valid": False, "error_message": error_message})

    except Exception as e:
        current_app.logger.error(f"Error rendering or validating template: {e}")
        flash("Failed to render or validate template.", "error")
        return jsonify(
            {
                "is_valid": False,
                "error_message": f"Gagal merender atau memvalidasi template: {e}",
            }
        )

    try:
        gen_filename = generate_random_filename(template.vendor)
        newFileName = f"{gen_filename}.txt"
        new_file_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, newFileName
        )

        with open(new_file_path, "w", encoding="utf-8") as new_file:
            new_file.write(rendered_config)
        current_app.logger.info(
            f"Successfully saved rendered config to file: {new_file_path}"
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
            f"Successfully saved generated template to database: {newFileName}"
        )
        flash("Template successfully generated.", "success")
        return jsonify({"is_valid": True})

    except Exception as e:
        current_app.logger.error(
            f"Error saving rendered config or template to database: {e}"
        )
        flash("Failed to save configuration or template to database.", "error")

    return redirect(url_for("tm.index"))


# --------------------------------------------------------------------------------
# Bagian File konfigurasi (hasil dari generate template yang telah di validasi AI)
# --------------------------------------------------------------------------------


@tm_bp.route("/template_results")
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Templates", "View Templates"],
    page="Configuration File Management",
)
def template_results():
    # Logging untuk akses ke endpoint
    current_app.logger.info(f"{current_user.email} accessed template_results")

    # Validasi input untuk page, per_page, dan search_query
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 10))
        if page < 1 or per_page < 1:
            raise ValueError("Page and per_page must be positive integers.")
    except ValueError as e:
        current_app.logger.warning(f"Invalid pagination parameters: {e}")
        flash("Invalid pagination parameters. Please try again.", "danger")
        return redirect(url_for("tm.template_results"))

    search_query = request.args.get("search", "").strip().lower()

    # Logging untuk pencarian
    if search_query:
        current_app.logger.info(
            f"{current_user.email} performed a search with query: {search_query}"
        )

    # Menerapkan filter berdasarkan search query dan user ownership
    if search_query:
        query = ConfigurationManager.query.filter(
            ConfigurationManager.user_id == current_user.id,
            ConfigurationManager.config_name.ilike(f"%{search_query}%")
            | ConfigurationManager.vendor.ilike(f"%{search_query}%")
            | ConfigurationManager.description.ilike(f"%{search_query}%"),
        )
    else:
        query = ConfigurationManager.query.filter_by(user_id=current_user.id)

    # Mendapatkan total hasil pencarian
    total_templates = query.count()

    # Logging jika tidak ada hasil pencarian
    if total_templates == 0:
        current_app.logger.info(
            f"No templates found for user {current_user.email} with query '{search_query}'"
        )
        flash("No templates found matching your search criteria.", "info")

    # Paginasi hasil pencarian
    all_templates = query.limit(per_page).offset((page - 1) * per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total_templates)

    template_contents = {}
    for template in all_templates:
        template_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, template.config_name
        )
        template_content = read_file(template_path)

        if template_content:
            template_contents[template.id] = template_content
        else:
            template_contents[template.id] = "File not found"
            current_app.logger.warning(
                f"Template file not found for {template.config_name} at {template_path}"
            )
            flash(f"Template file '{template.config_name}' not found.", "warning")

    return render_template(
        "/template_managers/template_results.html",
        all_templates=all_templates,
        page=page,
        per_page=per_page,
        pagination=pagination,
        search_query=search_query,
        template_contents=template_contents,
        total_templates=total_templates,
    )


@tm_bp.route("/configuration_manual_create", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Configuration File Management",
)
def configuration_manual_create():
    """Membuat file konfigurasi manual dan menyimpannya ke dalam database."""
    filename = secure_filename(request.form.get("filename"))
    vendor = request.form.get("vendor")
    configuration_description = request.form.get("configuration_description")
    configuration_content = (
        request.form.get("configuration_content")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .strip()
    )

    current_app.logger.info(
        f"Attempting to create a manual configuration file by {current_user.email}"
    )

    if not filename or not vendor:
        flash("Filename and vendor cannot be empty!", "info")
        current_app.logger.warning("Filename is empty.")
        return redirect(request.url)

    gen_filename = generate_random_filename(vendor)

    configuration_name = f"{filename}_{gen_filename}.txt"
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

            return jsonify({"is_valid": True})  # Respond with JSON indicating success
        else:
            error_message = config_validated.get("error_message")
            return jsonify({"is_valid": False, "error_message": error_message})

    except Exception as e:
        # Rolling back session jika terjadi kesalahan
        db.session.rollback()
        current_app.logger.error(f"Error creating configuration file: {e}")
        flash("Failed to create configuration file.", "error")
        return redirect("tm.index")


@tm_bp.route("/create_configuration_with_ai", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Configuration File Management",
)
def create_configuration_with_ai():
    """Membuat file konfigurasi dengan bantuan AI dan menyimpannya ke dalam database."""
    filename = secure_filename(request.form.get("filename"))
    vendor = request.form.get("vendor")
    description = request.form.get("description")
    ask_configuration = request.form.get("ask_configuration")

    current_app.logger.info(
        f"Attempting to create an AI-generated configuration file by {current_user.email}"
    )

    if not filename or not vendor:
        flash("Filename and vendor cannot be empty!", "info")
        current_app.logger.warning("Filename is empty.")
        return redirect(request.url)

    gen_filename = generate_random_filename(vendor)

    configuration_name = f"{filename}_{gen_filename}.txt"
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
        return redirect("tm.index")


@tm_bp.route("/template_result_update/<template_result_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Configuration File Management",
)
def template_result_update(template_result_id):
    """Meng-handle pembaruan file konfigurasi template yang ada."""
    current_app.logger.info(
        f"Attempting to update configuration file with ID {template_result_id} by {current_user.email}"
    )

    template = ConfigurationManager.query.get_or_404(template_result_id)

    # Verifikasi kepemilikan file konfigurasi
    if template.user_id != current_user.id:
        flash("You do not have permission to update this configuration file.", "danger")
        return redirect(url_for("tm.template_results"))

    template_content = read_file(
        os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, template.config_name
        )
    )

    if template_content is None:
        flash("Error loading template content.", "error")
        return redirect(url_for("tm.template_results"))

    if request.method == "POST":
        new_template_name = secure_filename(request.form["template_name"])
        new_vendor = request.form["vendor"]
        new_description = request.form["description"]
        new_template_content = (
            request.form["template_content"]
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .strip()
        )

        try:
            if new_template_content != template_content:
                template_path = os.path.join(
                    current_app.static_folder, GEN_TEMPLATE_FOLDER, template.config_name
                )
                with open(template_path, "w", encoding="utf-8") as file:
                    file.write(new_template_content)
                current_app.logger.info(
                    f"Successfully updated template content in file: {template_path}"
                )

            if new_template_name != template.config_name:
                new_path_template = os.path.join(
                    current_app.static_folder, GEN_TEMPLATE_FOLDER, new_template_name
                )

                if os.path.exists(new_path_template):
                    flash("File with the new name already exists.", "info")
                    current_app.logger.warning(
                        f"File with the new name already exists: {new_path_template}"
                    )
                else:
                    old_path_template = os.path.join(
                        current_app.static_folder,
                        GEN_TEMPLATE_FOLDER,
                        template.config_name,
                    )
                    os.rename(old_path_template, new_path_template)
                    template.config_name = new_template_name
                    current_app.logger.info(
                        f"Successfully renamed file from {old_path_template} to {new_path_template}"
                    )

            template.vendor = new_vendor
            template.description = new_description
            db.session.commit()
            current_app.logger.info(
                f"Successfully updated template data in database: ID {template_result_id}"
            )
            flash("Template update successful.", "success")
            return redirect(url_for("tm.template_results"))

        except Exception as e:
            current_app.logger.error(f"Error updating template: {e}")
            flash("Failed to update template.", "error")
            return redirect(request.url)

    return render_template(
        "/template_managers/template_result_update.html",
        template=template,
        template_content=template_content,
    )


@tm_bp.route("/template_result_delete/<template_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Configuration File Management",
)
def template_result_delete(template_id):
    template = ConfigurationManager.query.get_or_404(template_id)

    # Verifikasi kepemilikan file konfigurasi
    if template.user_id != current_user.id:
        flash("You do not have permission to delete this configuration file.", "danger")
        return redirect(url_for("tm.template_results"))

    try:
        file_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, str(template.config_name)
        )
        if os.path.exists(file_path):
            os.remove(file_path)
            current_app.logger.info(f"Deleted configuration file: {file_path}")
        else:
            current_app.logger.warning(f"Configuration file not found: {file_path}")

        db.session.delete(template)
        db.session.commit()
        current_app.logger.info(
            f"Configuration file successfully deleted: ID {template.id}"
        )
        flash("Configuration file successfully deleted.", "success")

    except Exception as e:
        current_app.logger.error(f"Error deleting configuration file: {e}")
        flash("Failed to delete configuration file.", "error")

    return redirect(url_for("tm.template_results"))


@tm_bp.route("/ask_talita", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Configuration File Management",
)
def ask_talita():
    if request.method == "POST":
        # Mengambil data dari form modal
        question = request.form.get("question")
        context = request.form.get("context")
        question_with_context = f"{context}\n{question}"
        user_id = request.form.get("user_id")
        url = "https://talita.lintasarta.net/api/portal"
        apikey = "ZTczN2Y0N2E0ZDcxZTIwZjUzN2I5MzA5MDE4MWZmODg="

        # Memanggil fungsi talita_chat_completion
        response = talita_chat_completion(url, apikey, question_with_context, user_id)

        # Mengecek apakah respon berhasil atau gagal
        if response is None:
            current_app.logger.warning(f"Failed to connect Talita AI")
        elif not response.startswith("Gagal"):
            # Membuat nama file acak
            random_name = "".join(
                random.choices(string.ascii_letters + string.digits, k=8)
            )
            filename = f"talita_{random_name}.txt"
            file_path = os.path.join(
                current_app.static_folder, GEN_TEMPLATE_FOLDER, filename
            )

            # Menyimpan hasil ke dalam file
            with open(file_path, "w") as file:
                file.write(response)

            new_configuration = ConfigurationManager(
                config_name=filename,
                vendor="talita",
                description=filename,
                created_by=current_user.email,
                user_id=current_user.id,
            )
            db.session.add(new_configuration)
            db.session.commit()

            # Flash message sukses
            flash(
                "Berhasil mendapatkan jawaban dari TALITA dan menyimpan ke dalam file.",
                "success",
            )
        else:
            # Flash message gagal
            flash(f"Gagal mendapatkan jawaban dari TALITA: {response}", "danger")

        # Redirect kembali ke halaman yang sama untuk menutup modal dan memperbarui UI
        return redirect(url_for("tm.template_results"))

    # Jika GET request, tampilkan halaman dengan modal
    return render_template("tm.template_results")
