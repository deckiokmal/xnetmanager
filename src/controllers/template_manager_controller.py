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
from src.models.xmanager_model import TemplateManager, ConfigurationManager
from src.utils.config_manager_utils import ConfigurationManagerUtils
from src.utils.openai_utils import validate_generated_template_with_openai
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from .decorators import login_required, role_required, required_2fa
import random
import string
from flask_paginate import Pagination
import logging

# Blueprint untuk template manager
tm_bp = Blueprint("tm", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging untuk aplikasi
logging.basicConfig(level=logging.INFO)


@tm_bp.before_app_request
def setup_logging():
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


@error_bp.app_errorhandler(404)
def page_not_found(error):
    current_app.logger.error(f"Error 404: {error}")
    return render_template("main/404.html"), 404


@tm_bp.before_request
def before_request_func():
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return jsonify({"message": "Unauthorized access"}), 401


@tm_bp.context_processor
def inject_user():
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


@tm_bp.route("/tm", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Templates", "View Templates"],
    page="Templates Management",
)
def index():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    search_query = request.args.get("search", "")

    query = TemplateManager.query
    if search_query:
        query = query.filter(
            TemplateManager.template_name.ilike(f"%{search_query}%")
            | TemplateManager.parameter_name.ilike(f"%{search_query}%")
            | TemplateManager.vendor.ilike(f"%{search_query}%")
            | TemplateManager.version.ilike(f"%{search_query}%")
        )

    all_templates = query.paginate(page=page, per_page=per_page)

    return render_template(
        "/template_managers/index.html",
        all_templates=all_templates,
        per_page=per_page,
        search_query=search_query,
    )


@tm_bp.route("/template_upload", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
def template_upload():
    """Meng-handle upload file template dan parameter serta menyimpan data ke database."""
    if "j2" not in request.files or "yaml" not in request.files:
        flash("No file part", "error")
        current_app.logger.warning("File part missing in upload request")
        return redirect(request.url)

    j2 = request.files["j2"]
    yaml = request.files["yaml"]
    vendor = request.form.get("vendor")
    version = request.form.get("version")
    description = request.form.get("description")

    if not vendor or not version:
        flash("Vendor and version fields cannot be empty.", "info")
        return redirect(request.url)

    if j2.filename and allowed_file(j2.filename, TEMPLATE_EXTENSIONS):
        template_name = save_uploaded_file(j2, RAW_TEMPLATE_FOLDER)
    else:
        flash("Invalid template file type. Allowed: j2.", "error")
        current_app.logger.warning(f"Invalid template file type: {j2.filename}")
        return redirect(request.url)

    if yaml.filename and allowed_file(yaml.filename, PARAMS_EXTENSIONS):
        parameter_name = save_uploaded_file(yaml, RAW_TEMPLATE_FOLDER)
    else:
        flash("Invalid parameter file type. Allowed: yml, yaml.", "error")
        current_app.logger.warning(f"Invalid parameter file type: {yaml.filename}")
        return redirect(request.url)

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
    current_app.logger.info(f"New template saved to database: {template_name}")
    flash("File successfully uploaded.", "success")
    return redirect(url_for("tm.index"))


@tm_bp.route("/template_update/<int:template_id>", methods=["GET", "POST"])
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


@tm_bp.route("/template_delete/<int:template_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
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


@tm_bp.route("/template_detail/<int:template_id>", methods=["GET"])
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


@tm_bp.route("/template_generator/<int:template_id>", methods=["POST"])
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
            current_app.logger.error(f"Template validation failed: {error_message}")
            flash(f"Template validation failed: {error_message}", "error")
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
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    search_query = request.args.get("search", "")

    query = ConfigurationManager.query
    if search_query:
        query = query.filter(
            ConfigurationManager.config_name.ilike(f"%{search_query}%")
            | ConfigurationManager.description.ilike(f"%{search_query}%")
        )

    total_templates = query.count()
    all_templates = query.paginate(page=page, per_page=per_page)

    pagination = Pagination(
        page=page, per_page=per_page, total=total_templates, css_framework="bootstrap4"
    )

    template_contents = {}
    for template in all_templates.items:
        template_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, template.config_name
        )
        template_contents[template.id] = read_file(template_path) or "File not found"

    return render_template(
        "/template_managers/template_results.html",
        all_templates=all_templates.items,
        template_contents=template_contents,
        per_page=per_page,
        search_query=search_query,
        pagination=pagination,
    )


@tm_bp.route(
    "/template_result_update/<int:template_result_id>", methods=["GET", "POST"]
)
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


@tm_bp.route("/template_result_delete/<int:template_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Configuration File Management",
)
def template_result_delete(template_id):
    template = ConfigurationManager.query.get_or_404(template_id)

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

    if not filename:
        flash("Filename cannot be empty!", "info")
        current_app.logger.warning("Filename is empty.")
        return redirect(request.url)

    configuration_name = f"{filename}.txt"
    file_path = os.path.join(
        current_app.static_folder, GEN_TEMPLATE_FOLDER, configuration_name
    )

    try:
        with open(file_path, "w", encoding="utf-8") as configuration_file:
            configuration_file.write(configuration_content)
        current_app.logger.info(
            f"Successfully created configuration file at: {file_path}"
        )

        new_configuration = ConfigurationManager(
            config_name=configuration_name,
            description=configuration_description,
            created_by=current_user.email,
        )
        db.session.add(new_configuration)
        db.session.commit()
        current_app.logger.info(
            f"Successfully added configuration to database: {configuration_name}"
        )
        flash("Configuration file successfully created.", "success")
        return redirect(url_for("tm.template_results"))

    except Exception as e:
        current_app.logger.error(f"Error creating configuration file: {e}")
        flash("Failed to create configuration file.", "error")
        return redirect(request.url)
