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
from src.models.app_models import ConfigurationManager
from src.utils.openai_utils import (
    validate_generated_template_with_openai,
    create_configuration_with_openai,
)
from src.utils.ConfigurationFileUtils import (
    check_ownership,
    read_file,
    generate_random_filename,
    is_safe_path,
    delete_file_safely,
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
    ManualConfigurationForm,
    AIConfigurationForm,
    UpdateConfigurationForm,
    TalitaQuestionForm,
)

# Blueprint untuk config manager
config_file_bp = Blueprint("config_file", __name__)
error_bp = Blueprint("error", __name__)


@error_bp.app_errorhandler(404)
def page_not_found(error):
    """
    Menangani error 404 dan menampilkan halaman 404.
    """
    current_app.logger.error(f"Error 404: {error}")
    return render_template("main/404.hconfig_filel"), 404


# Middleware untuk autentikasi dan otorisasi sebelum permintaan.
@config_file_bp.before_request
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
        return render_template("main/404.hconfig_filel"), 404

    # Jika pengguna terotentikasi dan memiliki flag force_logout, lakukan logout
    if current_user.force_logout:
        current_user.force_logout = False  # Reset the flag
        db.session.commit()
        logout_user()
        flash("Your password has been updated. Please log in again.", "info")
        return redirect(url_for("main.login"))


@config_file_bp.context_processor
def inject_user():
    """
    Menyediakan first_name dan last_name pengguna yang terotentikasi ke dalam config.
    """
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


CONFIG_DIRECTORY = "xmanager/configurations"

# --------------------------------------------------------------------------------
# CRUD Operation Section
# --------------------------------------------------------------------------------


@config_file_bp.route("/configuration-file")
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def index():
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
            "config_file_managers/index.html",
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


@config_file_bp.route(
    "/configuration-file/create-configuration-with-ai-validated", methods=["POST"]
)
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def create_configuration_with_ai_validated():
    current_app.logger.info(
        f"User {current_user.email} is attempting to create a manual configuration file."
    )

    formManualConfiguration = ManualConfigurationForm()

    if formManualConfiguration.validate_on_submit():
        filename = secure_filename(formManualConfiguration.filename.data)
        vendor = formManualConfiguration.vendor.data
        configuration_description = (
            formManualConfiguration.configuration_description.data
        )
        configuration_content = (
            formManualConfiguration.configuration_content.data.strip()
        )

        gen_filename = generate_random_filename(vendor)
        file_path = os.path.join(
            current_app.static_folder, CONFIG_DIRECTORY, gen_filename
        )

        try:
            config_validated = validate_generated_template_with_openai(
                config=configuration_content, vendor=vendor
            )
            if config_validated.get("is_valid"):
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, "w", encoding="utf-8") as configuration_file:
                    configuration_file.write(configuration_content)

                new_configuration = ConfigurationManager(
                    config_name=gen_filename,
                    vendor=vendor,
                    description=configuration_description,
                    created_by=current_user.email,
                    user_id=current_user.id,
                )
                db.session.add(new_configuration)
                db.session.commit()

                return (
                    jsonify(
                        {"is_valid": True, "redirect_url": url_for("config_file.index")}
                    ),
                    200,
                )

            else:
                return (
                    jsonify(
                        {
                            "is_valid": False,
                            "error_message": config_validated.get("error_message"),
                        }
                    ),
                    400,
                )

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating configuration file: {e}")
            return (
                jsonify(
                    {
                        "is_valid": False,
                        "error_message": "Failed to create configuration file.",
                    }
                ),
                500,
            )

    else:
        errors = {
            field: error for field, error in formManualConfiguration.errors.items()
        }
        current_app.logger.warning(f"Form validation failed: {errors}")
        return jsonify({"is_valid": False, "errors": errors}), 400


@config_file_bp.route(
    "/configuration-file/create-configuration-with-ai-automated", methods=["POST"]
)
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def create_configuration_with_ai_automated():
    current_app.logger.info(
        f"User {current_user.email} is attempting to create an AI-generated configuration file."
    )

    formAIconfiguration = AIConfigurationForm()

    if formAIconfiguration.validate_on_submit():
        vendor = formAIconfiguration.vendor.data
        description = formAIconfiguration.description.data
        ask_configuration = formAIconfiguration.ask_configuration.data

        gen_filename = generate_random_filename(vendor)
        file_path = os.path.join(
            current_app.static_folder, CONFIG_DIRECTORY, gen_filename
        )

        try:
            configuration_content, error = create_configuration_with_openai(
                question=ask_configuration, vendor=vendor
            )
            if error:
                current_app.logger.error(f"AI configuration error: {error}")
                return jsonify({"is_valid": False, "error_message": error}), 400

            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as configuration_file:
                configuration_file.write(configuration_content)

            new_configuration = ConfigurationManager(
                config_name=gen_filename,
                vendor=vendor,
                description=description,
                created_by=current_user.email,
                user_id=current_user.id,
            )
            db.session.add(new_configuration)
            db.session.commit()

            return (
                jsonify(
                    {"is_valid": True, "redirect_url": url_for("config_file.index")}
                ),
                200,
            )

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating configuration file: {e}")
            return (
                jsonify(
                    {
                        "is_valid": False,
                        "error_message": "Failed to create configuration file.",
                    }
                ),
                500,
            )

    else:
        errors = {field: error for field, error in formAIconfiguration.errors.items()}
        current_app.logger.warning(f"Form validation failed: {errors}")
        return jsonify({"is_valid": False, "error_message": errors}), 400


@config_file_bp.route("/configuration-file/get-detail/<config_id>", methods=["GET"])
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
        configuration_file_path = os.path.join(
            current_app.static_folder, CONFIG_DIRECTORY, configuration.config_name
        )
        if not is_safe_path(configuration_file_path, current_app.static_folder):
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


@config_file_bp.route("/configuration-file/update/<config_id>", methods=["GET", "POST"])
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
    config_content = read_file(
        os.path.join(current_app.static_folder, CONFIG_DIRECTORY, config.config_name)
    )
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
                {"is_valid": True, "redirect_url": url_for("config_file.index")}
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
            if new_config_content != config_content:
                config_path = os.path.join(
                    current_app.static_folder, CONFIG_DIRECTORY, config.config_name
                )
                with open(config_path, "w", encoding="utf-8") as file:
                    file.write(new_config_content)
                current_app.logger.info(
                    f"Successfully updated config content by user {current_user.email}"
                )

            # Rename the file if necessary
            if new_config_name != config.config_name:
                old_path = os.path.join(
                    current_app.static_folder, CONFIG_DIRECTORY, config.config_name
                )
                new_path = os.path.join(
                    current_app.static_folder, CONFIG_DIRECTORY, new_config_name
                )

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

            return jsonify(
                {"is_valid": True, "redirect_url": url_for("config_file.index")}
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
        "config_file_managers/update_config_file.html", config=config, form=form
    )


@config_file_bp.route("/configuration-file/delete/<config_id>", methods=["POST"])
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
        file_path = os.path.join(
            current_app.static_folder, CONFIG_DIRECTORY, config.config_name
        )
        success, message = delete_file_safely(file_path)
        if not success:
            return jsonify({"error": message}), 400

        db.session.delete(config)
        db.session.commit()

        jsonify({"success": True, "redirect_url": url_for("config_file.index")})
        return redirect(url_for("config_file.index"))

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting configuration: {e}")
        return (
            jsonify({"error": "Failed to delete configuration due to an error."}),
            500,
        )


# --------------------------------------------------------------------------------
# Talita Lintasarta Section
# --------------------------------------------------------------------------------


@config_file_bp.route("/ask_talita", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def ask_talita():
    current_app.logger.warning(
        f"User {current_user.email} is attempting to use Talita AI Endpoint."
    )

    formTalita = TalitaQuestionForm()

    if formTalita.validate_on_submit():
        config_name = formTalita.config_name.data
        vendor = formTalita.vendor.data
        description = formTalita.description.data
        question = formTalita.question.data

        context = (
            f"Berikan hanya sintaks konfigurasi yang tepat untuk {vendor}.\n"
            f"Hanya sertakan perintah konfigurasi yang spesifik untuk vendor {vendor}.\n"
            f"Jika permintaan tidak dapat dipenuhi, respons harus dimulai dengan 'Gagal'.\n"
            f"Pertanyaan: {question}\n"
        )

        user_id = str(current_user.id)

        current_app.logger.info(
            f"User {current_user.email} is asking TALITA a question."
        )

        try:
            response = talita_chat_completion(context, user_id)

            if response is None:
                current_app.logger.warning(
                    f"Failed to connect to Talita AI for user {current_user.email}"
                )
                return (
                    jsonify(
                        {
                            "is_valid": False,
                            "error_message": "Tidak dapat terhubung dengan TALITA. Coba lagi nanti.",
                        }
                    ),
                    400,
                )
            elif response.startswith("Gagal"):
                return jsonify({"is_valid": False, "error_message": response}), 400

            gen_filename = generate_random_filename(config_name)
            filename = f"{gen_filename}.txt"
            file_path = os.path.join(
                current_app.static_folder, CONFIG_DIRECTORY, filename
            )

            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            with open(file_path, "w", encoding="utf-8") as file:
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
                f"User {current_user.email} successfully saved response from TALITA to {filename}."
            )
            return (
                jsonify(
                    {"is_valid": True, "message": "Configuration created successfully."}
                ),
                200,
            )

        except Exception as e:
            current_app.logger.error(f"Error processing TALITA request: {str(e)}")
            return (
                jsonify(
                    {
                        "is_valid": False,
                        "error_message": "Terjadi kesalahan saat memproses permintaan.",
                    }
                ),
                500,
            )

    else:
        errors = {field: error for field, error in formTalita.errors.items()}
        current_app.logger.warning(f"Form validation failed: {errors}")
        return jsonify({"is_valid": False, "errors": errors}), 400
