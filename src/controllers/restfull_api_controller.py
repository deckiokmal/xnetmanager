from flask import (
    Blueprint,
    jsonify,
    current_app,
    request,
)
from src import db, bcrypt
from src.models.app_models import (
    DeviceManager,
    User,
    Role,
    TemplateManager,
    ConfigurationManager,
)
import logging
from src.utils.schema_utils import (
    user_schema,
    users_schema,
    device_schema,
    devices_schema,
    template_schema,
    templates_schema,
    configfile_schema,
    configfiles_schema,
)
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from datetime import datetime
import random
import string
from werkzeug.utils import secure_filename
import os
from src.utils.openai_utils import (
    validate_generated_template_with_openai,
)
from src.utils.config_manager_utils import ConfigurationManagerUtils

# Create blueprints for the device manager (restapi_bp) and error handling (error_bp)
restapi_bp = Blueprint("restapi", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging configuration for the application
logging.basicConfig(level=logging.INFO)


@restapi_bp.before_app_request
def setup_logging():
    """
    Configure logging for the application.
    This function ensures that all logs are captured at the INFO level,
    making it easier to track the flow of the application and debug issues.
    """
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]  # Use the first handler
    current_app.logger.addHandler(handler)


# -----------------------------------------------------------
# Utility
# -----------------------------------------------------------


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


# -----------------------------------------------------------
# Login JWT Access Token
# -----------------------------------------------------------


@restapi_bp.route("/api/login", methods=["POST"])
def login():
    if request.is_json:
        email = request.json["email"]
        password = request.json["password"]
    else:
        email = request.form["email"]
        password = request.form["password"]

    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=email)

        current_app.logger.info(
            f"User {email} Login via API at {datetime.now().strftime("%d:%m:%Y")}"
        )
        return jsonify(message="Login Sukses.", access_token=access_token)
    else:
        return jsonify(message="Email atau Password salah."), 401


# -----------------------------------------------------------
# API User Management
# -----------------------------------------------------------


@restapi_bp.route("/api/get-users", methods=["GET"])
@jwt_required()
def get_users():
    users_list = User.query.all()
    result = users_schema.dump(users_list)
    return jsonify(result)


@restapi_bp.route("/api/get-user/<user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        result = user_schema.dump(user)
        return jsonify(result)
    else:
        return jsonify(message="User tidak ditemukan."), 404


@restapi_bp.route("/api/create-user", methods=["POST"])
@jwt_required()
def create_user():
    # Mengambil identitas pengguna dari JWT
    user_identity = get_jwt_identity()

    try:
        current_app.logger.info(f"Attempting API create user by {user_identity}")

        # Memeriksa apakah request menggunakan form data atau JSON
        if request.is_json:
            data = request.get_json()
            email = data.get("email")
            first_name = data.get("first_name")
            last_name = data.get("last_name")
            password = data.get("password")
        else:
            email = request.form.get("email")
            first_name = request.form.get("first_name")
            last_name = request.form.get("last_name")
            password = request.form.get("password")

        # Validasi input dasar
        if not email or not first_name or not last_name or not password:
            return jsonify(message="Input tidak lengkap, semua field harus diisi."), 400

        # Memeriksa apakah email sudah terdaftar
        user = User.query.filter_by(email=email).first()
        if user:
            return jsonify(message="Email sudah terdaftar!"), 409

        # Membuat user baru
        new_user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password_hash=password,  # Diasumsikan password sudah di-hash sebelumnya
        )

        # Assign role 'User'
        user_role = Role.query.filter_by(name="User").first()
        if user_role:
            new_user.roles.append(user_role)

        db.session.add(new_user)
        db.session.commit()

        current_app.logger.info(
            f"{user_identity} created user {email} at {datetime.now().strftime('%d:%m:%Y %H:%M:%S')}"
        )

        return jsonify(message="User berhasil dibuat."), 201

    except KeyError as e:
        current_app.logger.error(f"Missing key in request: {str(e)}")
        return jsonify(message=f"Key {str(e)} tidak ditemukan di request."), 400

    except Exception as e:
        current_app.logger.error(f"Error creating user: {str(e)}")
        return jsonify(message="Terjadi kesalahan pada server, silakan coba lagi."), 500


@restapi_bp.route("/api/update-user", methods=["PUT"])
@jwt_required()
def update_user():
    # Mengambil identitas pengguna dari JWT
    user_identity = get_jwt_identity()

    try:
        current_app.logger.info(f"Attempting API update user by {user_identity}")

        # Memeriksa apakah request menggunakan form data atau JSON
        if request.is_json:
            data = request.get_json()
            user_id = data.get("user_id")
            first_name = data.get("first_name")
            last_name = data.get("last_name")
        else:
            user_id = request.form.get("user_id")
            first_name = request.form.get("first_name")
            last_name = request.form.get("last_name")

        # Validasi input dasar
        if not user_id or not first_name or not last_name:
            return jsonify(message="Input tidak lengkap, semua field harus diisi."), 400

        # Memeriksa apakah user dengan ID tersebut ada
        user = User.query.filter_by(id=user_id).first()
        if user:
            user.first_name = first_name
            user.last_name = last_name
            db.session.commit()

            current_app.logger.info(
                f"{user_identity} updated user {user.email} at {datetime.now().strftime('%d:%m:%Y %H:%M:%S')}"
            )
            return jsonify(message="User update sukses."), 202
        else:
            return jsonify(message="User tidak ditemukan."), 404

    except KeyError as e:
        current_app.logger.error(f"Missing key in request: {str(e)}")
        return jsonify(message=f"Key {str(e)} tidak ditemukan di request."), 400

    except Exception as e:
        current_app.logger.error(f"Error updating user: {str(e)}")
        return jsonify(message="Terjadi kesalahan pada server, silakan coba lagi."), 500


@restapi_bp.route("/api/delete-user/<user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    # Mengambil identitas pengguna dari JWT
    user_identity = get_jwt_identity()

    try:
        current_app.logger.info(
            f"Attempting API delete user by {user_identity} for user_id {user_id}"
        )

        # Mencari user berdasarkan user_id
        user = User.query.filter_by(id=user_id).first()

        if user:
            db.session.delete(user)
            db.session.commit()

            current_app.logger.info(
                f"{user_identity} deleted user {user.email} at {datetime.now().strftime('%d:%m:%Y %H:%M:%S')}"
            )
            return jsonify(message=f"User {user.email} berhasil dihapus."), 202
        else:
            return jsonify(message="User tidak ditemukan."), 404

    except Exception as e:
        current_app.logger.error(f"Error deleting user: {str(e)}")
        return jsonify(message="Terjadi kesalahan pada server, silakan coba lagi."), 500


# -----------------------------------------------------------
# API Devices Management
# -----------------------------------------------------------


@restapi_bp.route("/api/get-devices", methods=["GET"])
@jwt_required()
def get_devices():
    devices_list = DeviceManager.query.all()
    result = devices_schema.dump(devices_list)
    return jsonify(result)


@restapi_bp.route("/api/get-device/<device_id>", methods=["GET"])
@jwt_required()
def get_device(device_id):
    device = DeviceManager.query.filter_by(id=device_id).first()
    if device:
        result = device_schema.dump(device)
        return jsonify(result)
    else:
        return jsonify(message="Device tidak ditemukan."), 404


@restapi_bp.route("/api/create-device", methods=["POST"])
@jwt_required()
def create_device():
    # Mengambil identitas pengguna dari JWT
    user_identity = get_jwt_identity()

    try:
        current_app.logger.info(f"Attempting API create device by {user_identity}")

        # Memeriksa apakah request menggunakan form data atau JSON
        if request.is_json:
            data = request.get_json()
            ip_address = data.get("ip_address")
            device_name = data.get("device_name")
            vendor = data.get("vendor")
            username = data.get("username")
            password = data.get("password")
            ssh = int(data.get("ssh", 22))  # default port 22 jika tidak ada di request
            description = data.get("description")
        else:
            ip_address = request.form.get("ip_address")
            device_name = request.form.get("device_name")
            vendor = request.form.get("vendor")
            username = request.form.get("username")
            password = request.form.get("password")
            ssh = int(
                request.form.get("ssh", 22)
            )  # default port 22 jika tidak ada di form
            description = request.form.get("description")

        # Validasi input dasar
        if (
            not ip_address
            or not device_name
            or not vendor
            or not username
            or not password
        ):
            return jsonify(message="Semua field wajib diisi."), 400

        # Cek apakah IP address atau device name sudah ada
        exist_address = DeviceManager.query.filter_by(ip_address=ip_address).first()
        exist_device_name = DeviceManager.query.filter_by(
            device_name=device_name
        ).first()

        if exist_address or exist_device_name:
            return (
                jsonify(
                    message="IP Address atau Device Name sudah ada. Silakan coba yang lain."
                ),
                409,
            )

        # Membuat device baru
        new_device = DeviceManager(
            device_name=device_name,
            vendor=vendor,
            ip_address=ip_address,
            username=username,
            password=password,
            ssh=ssh,
            description=description,
            created_by=user_identity,
        )

        db.session.add(new_device)
        db.session.commit()

        current_app.logger.info(
            f"{user_identity} created device {device_name} at {datetime.now().strftime('%d:%m:%Y %H:%M:%S')}"
        )

        return jsonify(message="Device berhasil dibuat."), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating device: {str(e)}")
        return (
            jsonify(
                message="Terjadi kesalahan saat membuat perangkat. Silakan coba lagi."
            ),
            500,
        )


@restapi_bp.route("/api/update-device", methods=["PUT"])
@jwt_required()
def update_device():
    # Mengambil identitas pengguna dari JWT
    user_identity = get_jwt_identity()

    try:
        current_app.logger.info(f"Attempting API update device by {user_identity}")

        # Memeriksa apakah request menggunakan form data atau JSON
        if request.is_json:
            data = request.get_json()
            device_id = data.get("device_id")
            device_name = data.get("device_name")
            vendor = data.get("vendor")
            ip_address = data.get("ip_address")
            username = data.get("username")
            password = data.get("password")
            ssh = int(data.get("ssh", 22))  # default port 22 jika tidak disertakan
            description = data.get("description")
        else:
            device_id = request.form.get("device_id")
            device_name = request.form.get("device_name")
            vendor = request.form.get("vendor")
            ip_address = request.form.get("ip_address")
            username = request.form.get("username")
            password = request.form.get("password")
            ssh = int(
                request.form.get("ssh", 22)
            )  # default port 22 jika tidak disertakan
            description = request.form.get("description")

        # Validasi input dasar
        if (
            not device_id
            or not device_name
            or not vendor
            or not ip_address
            or not username
            or not password
        ):
            return jsonify(message="Semua field wajib diisi."), 400

        # Mencari perangkat berdasarkan device_id
        device = DeviceManager.query.filter_by(id=device_id).first()

        if device:
            device.device_name = device_name
            device.vendor = vendor
            device.ip_address = ip_address
            device.username = username
            device.password = password
            device.ssh = ssh
            device.description = description
            device.created_by = user_identity

            db.session.commit()

            current_app.logger.info(
                f"{user_identity} updated device {device.device_name} at {datetime.now().strftime('%d:%m:%Y %H:%M:%S')}"
            )
            return jsonify(message="Device update sukses."), 202
        else:
            return jsonify(message="Device tidak ditemukan."), 404

    except Exception as e:
        current_app.logger.error(f"Error updating device: {str(e)}")
        return (
            jsonify(
                message="Terjadi kesalahan saat memperbarui perangkat. Silakan coba lagi."
            ),
            500,
        )


@restapi_bp.route("/api/delete-device/<device_id>", methods=["DELETE"])
@jwt_required()
def delete_device(device_id):
    # Mengambil identitas pengguna dari JWT
    user_identity = get_jwt_identity()

    try:
        current_app.logger.info(
            f"Attempting API delete device by {user_identity} for device_id {device_id}"
        )

        # Mencari perangkat berdasarkan device_id
        device = DeviceManager.query.filter_by(id=device_id).first()

        if device:
            db.session.delete(device)
            db.session.commit()

            current_app.logger.info(
                f"{user_identity} deleted device {device.device_name} at {datetime.now().strftime('%d:%m:%Y %H:%M:%S')}"
            )
            return (
                jsonify(message=f"Device {device.device_name} berhasil dihapus."),
                202,
            )
        else:
            return jsonify(message="Device tidak ditemukan."), 404

    except Exception as e:
        current_app.logger.error(f"Error deleting device: {str(e)}")
        return (
            jsonify(
                message="Terjadi kesalahan saat menghapus perangkat. Silakan coba lagi."
            ),
            500,
        )


# -----------------------------------------------------------
# API Template Management
# -----------------------------------------------------------


@restapi_bp.route("/api/get-templates", methods=["GET"])
@jwt_required()
def get_templates():
    templates_list = TemplateManager.query.all()
    result = templates_schema.dump(templates_list)
    return jsonify(result)


@restapi_bp.route("/api/get-template/<template_id>", methods=["GET"])
@jwt_required()
def get_template(template_id):
    try:
        # Query the template from the database, or return 404 if not found
        template = TemplateManager.query.filter_by(id=template_id).first_or_404()

        # Read the template and parameter content from file
        template_content = read_file(
            os.path.join(
                current_app.static_folder,
                RAW_TEMPLATE_FOLDER,
                template.template_name,
            )
        )
        parameter_content = read_file(
            os.path.join(
                current_app.static_folder,
                RAW_TEMPLATE_FOLDER,
                template.parameter_name,
            )
        )

        # Check if files exist
        if template_content is None:
            current_app.logger.error(
                f"Template content not found for: {template.template_name}"
            )
            return jsonify({"error": "Template content tidak ditemukan."}), 500

        if parameter_content is None:
            current_app.logger.error(
                f"Parameter content not found for: {template.parameter_name}"
            )
            return jsonify({"error": "Parameter content tidak ditemukan."}), 500

        # Add file content to the template object
        template.template_content = template_content
        template.parameter_content = parameter_content

        # Serialize the template data using Marshmallow
        result = template_schema.dump(template)

        current_app.logger.info(
            f"Template details retrieved successfully: {template_id}"
        )
        return jsonify(result), 200

    except Exception as e:
        current_app.logger.error(f"Error retrieving template details: {e}")
        return (
            jsonify({"error": "Terjadi kesalahan saat mengambil detail template."}),
            500,
        )


@restapi_bp.route("/api/create-template", methods=["POST"])
@jwt_required()
def create_template():
    # Mengambil identitas pengguna dari JWT
    user_identity = get_jwt_identity()

    current_app.logger.info(f"Attempting API create template by {user_identity}")

    try:
        # Memeriksa apakah request menggunakan form data atau JSON
        if request.is_json:
            data = request.get_json()
            vendor = data.get("vendor")
            version = data.get("version")
            description = data.get("description")
            template_content = (
                data.get("template_content", "")
                .replace("\r\n", "\n")
                .replace("\r", "\n")
                .strip()
            )
            parameter_content = (
                data.get("parameter_content", "")
                .replace("\r\n", "\n")
                .replace("\r", "\n")
                .strip()
            )
        else:
            if not all(
                key in request.form
                for key in [
                    "vendor",
                    "version",
                    "description",
                    "template_content",
                    "parameter_content",
                ]
            ):
                return jsonify({"error": "Data yang diperlukan tidak lengkap."}), 400

            vendor = request.form["vendor"]
            version = request.form["version"]
            description = request.form["description"]
            template_content = (
                request.form["template_content"]
                .replace("\r\n", "\n")
                .replace("\r", "\n")
                .strip()
            )
            parameter_content = (
                request.form["parameter_content"]
                .replace("\r\n", "\n")
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

        # Simpan template content ke file
        with open(template_path, "w", encoding="utf-8") as template_file:
            template_file.write(template_content)
        current_app.logger.info(
            f"Successfully saved template content to file: {template_path}"
        )

        # Simpan parameter content ke file
        with open(parameter_path, "w", encoding="utf-8") as parameter_file:
            parameter_file.write(parameter_content)
        current_app.logger.info(
            f"Successfully saved parameter content to file: {parameter_path}"
        )

        # Simpan template baru ke database
        new_template = TemplateManager(
            template_name=template_filename,
            parameter_name=parameter_filename,
            vendor=vendor,
            version=version,
            description=description,
            created_by=user_identity,
        )
        db.session.add(new_template)
        db.session.commit()

        current_app.logger.info(
            f"Successfully added new template by {user_identity} at {datetime.now().strftime('%d:%m:%Y %H:%M:%S')}"
        )
        return (
            jsonify(
                {"message": "Template berhasil dibuat.", "template_id": new_template.id}
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error creating template for user {user_identity}: {e}"
        )
        return (
            jsonify(
                {
                    "error": "Terjadi kesalahan saat membuat template. Silakan coba lagi nanti."
                }
            ),
            500,
        )


@restapi_bp.route("/api/update-template/<template_id>", methods=["PUT"])
@jwt_required()
def update_template(template_id):
    """API Endpoint untuk memperbarui template berdasarkan ID, mendukung form data dan JSON."""

    # Mengambil user identity dari JWT token
    user_identity = get_jwt_identity()

    try:
        # Ambil template berdasarkan ID
        template = TemplateManager.query.get_or_404(template_id)
        current_app.logger.info(
            f"Accessed template update for template_id: {template_id}"
        )

        # Membaca konten template dan parameter saat ini dari file
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

        # Cek apakah konten file ada
        if template_content is None or parameter_content is None:
            return (
                jsonify({"error": "Gagal memuat konten template atau parameter."}),
                500,
            )

        # Menangani data JSON atau Form Data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        # Ambil data dari request (baik JSON atau Form Data)
        new_template_name = secure_filename(
            data.get("template_name", template.template_name)
        )
        new_parameter_name = secure_filename(
            data.get("parameter_name", template.parameter_name)
        )
        new_vendor = data.get("vendor", template.vendor)
        new_version = data.get("version", template.version)
        new_description = data.get("description", template.description)
        new_template_content = (
            data.get("template_content", template_content).replace("\r\n", "\n").strip()
        )
        new_parameter_content = (
            data.get("parameter_content", parameter_content)
            .replace("\r\n", "\n")
            .strip()
        )

        # Cek keunikan nama template dan parameter
        if TemplateManager.query.filter(
            TemplateManager.template_name == new_template_name,
            TemplateManager.id != template.id,
        ).first():
            return (
                jsonify({"error": f"Nama template '{new_template_name}' sudah ada."}),
                400,
            )

        if TemplateManager.query.filter(
            TemplateManager.parameter_name == new_parameter_name,
            TemplateManager.id != template.id,
        ).first():
            return (
                jsonify({"error": f"Nama parameter '{new_parameter_name}' sudah ada."}),
                400,
            )

        # Simpan perubahan konten file jika ada perubahan
        if new_template_content != template_content:
            template_path = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
            )
            with open(template_path, "w", encoding="utf-8") as file:
                file.write(new_template_content)
            current_app.logger.info(
                f"Template content updated: {template.template_name}"
            )

        if new_parameter_content != parameter_content:
            parameter_path = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
            )
            with open(parameter_path, "w", encoding="utf-8") as file:
                file.write(new_parameter_content)
            current_app.logger.info(
                f"Parameter content updated: {template.parameter_name}"
            )

        # Ganti nama file jika nama template atau parameter berubah
        if new_template_name != template.template_name:
            new_path_template = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, new_template_name
            )
            old_path_template = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
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
                current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
            )
            os.rename(old_path_parameter, new_path_parameter)
            template.parameter_name = new_parameter_name
            current_app.logger.info(
                f"Parameter file renamed from {template.parameter_name} to {new_parameter_name}"
            )

        # Update field lain pada template
        template.vendor = new_vendor
        template.version = new_version
        template.description = new_description

        # Commit perubahan ke database
        db.session.commit()
        current_app.logger.info(f"Template updated successfully: {template_id}")

        # Return response sukses
        return jsonify({"message": "Template berhasil diperbarui."}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error updating template for user {user_identity}: {e}"
        )
        return jsonify({"error": "Gagal memperbarui template."}), 500


@restapi_bp.route("/api/delete-template/<template_id>", methods=["DELETE"])
@jwt_required()
def delete_template(template_id):
    """API Endpoint untuk menghapus template berdasarkan ID."""

    # Mengambil user identity dari JWT token
    user_identity = get_jwt_identity()

    try:
        # Ambil template berdasarkan ID
        template = TemplateManager.query.get_or_404(template_id)

        # Tentukan path untuk file template dan parameter
        template_file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
        )
        parameter_file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
        )

        # Hapus file template jika ada
        if os.path.exists(template_file_path):
            os.remove(template_file_path)
            current_app.logger.info(
                f"Template file deleted: {template_file_path} by {user_identity}"
            )
        else:
            current_app.logger.warning(
                f"Template file not found for deletion: {template_file_path} by {user_identity}"
            )

        # Hapus file parameter jika ada
        if os.path.exists(parameter_file_path):
            os.remove(parameter_file_path)
            current_app.logger.info(
                f"Parameter file deleted: {parameter_file_path} by {user_identity}"
            )
        else:
            current_app.logger.warning(
                f"Parameter file not found for deletion: {parameter_file_path} by {user_identity}"
            )

        # Hapus template dari database
        db.session.delete(template)
        db.session.commit()
        current_app.logger.info(
            f"Template with ID {template_id} successfully deleted by {user_identity}"
        )

        # Return response sukses
        return jsonify({"message": "Template berhasil dihapus."}), 200

    except OSError as os_error:
        current_app.logger.error(
            f"OS error while deleting files for template ID {template_id}: {os_error} by {user_identity}"
        )
        db.session.rollback()
        return jsonify({"error": "Terjadi kesalahan sistem saat menghapus file."}), 500

    except Exception as e:
        current_app.logger.error(
            f"Unexpected error while deleting template ID {template_id}: {e} by {user_identity}"
        )
        db.session.rollback()
        return jsonify({"error": "Gagal menghapus template. Silakan coba lagi."}), 500


@restapi_bp.route("/api/generate-template/<template_id>", methods=["POST"])
@jwt_required()
def generate_template(template_id):
    """API Endpoint untuk generate, render, dan menyimpan template berdasarkan ID."""

    # Mengambil user identity dari JWT token
    user_identity = get_jwt_identity()

    try:
        # Ambil template berdasarkan ID
        template = TemplateManager.query.get_or_404(template_id)
        vendor = template.vendor

        # Tentukan path untuk file Jinja template dan YAML parameter
        jinja_template_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
        )
        yaml_params_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
        )

        # Membaca konten file Jinja template dan YAML parameter
        jinja_template = read_file(jinja_template_path)
        yaml_params = read_file(yaml_params_path)

        # Cek apakah file berhasil dibaca
        if jinja_template is None or yaml_params is None:
            current_app.logger.error(
                f"Failed to load template or parameter content for template ID {template_id} by {user_identity}."
            )
            return (
                jsonify({"error": "Gagal memuat konten template atau parameter."}),
                500,
            )

        current_app.logger.info(
            f"Successfully read Jinja template and YAML parameters for template ID {template_id} by {user_identity}."
        )

        # Render konfigurasi menggunakan ConfigurationManagerUtils
        net_auto = ConfigurationManagerUtils(
            ip_address="0.0.0.0", username="none", password="none", ssh=22
        )
        rendered_config = net_auto.render_template_config(jinja_template, yaml_params)
        current_app.logger.info(
            f"Successfully rendered Jinja template for template ID {template_id} by {user_identity}."
        )

        # Validasi template menggunakan OpenAI
        current_app.logger.info(
            f"Validating rendered template with OpenAI for template ID {template_id} by {user_identity}..."
        )
        config_validated = validate_generated_template_with_openai(
            config=rendered_config, vendor=vendor
        )

        if not config_validated.get("is_valid"):
            error_message = config_validated.get("error_message")
            current_app.logger.error(
                f"Template validation failed for template ID {template_id} by {user_identity}. Error: {error_message}"
            )
            return jsonify({"is_valid": False, "error_message": error_message}), 400

    except Exception as e:
        current_app.logger.error(
            f"Error rendering or validating template ID {template_id} by {user_identity}: {e}"
        )
        return jsonify({"error": f"Gagal merender atau memvalidasi template: {e}"}), 500

    try:
        # Generate filename untuk menyimpan hasil template yang digenerate
        gen_filename = generate_random_filename(template.vendor)
        new_file_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, f"{gen_filename}.txt"
        )

        # Simpan konfigurasi yang sudah dirender ke dalam file
        with open(new_file_path, "w", encoding="utf-8") as new_file:
            new_file.write(rendered_config)
        current_app.logger.info(
            f"Successfully saved rendered config to file: {new_file_path} for template ID {template_id} by {user_identity}."
        )

        # Simpan detail konfigurasi yang sudah digenerate ke dalam database
        new_template_generate = ConfigurationManager(
            config_name=gen_filename,
            description=f"{gen_filename} created by {user_identity}",
            created_by=user_identity,
            user_id=user_identity,
            vendor=vendor,
        )
        db.session.add(new_template_generate)
        db.session.commit()
        current_app.logger.info(
            f"Successfully saved generated template to database: {gen_filename} for template ID {template_id} by {user_identity}."
        )

        # Return response sukses
        return (
            jsonify({"is_valid": True, "message": "Template berhasil digenerate."}),
            201,
        )

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Error saving rendered config or template to database for template ID {template_id} by {user_identity}: {e}"
        )
        return (
            jsonify({"error": f"Gagal menyimpan konfigurasi atau template: {e}"}),
            500,
        )


# -----------------------------------------------------------
# API Configuration File Management
# -----------------------------------------------------------


@restapi_bp.route("/api/get-configfiles", methods=["GET"])
@jwt_required()
def get_configfiles():
    configfiles_list = ConfigurationManager.query.all()
    result = configfiles_schema.dump(configfiles_list)
    return jsonify(result)


@restapi_bp.route("/api/get-configfile/<config_id>", methods=["GET"])
@jwt_required()
def get_configfile(config_id):
    try:
        # Query the template from the database, or return 404 if not found
        config = ConfigurationManager.query.filter_by(id=config_id).first_or_404()

        # Read the template and parameter content from file
        config_content = read_file(
            os.path.join(
                current_app.static_folder,
                GEN_TEMPLATE_FOLDER,
                config.config_name,
            )
        )

        # Check if files exist
        if config_content is None:
            current_app.logger.error(
                f"Config content not found for: {config.config_name}"
            )
            return jsonify({"error": "Config content tidak ditemukan."}), 500

        # Add file content to the template object
        config.config_content = config_content

        # Serialize the template data using Marshmallow
        result = configfile_schema.dump(config)

        current_app.logger.info(f"Config details retrieved successfully: {config_id}")
        return jsonify(result), 200

    except Exception as e:
        current_app.logger.error(f"Error retrieving config details: {e}")
        return (
            jsonify({"error": "Terjadi kesalahan saat mengambil detail config."}),
            500,
        )


@restapi_bp.route("/api/create-manual-configfile", methods=["POST"])
@jwt_required()
def create_manual_configfile():
    # Mengambil identitas pengguna dari JWT
    user_identity = get_jwt_identity()

    current_app.logger.info(f"Attempting API create configfile by {user_identity}")

    try:
        # Memeriksa apakah request menggunakan form data atau JSON
        if request.is_json:
            data = request.get_json()
            config_name = data.get("config_name")
            vendor = data.get("vendor")
            description = data.get("description")
            config_content = (
                data.get("config_content", "")
                .replace("\r\n", "\n")
                .replace("\r", "\n")
                .strip()
            )
        else:
            if not all(
                key in request.form
                for key in [
                    "config_name",
                    "vendor",
                    "description",
                    "config_content",
                ]
            ):
                return jsonify({"error": "Data yang diperlukan tidak lengkap."}), 400

            config_name = request.form["config_name"]
            vendor = request.form["vendor"]
            description = request.form["description"]
            config_content = (
                request.form["config_content"]
                .replace("\r\n", "\n")
                .replace("\r", "\n")
                .strip()
            )

        # Generate filenames for saving the content
        gen_filename = generate_random_filename(vendor)
        config_filename = f"{config_name}_{gen_filename}"

        config_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, config_filename
        )

        config_validated = validate_generated_template_with_openai(
            config=config_content, vendor=vendor
        )

        if config_validated.get("is_valid"):
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            # Simpan config content ke file
            with open(config_path, "w", encoding="utf-8") as config_file:
                config_file.write(config_content)
            current_app.logger.info(
                f"Successfully saved config content to file: {config_path}"
            )

            # Simpan template baru ke database
            new_config = ConfigurationManager(
                config_name=config_filename,
                vendor=vendor,
                description=description,
                created_by=user_identity,
                user_id=None,
            )
            db.session.add(new_config)
            db.session.commit()

            current_app.logger.info(
                f"Successfully added new config by {user_identity} at {datetime.now().strftime('%d:%m:%Y %H:%M:%S')}"
            )
            return (
                jsonify(
                    {"message": "Config berhasil dibuat.", "config_id": new_config.id}
                ),
                201,
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
        current_app.logger.error(f"Error creating config for user {user_identity}: {e}")
        return (
            jsonify(
                {
                    "error": "Terjadi kesalahan saat membuat configfile. Silakan coba lagi nanti."
                }
            ),
            500,
        )
