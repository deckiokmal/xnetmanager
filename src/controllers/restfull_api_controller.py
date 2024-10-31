from flask import (
    Blueprint,
    jsonify,
    current_app,
    request,
    copy_current_request_context,
)
from src import db, bcrypt
from src.models.app_models import (
    DeviceManager,
    User,
    Role,
    TemplateManager,
    ConfigurationManager,
    BackupData,
    UserBackupShare,
    BackupTag,
    BackupAuditLog,
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
    backup_schema,
    backups_schema,
)
from flask_jwt_extended import (
    jwt_required,
    create_access_token,
    get_jwt_identity,
    get_jwt,
)
from datetime import datetime
import random
import string
from werkzeug.utils import secure_filename
import os
from src.utils.openai_utils import (
    validate_generated_template_with_openai,
    create_configuration_with_openai,
)
from src.utils.talita_ai_utils import generate_configfile_talita
from src.utils.config_manager_utils import ConfigurationManagerUtils
import time
from .decorators import jwt_role_required
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from src.utils.backupUtils import BackupUtils

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
    # Mendapatkan data login dari request
    if request.is_json:
        email = request.json.get("email")
        password = request.json.get("password")
    else:
        email = request.form.get("email")
        password = request.form.get("password")

    # Mencari pengguna berdasarkan email
    user = User.query.filter_by(email=email).first()

    # Validasi pengguna dan password
    if user and bcrypt.check_password_hash(user.password_hash, password):
        # Mengumpulkan role dan permission dari user
        user_roles = [role.name for role in user.roles]
        user_permissions = set()

        # Mengumpulkan permissions berdasarkan role yang dimiliki user
        for role in user.roles:
            user_permissions.update(permission.name for permission in role.permissions)

        # Membuat token akses dengan additional_claims untuk role dan permission
        additional_claims = {
            "roles": user_roles,
            "permissions": list(
                user_permissions
            ),  # Dikonversi ke list untuk JSON serialization
        }
        access_token = create_access_token(
            identity={"user_id": user.id, "email": user.email},
            additional_claims=additional_claims,
        )

        # Logging aktivitas login
        current_app.logger.info(
            f"User {email} Login via API at {datetime.now().strftime('%d:%m:%Y %H:%M:%S')}"
        )
        return jsonify(message="Login Sukses.", access_token=access_token)
    else:
        # Respon jika login gagal
        return jsonify(message="Email atau Password salah."), 401


# -----------------------------------------------------------
# API User Management
# -----------------------------------------------------------


@restapi_bp.route("/api/get-users", methods=["GET"])
@jwt_required()
@jwt_role_required(
    roles=["Admin"], permissions=["Manage Users"], page="Users Management"
)
def get_users():
    users_list = User.query.all()
    result = users_schema.dump(users_list)
    return jsonify(result)


@restapi_bp.route("/api/get-user/<user_id>", methods=["GET"])
@jwt_required()
@jwt_role_required(
    roles=["Admin"], permissions=["Manage Users"], page="Users Management"
)
def get_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        result = user_schema.dump(user)
        return jsonify(result)
    else:
        return jsonify(message="User tidak ditemukan."), 404


@restapi_bp.route("/api/create-user", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin"], permissions=["Manage Users"], page="Users Management"
)
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
@jwt_role_required(
    roles=["Admin"], permissions=["Manage Users"], page="Users Management"
)
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
@jwt_role_required(
    roles=["Admin"], permissions=["Manage Users"], page="Users Management"
)
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
@jwt_role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Devices", "View Devices"],
    page="Devices Management",
)
def get_devices():
    devices_list = DeviceManager.query.all()
    result = devices_schema.dump(devices_list)
    return jsonify(result)


@restapi_bp.route("/api/get-device/<device_id>", methods=["GET"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Devices", "View Devices"],
    page="Devices Management",
)
def get_device(device_id):
    device = DeviceManager.query.filter_by(id=device_id).first()
    if device:
        result = device_schema.dump(device)
        return jsonify(result)
    else:
        return jsonify(message="Device tidak ditemukan."), 404


@restapi_bp.route("/api/create-device", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def create_device():
    # Mengambil identitas pengguna dari JWT
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    user_identity = jwt_data.get("email")

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
            user_id=user_id,
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
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def update_device():
    # Mengambil identitas pengguna dari JWT
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    user_identity = jwt_data.get("email")

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
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
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
@jwt_role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Templates", "View Templates"],
    page="Templates Management",
)
def get_templates():
    templates_list = TemplateManager.query.all()
    result = templates_schema.dump(templates_list)
    return jsonify(result)


@restapi_bp.route("/api/get-template/<template_id>", methods=["GET"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Templates", "View Templates"],
    page="Templates Management",
)
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
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
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
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
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
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
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
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Manage Templates"],
    page="Templates Management",
)
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
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def get_configfiles():
    configfiles_list = ConfigurationManager.query.all()
    result = configfiles_schema.dump(configfiles_list)
    return jsonify(result)


@restapi_bp.route("/api/get-configfile/<config_id>", methods=["GET"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
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
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def create_manual_configfile():
    # Mengambil identitas pengguna dari JWT
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    user_identity = jwt_data.get("email")

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
                user_id=user_id,
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


@restapi_bp.route("/api/create-automate-configfile", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def create_automate_configfile():
    # Mengambil identitas pengguna dari JWT
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    user_identity = jwt_data.get("email")

    current_app.logger.info(
        f"Attempting API create automate configfile by {user_identity}"
    )

    try:
        # Mengambil data dari request JSON atau form
        data = request.get_json() if request.is_json else request.form

        # Validasi input
        required_fields = ["config_name", "vendor", "description", "ask_configuration"]
        missing_fields = [field for field in required_fields if field not in data]

        if missing_fields:
            current_app.logger.warning(f"Missing required fields: {missing_fields}")
            return (
                jsonify(
                    {
                        "is_valid": False,
                        "error": f"Data yang diperlukan tidak lengkap: {', '.join(missing_fields)}",
                    }
                ),
                400,
            )

        config_name = data.get("config_name")
        vendor = data.get("vendor")
        description = data.get("description")
        ask_configuration = data.get("ask_configuration")

        # Generate nama file
        gen_filename = generate_random_filename(vendor)
        config_filename = f"{config_name}_{gen_filename}"
        config_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, config_filename
        )

        # Generate konfigurasi otomatis menggunakan OpenAI
        configuration_content, error = create_configuration_with_openai(
            question=ask_configuration, vendor=vendor
        )
        if error:
            current_app.logger.error(f"AI configuration error: {error}")
            return jsonify({"is_valid": False, "error": error}), 400

        # Simpan konfigurasi ke file
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as configuration_file:
            configuration_file.write(configuration_content)

        # Simpan konfigurasi ke database
        new_configuration = ConfigurationManager(
            config_name=config_filename,
            vendor=vendor,
            description=description,
            created_by=user_identity,
            user_id=user_id,  # Disesuaikan jika ID pengguna relevan
        )
        db.session.add(new_configuration)
        db.session.commit()

        current_app.logger.info(
            f"Successfully created AI-generated configuration by {user_identity}"
        )
        return (
            jsonify(
                {
                    "is_valid": True,
                    "message": "Konfigurasi berhasil dibuat dengan AI",
                    "config_id": new_configuration.id,
                    "configuration_content": configuration_content,
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating configuration file: {e}")
        return (
            jsonify(
                {"is_valid": False, "error": "Failed to create configuration file."}
            ),
            500,
        )


from flask import jsonify, current_app, request
from werkzeug.utils import secure_filename
from sqlalchemy.exc import SQLAlchemyError
import os


@restapi_bp.route("/api/create-automate-configfile-talita", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def create_automate_configfile_talita():
    # Mengambil identitas pengguna dari JWT
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    user_identity = jwt_data.get("email")

    current_app.logger.info(
        f"User {user_identity} initiated TALITA configuration creation via API."
    )

    try:
        # Mengambil data dari request JSON atau form
        data = request.get_json() if request.is_json else request.form

        # Validasi input dan cek kelengkapan field
        required_fields = ["config_name", "vendor", "description", "ask_configuration"]
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            current_app.logger.warning(f"Missing required fields: {missing_fields}")
            return (
                jsonify(
                    {
                        "is_valid": False,
                        "error": f"Data yang diperlukan tidak lengkap: {', '.join(missing_fields)}",
                    }
                ),
                400,
            )

        # Ekstraksi data input
        config_name = data.get("config_name")
        vendor = data.get("vendor")
        description = data.get("description")
        ask_configuration = data.get("ask_configuration")

        # Membuat konteks pertanyaan untuk API TALITA
        context = (
            f"Berikan hanya sintaks konfigurasi yang tepat untuk {vendor}.\n"
            f"Hanya sertakan perintah konfigurasi yang spesifik untuk vendor {vendor}.\n"
            f"Hasil response hanya berupa plaintext tanpa adanya text formatting.\n"
            f"Jawaban harus sesuai context yang telah diberikan. Jika context tidak tersedia jawab dengan 'Gagal'.\n"
            f"Jika 'Gagal' jelaskan penyebabnya.\n"
            f"Pertanyaan: {ask_configuration}\n"
        )

        current_app.logger.info(
            f"Requesting TALITA API for configuration generation by user {user_identity}."
        )

        # Meminta TALITA untuk menghasilkan konfigurasi
        result = generate_configfile_talita(context, str(user_id))
        if not result["success"]:
            current_app.logger.warning(
                f"TALITA API request failed for {user_identity}: {result['message']}"
            )
            return jsonify({"is_valid": False, "error": result["message"]}), 502

        talita_answer = result["message"]

        # Cek jika TALITA mengembalikan pesan "Gagal"
        if talita_answer.lower().startswith("gagal"):
            current_app.logger.warning(
                f"TALITA response 'Gagal' for user {user_identity}."
            )
            return jsonify({"is_valid": False, "error": talita_answer}), 400

        # Membuat nama file dan path penyimpanan
        gen_filename = generate_random_filename(config_name)
        config_filename = secure_filename(f"{config_name}_{gen_filename}.txt")
        config_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, config_filename
        )

        # Menyimpan konfigurasi ke file
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as configuration_file:
            configuration_file.write(talita_answer)

        # Menyimpan informasi konfigurasi ke database
        new_configuration = ConfigurationManager(
            config_name=config_filename,
            vendor=vendor,
            description=description,
            created_by=user_identity,
            user_id=user_id,
        )
        db.session.add(new_configuration)
        db.session.commit()

        current_app.logger.info(
            f"Configuration '{config_filename}' created successfully by {user_identity}."
        )
        return (
            jsonify(
                {
                    "is_valid": True,
                    "message": "Konfigurasi berhasil dibuat dengan AI",
                    "config_id": new_configuration.id,
                    "configuration_content": talita_answer,
                }
            ),
            201,
        )

    except SQLAlchemyError as e:
        # Rollback jika terjadi error database dan log kesalahan
        db.session.rollback()
        current_app.logger.error(f"Database error for {user_identity}: {str(e)}")
        # Hapus file jika terjadi error setelah penulisan file
        if os.path.exists(config_path):
            os.remove(config_path)
        return (
            jsonify(
                {
                    "is_valid": False,
                    "error": "Database error occurred. Unable to save configuration.",
                }
            ),
            500,
        )

    except Exception as e:
        # Penanganan error umum dan log kesalahan
        db.session.rollback()
        current_app.logger.error(f"Unexpected error for {user_identity}: {str(e)}")
        # Hapus file jika terjadi error setelah penulisan file
        if os.path.exists(config_path):
            os.remove(config_path)
        return (
            jsonify(
                {
                    "is_valid": False,
                    "error": "An unexpected error occurred. Failed to create configuration file.",
                }
            ),
            500,
        )


@restapi_bp.route("/api/update-configfile/<config_id>", methods=["PUT"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def update_configfile(config_id):
    """API Endpoint untuk memperbarui configfile berdasarkan ID, mendukung form data dan JSON."""

    # Mengambil identitas pengguna dari JWT
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    user_identity = jwt_data.get("email")

    try:
        # Ambil konfigurasi berdasarkan ID atau kembalikan 404 jika tidak ada
        config = ConfigurationManager.query.get_or_404(config_id)
        current_app.logger.info(f"Accessed config update for config_id: {config_id}")

        # Membaca konten konfigurasi file saat ini
        config_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, config.config_name
        )
        config_content = read_file(config_path)

        if config_content is None:
            current_app.logger.error(f"Config content not found for ID {config_id}")
            return (
                jsonify({"is_valid": False, "error": "Gagal memuat konten config."}),
                500,
            )

        # Menangani data JSON atau Form Data
        data = request.get_json() if request.is_json else request.form

        # Validasi input dan pengambilan data baru dari request
        required_fields = ["config_name", "vendor", "description", "config_content"]
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            current_app.logger.warning(f"Missing fields: {missing_fields}")
            return (
                jsonify(
                    {
                        "is_valid": False,
                        "error": f"Data yang diperlukan tidak lengkap: {', '.join(missing_fields)}",
                    }
                ),
                400,
            )

        new_config_name = secure_filename(data.get("config_name", config.config_name))
        new_vendor = data.get("vendor", config.vendor)
        new_description = data.get("description", config.description)
        new_config_content = (
            data.get("config_content", config_content).replace("\r\n", "\n").strip()
        )

        # Cek keunikan nama file konfigurasi
        existing_config = ConfigurationManager.query.filter(
            ConfigurationManager.config_name == new_config_name,
            ConfigurationManager.id != config.id,
        ).first()
        if existing_config:
            current_app.logger.warning(
                f"Config name '{new_config_name}' already exists."
            )
            return (
                jsonify(
                    {
                        "is_valid": False,
                        "error": f"Nama config '{new_config_name}' sudah ada.",
                    }
                ),
                400,
            )

        # Perbarui konten file jika berubah
        if new_config_content != config_content:
            with open(config_path, "w", encoding="utf-8") as file:
                file.write(new_config_content)
            current_app.logger.info(f"Config content updated for ID {config_id}")

        # Perbarui nama file jika berubah
        if new_config_name != config.config_name:
            new_path = os.path.join(
                current_app.static_folder, GEN_TEMPLATE_FOLDER, new_config_name
            )
            os.rename(config_path, new_path)
            config.config_name = new_config_name
            current_app.logger.info(
                f"Config filename changed from {config.config_name} to {new_config_name}"
            )

        # Perbarui field vendor dan description di database
        config.vendor = new_vendor
        config.description = new_description

        # Commit perubahan ke database
        db.session.commit()
        current_app.logger.info(f"Config updated successfully for ID {config_id}")

        # Return response sukses
        return (
            jsonify(
                {"is_valid": True, "message": "Configuration File berhasil diperbarui."}
            ),
            200,
        )

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating config for user {user_identity}: {e}")
        return jsonify({"is_valid": False, "error": "Gagal memperbarui config."}), 500


@restapi_bp.route("/api/delete-config/<config_id>", methods=["DELETE"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Manage Configuration File"],
    page="Configuration File Management",
)
def delete_config(config_id):
    """API Endpoint untuk menghapus config berdasarkan ID."""

    # Mengambil identitas pengguna dari JWT
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    user_identity = jwt_data.get("email")

    try:
        # Ambil config berdasarkan ID
        config = ConfigurationManager.query.get_or_404(config_id)

        # Tentukan path untuk file config
        config_file_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, config.config_name
        )

        # Hapus file config jika ada
        if os.path.exists(config_file_path):
            os.remove(config_file_path)
            current_app.logger.info(
                f"config file deleted: {config_file_path} by {user_identity}"
            )
        else:
            current_app.logger.warning(
                f"config file not found for deletion: {config_file_path} by {user_identity}"
            )

        # Hapus config dari database
        db.session.delete(config)
        db.session.commit()
        current_app.logger.info(
            f"config with ID {config_id} successfully deleted by {user_identity}"
        )

        # Return response sukses
        return jsonify({"message": "config berhasil dihapus."}), 200

    except OSError as os_error:
        current_app.logger.error(
            f"OS error while deleting files for config ID {config_id}: {os_error} by {user_identity}"
        )
        db.session.rollback()
        return jsonify({"error": "Terjadi kesalahan sistem saat menghapus file."}), 500

    except Exception as e:
        current_app.logger.error(
            f"Unexpected error while deleting config ID {config_id}: {e} by {user_identity}"
        )
        db.session.rollback()
        return jsonify({"error": "Gagal menghapus config. Silakan coba lagi."}), 500


# -----------------------------------------------------------
# API Push & Backup Configuration
# -----------------------------------------------------------


# Cache status perangkat untuk menghindari pengecekan berulang
STATUS_CACHE_TTL = 60  # seconds
device_status_cache = {}


# Fungsi caching sederhana
def get_cached_device_status(device_id):
    cached = device_status_cache.get(device_id)
    if cached and (time.time() - cached["timestamp"]) < STATUS_CACHE_TTL:
        return cached["status"]
    return None


def set_device_status_cache(device_id, status):
    device_status_cache[device_id] = {"status": status, "timestamp": time.time()}


@restapi_bp.route("/api/check_status", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Config and Backup"], page="Config Management"
)
def check_status():
    jwt_data = get_jwt()
    roles = jwt_data.get("roles", [])
    user_id = jwt_data.get("user_id")

    try:
        # Validasi parameter page dan per_page untuk memastikan integer positif
        page = request.json.get("page", 1)
        per_page = request.json.get("per_page", 10)
        if not (isinstance(page, int) and page > 0) or not (
            isinstance(per_page, int) and per_page > 0
        ):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "code": "INVALID_PAGINATION",
                            "message": "Page and per_page must be positive integers.",
                        },
                    }
                ),
                400,
            )

        search_query = request.json.get("search_query", "").lower().strip()

        if "Admin" in roles:
            devices_query = DeviceManager.query
        else:
            devices_query = DeviceManager.query.filter_by(user_id=user_id)

        # Filter perangkat jika ada search query
        if search_query:
            devices_query = devices_query.filter(
                DeviceManager.device_name.ilike(f"%{search_query}%")
                | DeviceManager.ip_address.ilike(f"%{search_query}%")
                | DeviceManager.vendor.ilike(f"%{search_query}%")
            )

        # Pagination untuk devices
        devices = devices_query.limit(per_page).offset((page - 1) * per_page).all()

        # Menangani kondisi jika tidak ada perangkat yang ditemukan
        if not devices:
            return jsonify({"success": False, "message": "Device not found."}), 404

        device_status = {}

        # Fungsi pengecekan status perangkat
        def check_device_status(device):
            cached_status = get_cached_device_status(device.id)
            if cached_status:
                logging.info(f"Using cached status for device {device.device_name}")
                return device.id, cached_status

            utils = ConfigurationManagerUtils(ip_address=device.ip_address)
            status_json = utils.check_device_status()
            status_dict = json.loads(status_json)

            # Cache hasil status
            set_device_status_cache(device.id, status_dict["status"])
            return device.id, status_dict["status"]

        # Gunakan ThreadPoolExecutor untuk pengecekan paralel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(check_device_status, device): device
                for device in devices
            }

            for future in as_completed(futures):
                device = futures[
                    future
                ]  # Ambil device dari futures untuk konteks error handling
                try:
                    device_id, status = future.result()
                    device_status[device_id] = status
                except Exception as e:
                    logging.error(
                        f"Error checking status for device {device.device_name}: {e}"
                    )
                    device_status[device.id] = "error"

        return jsonify({"success": True, "data": device_status})

    except Exception as e:
        logging.error(f"Error checking device status: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "code": "DEVICE_STATUS_ERROR",
                        "message": "An error occurred while checking device status.",
                    },
                }
            ),
            500,
        )


from flask_jwt_extended import jwt_required, get_jwt
from concurrent.futures import ThreadPoolExecutor, as_completed


@restapi_bp.route("/api/push_configs", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Config and Backup"], page="Config Push"
)
def push_configs():
    """
    Mengirimkan konfigurasi ke perangkat yang dipilih secara paralel.
    Fitur: Memvalidasi input, membaca file konfigurasi, dan push konfigurasi ke beberapa perangkat.
    """
    data = request.get_json()
    device_ips = data.get("devices", [])
    config_id = data.get("config_id")

    # Validasi input
    if not device_ips:
        return jsonify({"success": False, "message": "No devices selected."}), 400
    if not config_id:
        return jsonify({"success": False, "message": "No config selected."}), 400

    # Ambil data JWT untuk peran dan ID pengguna
    jwt_data = get_jwt()
    roles = jwt_data.get("roles", [])
    user_id = jwt_data.get("user_id")

    # Query perangkat berdasarkan peran pengguna
    if "Admin" in roles:
        devices = DeviceManager.query.filter(
            DeviceManager.ip_address.in_(device_ips)
        ).all()
    else:
        devices = DeviceManager.query.filter(
            DeviceManager.ip_address.in_(device_ips),
            DeviceManager.user_id == user_id,
        ).all()

    # Jika tidak ada perangkat yang ditemukan
    if not devices:
        return (
            jsonify(
                {"success": False, "message": "No devices found for the provided IPs."}
            ),
            404,
        )

    # Query konfigurasi berdasarkan peran pengguna
    if "Admin" in roles:
        config = ConfigurationManager.query.filter_by(id=config_id).first()
    else:
        config = ConfigurationManager.query.filter_by(
            id=config_id, user_id=user_id
        ).first()

    # Jika konfigurasi tidak ditemukan
    if not config:
        return jsonify({"success": False, "message": "Selected config not found."}), 404

    # Membaca file konfigurasi
    def read_config(filename):
        config_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, filename
        )
        try:
            with open(config_path, "r") as file:
                return file.read()
        except FileNotFoundError:
            logging.error("Config file not found: %s", config_path)
            return None
        except Exception as e:
            logging.error("Error reading config file: %s", e)
            return None

    config_content = read_config(config.config_name)
    if not config_content:
        return jsonify({"success": False, "message": "Error reading config."}), 500

    results = []
    success = True

    # Fungsi untuk mengkonfigurasi perangkat
    def configure_device(device):
        nonlocal success
        try:
            config_utils = ConfigurationManagerUtils(
                ip_address=device.ip_address,
                username=device.username,
                password=device.password,
                ssh=device.ssh,
            )
            response_json = config_utils.configure_device(config_content)
            response_dict = json.loads(response_json)
            message = response_dict.get("message", "Konfigurasi sukses")
            status = response_dict.get("status", "success")
            return {
                "device_name": device.device_name,
                "ip": device.ip_address,
                "status": status,
                "message": message,
            }
        except json.JSONDecodeError as e:
            logging.error("Error decoding JSON response: %s", e)
            return {
                "device_name": device.device_name,
                "ip": device.ip_address,
                "status": "error",
                "message": "Error decoding JSON response",
            }
        except Exception as e:
            logging.error("Error configuring device %s: %s", device.ip_address, e)
            return {
                "device_name": device.device_name,
                "ip": device.ip_address,
                "status": "error",
                "message": str(e),
            }

    # Push konfigurasi ke perangkat secara paralel menggunakan threading
    max_threads = 10  # Jumlah maksimal thread yang digunakan
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {
            executor.submit(configure_device, device): device for device in devices
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result["status"] != "success":
                success = False

    return jsonify({"success": success, "results": results})


@restapi_bp.route("/api/push_config/<device_id>", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"],
    permissions=["Config and Backup"],
    page="Config Push Single Device",
)
def push_config_single_device(device_id):
    """
    Mengirimkan konfigurasi ke satu perangkat yang dipilih berdasarkan device_id.
    Fitur: Memvalidasi input, membaca file konfigurasi, dan push konfigurasi ke satu perangkat.
    """
    data = request.get_json()
    config_id = data.get("config_id")

    # Validasi input
    if not config_id:
        return jsonify({"success": False, "message": "No config selected."}), 400

    # Ambil data JWT untuk peran dan ID pengguna
    jwt_data = get_jwt()
    roles = jwt_data.get("roles", [])
    user_id = jwt_data.get("user_id")

    # Query perangkat berdasarkan device_id dan peran user
    if "Admin" in roles:
        device = DeviceManager.query.filter_by(id=device_id).first()
    else:
        device = DeviceManager.query.filter_by(id=device_id, user_id=user_id).first()

    # Jika perangkat tidak ditemukan
    if not device:
        return jsonify({"success": False, "message": "Device not found."}), 404

    # Query konfigurasi berdasarkan peran user
    if "Admin" in roles:
        config = ConfigurationManager.query.filter_by(id=config_id).first()
    else:
        config = ConfigurationManager.query.filter_by(
            id=config_id, user_id=user_id
        ).first()

    # Jika konfigurasi tidak ditemukan
    if not config:
        return jsonify({"success": False, "message": "Selected config not found."}), 404

    # Membaca file konfigurasi
    def read_config(filename):
        config_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, filename
        )
        try:
            with open(config_path, "r") as file:
                return file.read()
        except FileNotFoundError:
            logging.error("Config file not found: %s", config_path)
            return None
        except Exception as e:
            logging.error("Error reading config file: %s", e)
            return None

    config_content = read_config(config.config_name)
    if not config_content:
        return jsonify({"success": False, "message": "Error reading config."}), 500

    # Fungsi untuk mengkonfigurasi perangkat
    def configure_device(device):
        try:
            config_utils = ConfigurationManagerUtils(
                ip_address=device.ip_address,
                username=device.username,
                password=device.password,
                ssh=device.ssh,
            )
            response_json = config_utils.configure_device(config_content)
            response_dict = json.loads(response_json)
            message = response_dict.get("message", "Konfigurasi sukses")
            status = response_dict.get("status", "success")
            return {
                "device_name": device.device_name,
                "ip": device.ip_address,
                "status": status,
                "message": message,
            }
        except json.JSONDecodeError as e:
            logging.error("Error decoding JSON response: %s", e)
            return {
                "device_name": device.device_name,
                "ip": device.ip_address,
                "status": "error",
                "message": "Error decoding JSON response",
            }
        except Exception as e:
            logging.error("Error configuring device %s: %s", device.ip_address, e)
            return {
                "device_name": device.device_name,
                "ip": device.ip_address,
                "status": "error",
                "message": str(e),
            }

    # Push konfigurasi ke perangkat
    result = configure_device(device)
    success = result["status"] == "success"

    return jsonify({"success": success, "result": result}), 200 if success else 500


@restapi_bp.route("/api/create_backup_multiple", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def create_backup_multiple():
    """
    Membuat backup pada beberapa perangkat yang dipilih.
    Fitur: Validasi input, pengecekan vendor perangkat, dan backup konfigurasi perangkat secara paralel.
    """
    try:
        data = request.get_json()
        device_ips = data.get("devices", [])
        backup_name = data.get("backup_name")
        description = data.get("description", "")
        backup_type = data.get("backup_type", "full").lower()  # Konversi ke huruf kecil
        retention_days = data.get("retention_days")
        command = data.get("command")

        # Validasi backup_type
        valid_backup_types = {"full", "incremental", "differential"}
        if backup_type not in valid_backup_types:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Invalid backup type provided. Supported types are: {', '.join(valid_backup_types)}",
                    }
                ),
                400,
            )

        # Validasi input awal
        if not device_ips:
            return jsonify({"success": False, "message": "No devices selected."}), 400

        # Mengambil data JWT untuk akses user_id
        jwt_data = get_jwt()
        user_id = jwt_data.get("user_id")

        # Query perangkat berdasarkan IP yang diberikan
        devices = DeviceManager.query.filter(
            DeviceManager.ip_address.in_(device_ips)
        ).all()

        # Validasi perangkat
        if not devices:
            return jsonify({"success": False, "message": "No devices found."}), 404

        # Pengecekan vendor perangkat harus seragam
        vendors = {device.vendor for device in devices}
        if len(vendors) > 1:
            return (
                jsonify(
                    {"success": False, "message": "Devices must have the same vendor."}
                ),
                400,
            )

        results = []
        success = True

        # Fungsi untuk membuat backup perangkat
        @copy_current_request_context
        def backup_device(device):
            nonlocal success
            try:
                with app.app_context():
                    # Jika backup incremental atau differential dan tidak ada backup sebelumnya, gunakan full backup
                    if backup_type in {"incremental", "differential"}:
                        previous_backup = (
                            BackupData.query.filter_by(
                                device_id=device.id, backup_type=backup_type
                            )
                            .order_by(BackupData.timestamp.desc())
                            .first()
                        )
                        if not previous_backup:
                            logging.info(
                                f"No previous backup found for device {device.device_name}. Performing full backup instead."
                            )
                            backup_type_for_device = "full"
                        else:
                            backup_type_for_device = backup_type
                    else:
                        backup_type_for_device = backup_type

                    # Lakukan backup
                    new_backup = BackupData.create_backup(
                        backup_name=backup_name,
                        description=description,
                        user_id=user_id,
                        device_id=device.id,
                        backup_type=backup_type_for_device,
                        retention_days=retention_days,
                        command=command,
                    )
                    results.append(
                        {
                            "device_name": device.device_name,
                            "ip": device.ip_address,
                            "status": "success",
                            "message": "Backup successful",
                            "backup_id": new_backup.id,
                        }
                    )
            except Exception as e:
                current_app.logger.error(
                    f"Error during backup for {device.ip_address}: {e}"
                )
                success = False
                results.append(
                    {
                        "device_name": device.device_name,
                        "ip": device.ip_address,
                        "status": "error",
                        "message": str(e),
                    }
                )

        # Memulai proses backup secara paralel dengan konteks aplikasi di dalam thread
        app = current_app._get_current_object()
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(backup_device, device): device for device in devices
            }
            for future in as_completed(futures):
                future.result()  # Memastikan semua futures selesai

        return jsonify({"success": success, "results": results}), (
            200 if success else 500
        )

    except Exception as e:
        current_app.logger.error(f"Error creating backup: {e}")
        return (
            jsonify({"success": False, "message": f"Error creating backup: {str(e)}"}),
            500,
        )


@restapi_bp.route("/api/create_backup_single/<int:device_id>", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def create_backup_single(device_id):
    """
    Membuat backup untuk satu perangkat yang dipilih berdasarkan device_id.
    """
    try:
        # Mendapatkan payload JSON dari permintaan
        data = request.get_json()
        backup_name = data.get("backup_name")
        description = data.get("description", "")
        backup_type = data.get("backup_type", "full").lower()  # Konversi ke huruf kecil
        retention_days = data.get("retention_days")
        command = data.get("command")

        # Validasi bahwa backup_name disediakan
        if not backup_name or not backup_name.strip():
            return (
                jsonify({"success": False, "message": "Backup name is required."}),
                400,
            )

        # Mengambil data JWT untuk akses user_id
        jwt_data = get_jwt()
        user_id = jwt_data.get("user_id")
        roles = jwt_data.get("roles", [])

        # Query perangkat berdasarkan ID perangkat
        device = DeviceManager.query.get(device_id)

        # Validasi perangkat
        if not device:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Device with ID {device_id} not found.",
                    }
                ),
                404,
            )

        # Validasi hak akses pengguna
        if "Admin" in roles or device.owner_id == user_id:
            # Validasi backup_type
            valid_backup_types = {"full", "incremental", "differential"}
            if backup_type not in valid_backup_types:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": f"Invalid backup type provided. Supported types are: {', '.join(valid_backup_types)}",
                        }
                    ),
                    400,
                )

            # Lakukan proses backup
            try:
                new_backup = BackupData.create_backup(
                    backup_name=backup_name,
                    description=description,
                    user_id=user_id,
                    device_id=device_id,
                    backup_type=backup_type,
                    retention_days=retention_days,
                    command=command,
                )

                return (
                    jsonify(
                        {
                            "success": True,
                            "message": "Backup created successfully.",
                            "backup_id": new_backup.id,
                            "backup_path": new_backup.backup_path,
                        }
                    ),
                    201,
                )

            except Exception as e:
                current_app.logger.error(
                    f"Error creating backup for device {device.ip_address}: {e}"
                )
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": f"Error creating backup: {str(e)}",
                        }
                    ),
                    500,
                )

        else:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "You do not have permission to back up this device.",
                    }
                ),
                403,
            )

    except Exception as e:
        current_app.logger.error(f"Error processing backup for device {device_id}: {e}")
        return (
            jsonify(
                {"success": False, "message": f"Error processing backup: {str(e)}"}
            ),
            500,
        )


# -----------------------------------------------------------
# API Backup Management
# -----------------------------------------------------------


@restapi_bp.route("/api/get-backups", methods=["GET"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backups Management"
)
def get_backups():
    backups_list = BackupData.query.all()
    result = backups_schema.dump(backups_list)
    return jsonify(result)


@restapi_bp.route("/api/get-backup/<backup_id>", methods=["GET"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def get_backup(backup_id):
    """
    Menampilkan detail backup untuk backup tertentu berdasarkan backup_id.
    Mengatur izin akses dan mengembalikan detail backup jika pengguna memiliki izin.
    """
    # Query backup berdasarkan ID
    backup = BackupData.query.get(backup_id)

    # Cek apakah backup ada
    if not backup:
        return jsonify({"message": "Backup not found"}), 404

    # Mendapatkan level izin akses untuk pengguna
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    roles = jwt_data.get("roles", [])

    if "Admin" in roles or backup.user_id == user_id:
        permission_level = "owner"
    else:
        # Cek apakah pengguna memiliki akses berbagi
        shared_access = UserBackupShare.query.filter_by(
            user_id=user_id, backup_id=backup_id
        ).first()
        if not shared_access:
            return jsonify({"message": "Unauthorized access"}), 403
        permission_level = shared_access.permission_level

    # Membaca konten file backup sesuai level izin
    try:
        if permission_level == "read-only":
            # Hanya membaca backup jika level izin adalah read-only
            backup_content = "Content hidden due to read-only access"
        else:
            backup_content = BackupUtils.read_backup_file(backup.backup_path)
    except FileNotFoundError:
        return jsonify({"message": "Backup file not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error reading backup: {str(e)}"}), 500

    # Serialisasi data backup dengan Marshmallow
    backup_data = backup_schema.dump(backup)
    backup_data["file_content"] = (
        backup_content
        if permission_level != "read-only"
        else "Content hidden due to read-only access"
    )
    backup_data["permission_level"] = permission_level

    # Mengembalikan data backup yang di-serialize
    return jsonify({"success": True, "backup": backup_data}), 200


@restapi_bp.route("/api/update_backup/<backup_id>", methods=["PUT"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def update_backup(backup_id):
    """
    Mengupdate detail backup tertentu berdasarkan backup_id.
    Memerlukan izin akses dan melakukan update jika pengguna memiliki izin.
    """
    try:
        # Mendapatkan data backup dari database berdasarkan backup_id
        backup = BackupData.query.get(backup_id)
        if not backup:
            return jsonify({"success": False, "message": "Backup not found"}), 404

        # Memeriksa izin pengguna, hanya Admin atau pemilik yang diizinkan
        jwt_data = get_jwt()
        user_id = jwt_data.get("user_id")
        roles = jwt_data.get("roles", [])

        if "Admin" not in roles and backup.user_id != user_id:
            return jsonify({"success": False, "message": "Unauthorized access"}), 403

        # Mendapatkan data dari request JSON
        data = request.get_json()
        backup_name = data.get("backup_name", backup.backup_name)
        description = data.get("description", backup.description)
        retention_days = data.get("retention_days", backup.retention_period_days)
        is_encrypted = data.get("is_encrypted", backup.is_encrypted)
        is_compressed = data.get("is_compressed", backup.is_compressed)
        tags = data.get("tags", "")

        # Update data backup
        backup.backup_name = backup_name
        backup.description = description
        backup.retention_period_days = retention_days
        backup.is_encrypted = is_encrypted
        backup.is_compressed = is_compressed

        # Proses pembaruan tags
        new_tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
        backup.tags.clear()
        for tag_text in new_tags:
            tag_instance = BackupTag.query.filter_by(tag=tag_text).first()
            if not tag_instance:
                tag_instance = BackupTag(tag=tag_text)
            backup.tags.append(tag_instance)

        # Commit perubahan ke database
        db.session.commit()

        # Serialisasi data backup yang telah diperbarui
        backup_data = backup_schema.dump(backup)

        # Mengembalikan data backup yang telah diperbarui dalam format JSON
        return (
            jsonify(
                {
                    "success": True,
                    "message": "Backup updated successfully",
                    "backup": backup_data,
                }
            ),
            200,
        )

    except Exception as e:
        current_app.logger.error(f"Error updating backup: {e}")
        db.session.rollback()
        return (
            jsonify({"success": False, "message": f"Error updating backup: {str(e)}"}),
            500,
        )


@restapi_bp.route("/api/delete_backup/<backup_id>", methods=["DELETE"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def delete_backup(backup_id):
    """
    Menghapus backup tertentu berdasarkan backup_id.
    Memerlukan izin akses dan melakukan penghapusan jika pengguna memiliki izin.
    """
    try:
        # Query backup berdasarkan backup_id
        backup = BackupData.query.get(backup_id)

        # Validasi apakah backup ditemukan
        if not backup:
            return jsonify({"success": False, "message": "Backup not found."}), 404

        # Validasi hak akses pengguna, hanya Admin atau pemilik yang diizinkan
        jwt_data = get_jwt()
        user_id = jwt_data.get("user_id")
        roles = jwt_data.get("roles", [])

        if "Admin" not in roles and backup.user_id != user_id:
            return (
                jsonify(
                    {"success": False, "message": "Unauthorized to delete this backup."}
                ),
                403,
            )

        # Menghapus data backup dari database
        db.session.delete(backup)
        db.session.commit()

        # Menghapus file backup dari sistem file (opsional)
        try:
            BackupUtils.delete_backup_file(backup.backup_path)
        except Exception as e:
            current_app.logger.error(f"Error deleting backup file: {e}")
            # Tidak perlu rollback transaksi DB jika penghapusan file gagal, hanya log error

        # Mengembalikan respons sukses
        return (
            jsonify({"success": True, "message": "Backup successfully deleted."}),
            200,
        )

    except Exception as e:
        current_app.logger.error(f"Error deleting backup: {e}")
        db.session.rollback()
        return (
            jsonify({"success": False, "message": f"Error deleting backup: {str(e)}"}),
            500,
        )


@restapi_bp.route("/api/share_backup", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def share_backup():
    """
    Endpoint untuk berbagi backup dengan pengguna lain.
    """
    data = request.get_json()
    user_email_to_share = data.get("user_email")
    backup_id = data.get("backup_id")
    permission_level = data.get("permission_level", "read-only")

    # Log untuk memeriksa data yang diterima
    current_app.logger.info(
        f"User Email: {user_email_to_share}, Backup ID: {backup_id}, Permission Level: {permission_level}"
    )

    # Validasi input
    if not user_email_to_share or not backup_id:
        return (
            jsonify(
                {"success": False, "message": "User Email and Backup ID are required"}
            ),
            400,
        )

    if permission_level not in ["read-only", "edit", "transfer"]:
        return jsonify({"success": False, "message": "Invalid permission level"}), 400

    # Query user berdasarkan email
    user_to_share = User.query.filter_by(email=user_email_to_share).first()
    if not user_to_share:
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"User with email {user_email_to_share} not found",
                }
            ),
            404,
        )

    # Query backup berdasarkan backup_id
    backup = BackupData.query.get(backup_id)
    if not backup:
        return (
            jsonify(
                {"success": False, "message": f"Backup with ID {backup_id} not found"}
            ),
            404,
        )

    # Pastikan bahwa pengguna memiliki backup ini (jika bukan Admin)
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    roles = jwt_data.get("roles", [])

    if "Admin" not in roles and backup.user_id != user_id:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "You do not have permission to share this backup",
                }
            ),
            403,
        )

    # Cek apakah sudah ada share sebelumnya
    existing_share = UserBackupShare.query.filter_by(
        user_id=user_to_share.id, backup_id=backup_id
    ).first()

    if existing_share:
        # Jika sudah dibagikan, perbarui permission level
        existing_share.permission_level = permission_level

        # Jika permission level adalah 'transfer', perbarui kepemilikan backup
        if permission_level == "transfer":
            backup.user_id = user_to_share.id  # Update pemilik backup
            current_app.logger.info(
                f"Backup ownership transferred to {user_to_share.email}"
            )

        db.session.commit()
        return (
            jsonify(
                {
                    "success": True,
                    "message": f"Backup permission updated for user {user_to_share.email} to {permission_level} access",
                }
            ),
            200,
        )

    # Buat record baru di UserBackupShare
    new_share = UserBackupShare(
        user_id=user_to_share.id,
        backup_id=backup_id,
        permission_level=permission_level,
    )

    db.session.add(new_share)

    # Jika permission level adalah 'transfer', perbarui kepemilikan backup
    if permission_level == "transfer":
        backup.user_id = user_to_share.id  # Update pemilik backup
        current_app.logger.info(
            f"Backup ownership transferred to {user_to_share.email}"
        )

    db.session.commit()

    return (
        jsonify(
            {
                "success": True,
                "message": f"Backup shared with user {user_to_share.email} with {permission_level} access",
            }
        ),
        200,
    )


@restapi_bp.route("/api/rollback_backup/<backup_id>", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def rollback_backup(backup_id):
    """
    Melakukan rollback konfigurasi perangkat ke keadaan sebelumnya berdasarkan backup_id.
    """
    # Query backup berdasarkan ID
    backup = BackupData.query.get(backup_id)

    # Validasi apakah backup ada
    if not backup:
        return jsonify({"success": False, "message": "Backup not found"}), 404

    # Validasi hak akses pengguna, hanya Admin atau pemilik backup yang diizinkan
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    roles = jwt_data.get("roles", [])

    if "Admin" not in roles and backup.user_id != user_id:
        return jsonify({"success": False, "message": "Unauthorized access"}), 403

    # Membaca isi backup dari filesystem
    try:
        backup_content = BackupUtils.read_backup_file(backup.backup_path)

        # Melakukan rollback dengan mengirimkan konfigurasi lama ke perangkat
        device = DeviceManager.query.get(backup.device_id)
        if not device:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Device associated with backup not found",
                    }
                ),
                404,
            )

        # Menggunakan isi backup sebagai perintah rollback
        command = backup_content
        config_utils = ConfigurationManagerUtils(
            ip_address=device.ip_address,
            username=device.username,
            password=device.password,
            ssh=device.ssh,
        )

        # Kirim konfigurasi rollback ke perangkat
        result = config_utils.configure_device(command)
        return (
            jsonify(
                {"success": True, "message": "Rollback berhasil", "result": result}
            ),
            200,
        )

    except FileNotFoundError:
        return jsonify({"success": False, "message": "Backup file not found"}), 404
    except Exception as e:
        current_app.logger.error(f"Error during rollback: {e}")
        return (
            jsonify({"success": False, "message": f"Error during rollback: {str(e)}"}),
            500,
        )


############# Utility Backup #####################
def log_action(backup_id, action, user_id):
    """Helper function to log actions related to backups."""
    audit_log = BackupAuditLog(
        backup_id=backup_id,
        action=action,
        performed_by=user_id,
        timestamp=datetime.utcnow(),
    )
    db.session.add(audit_log)
    db.session.commit()


############# Utility Backup #####################


@restapi_bp.route("/api/add_tag_to_backup/<backup_id>", methods=["POST"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def add_tag_to_backup(backup_id):
    """
    Menambahkan tag ke backup tertentu berdasarkan backup_id.
    Memerlukan izin akses dari pemilik backup atau Admin.
    """
    # Query backup berdasarkan backup_id
    backup = BackupData.query.get(backup_id)

    # Validasi apakah backup ada dan pengguna memiliki hak akses
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    roles = jwt_data.get("roles", [])

    if not backup or ("Admin" not in roles and backup.user_id != user_id):
        return (
            jsonify({"success": False, "message": "Backup not found or unauthorized"}),
            404,
        )

    # Mendapatkan data tag dari request JSON
    data = request.get_json()
    tag_text = data.get("tag")
    if not tag_text or not tag_text.strip():
        return jsonify({"success": False, "message": "Tag is required"}), 400

    try:
        # Tambahkan tag baru ke backup
        existing_tag = BackupTag.query.filter_by(
            tag=tag_text, backup_id=backup.id
        ).first()
        if existing_tag:
            return (
                jsonify(
                    {"success": False, "message": "Tag already exists for this backup"}
                ),
                400,
            )

        new_tag = BackupTag(backup_id=backup.id, tag=tag_text.strip())
        db.session.add(new_tag)
        db.session.commit()

        # Catat tindakan di audit log
        log_action(backup.id, "tag_added", user_id)

        return jsonify({"success": True, "message": "Tag added to backup"}), 201
    except Exception as e:
        current_app.logger.error(f"Error adding tag to backup: {e}")
        db.session.rollback()
        return (
            jsonify({"success": False, "message": f"Error adding tag: {str(e)}"}),
            500,
        )


@restapi_bp.route("/api/get_audit_logs/<backup_id>", methods=["GET"])
@jwt_required()
@jwt_role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def get_audit_logs(backup_id):
    """
    Mengambil log audit dari backup tertentu berdasarkan backup_id.
    Memerlukan izin akses dari pemilik backup atau Admin.
    """
    # Query backup berdasarkan backup_id
    backup = BackupData.query.get(backup_id)

    # Validasi apakah backup ada dan pengguna memiliki hak akses
    jwt_data = get_jwt()
    user_id = jwt_data.get("user_id")
    roles = jwt_data.get("roles", [])

    if not backup or ("Admin" not in roles and backup.user_id != user_id):
        return (
            jsonify({"success": False, "message": "Backup not found or unauthorized"}),
            404,
        )

    # Mengambil log audit terkait backup_id
    audit_logs = BackupAuditLog.query.filter_by(backup_id=backup_id).all()
    logs_list = [
        {
            "action": log.action,
            "timestamp": log.timestamp.isoformat(),
            "performed_by": log.performed_by,
        }
        for log in audit_logs
    ]

    # Mengembalikan daftar log audit dalam format JSON
    return jsonify({"success": True, "audit_logs": logs_list}), 200
