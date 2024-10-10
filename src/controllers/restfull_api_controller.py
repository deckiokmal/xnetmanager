from flask import (
    Blueprint,
    jsonify,
    current_app,
    request,
)
from src import db, bcrypt
from src.models.app_models import DeviceManager, User, Role, TemplateManager
import logging
from src.utils.schema_utils import (
    user_schema,
    users_schema,
    device_schema,
    devices_schema,
    template_schema,
    templates_schema,
)
from flask_jwt_extended import jwt_required, create_access_token

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
    email = request.form["email"]
    user = User.query.filter_by(email=email).first()

    if user:
        return jsonify(message="Email sudah terdaftar!."), 409
    else:
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        password = request.form["password"]

        new_user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password_hash=password,
        )

        # Assign role 'User'
        user_role = Role.query.filter_by(name="User").first()
        if user_role:
            new_user.roles.append(user_role)

        db.session.add(new_user)
        db.session.commit()

        return jsonify(message="User berhasil dibuat."), 201


@restapi_bp.route("/api/update-user", methods=["PUT"])
@jwt_required()
def update_user():
    user_id = request.form["user_id"]
    user = User.query.filter_by(id=user_id).first()

    if user:
        user.first_name = request.form["first_name"]
        user.last_name = request.form["last_name"]
        db.session.commit()
        return jsonify(message="User update sukses."), 202
    else:
        return jsonify(message="User tidak ditemukan."), 404


@restapi_bp.route("/api/delete-user/<user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify(message=f"Anda menghapus user {user}."), 202
    else:
        return jsonify(message=f"User tidak ditemukan."), 404


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
    ip_address = request.form["ip_address"]
    device_name = request.form["device_name"]
    try:
        exist_address = DeviceManager.query.filter_by(ip_address=ip_address).first()
        exist_device_name = DeviceManager.query.filter_by(
            device_name=device_name
        ).first()

        if exist_address or exist_device_name:
            return (
                jsonify(
                    message="IP Address atau Device Name sudah ada. Silahkan coba yang lain."
                ),
                401,
            )
        else:
            vendor = request.form["vendor"]
            username = request.form["username"]
            password = request.form["password"]
            ssh = int(request.form["ssh"])
            description = request.form["description"]

            new_device = DeviceManager(
                device_name=device_name,
                vendor=vendor,
                ip_address=ip_address,
                username=username,
                password=password,
                ssh=ssh,
                description=description,
            )
            db.session.add(new_device)
            db.session.commit()

            return jsonify(message="Device berhasil dibuat."), 201
    except Exception as e:
        db.session.rollback()
        return (
            jsonify(
                message="Terjadi kesalahan saat membuat perangkat. Silahkan coba lagi."
            ),
            501,
        )


@restapi_bp.route("/api/update-device", methods=["PUT"])
@jwt_required()
def update_device():
    device_id = request.form["device_id"]
    device = DeviceManager.query.filter_by(id=device_id).first()

    if device:
        device.device_name = request.form["device_name"]
        device.vendor = request.form["vendor"]
        device.ip_address = request.form["ip_address"]
        device.username = request.form["username"]
        device.password = request.form["password"]
        device.ssh = request.form["ssh"]
        device.description = request.form["description"]

        db.session.commit()
        return jsonify(message="Device update sukses."), 202
    else:
        return jsonify(message="Device tidak ditemukan."), 404


@restapi_bp.route("/api/delete-device/<device_id>", methods=["DELETE"])
@jwt_required()
def delete_device(device_id):
    device = DeviceManager.query.filter_by(id=device_id).first()
    if device:
        db.session.delete(device)
        db.session.commit()
        return jsonify(message=f"Anda menghapus device {device}."), 202
    else:
        return jsonify(message=f"Device tidak ditemukan."), 404


# -----------------------------------------------------------
# API Template Management
# -----------------------------------------------------------


@restapi_bp.route("/api/get-templates", methods=["GET"])
@jwt_required()
def get_templates():
    templates_list = TemplateManager.query.all()
    result = templates_schema.dump(templates_list)
    return jsonify(result)