from flask import (
    Blueprint,
    jsonify,
    current_app,
    request,
)
from src import db, bcrypt
from src.models.app_models import DeviceManager, User, Role
import logging
from src.utils.forms_utils import user_schema, users_schema
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
# API Devices Management
# -----------------------------------------------------------


@restapi_bp.route("/api/get-devices", methods=["GET"])
@jwt_required()
def get_devices():
    """Mendapatkan data semua perangkat dalam format JSON yang dimiliki oleh pengguna saat ini"""
    devices = DeviceManager.query.all()

    device_list = [
        {
            "id": device.id,
            "device_name": device.device_name,
            "vendor": device.vendor,
            "ip_address": device.ip_address,
            "username": device.username,
            "password": device.password,
            "ssh": device.ssh,
            "description": device.description,
            "user_id": device.user_id,
        }
        for device in devices
    ]

    return jsonify({"devices": device_list}), 200


@restapi_bp.route("/api/get-device/<device_id>", methods=["GET"])
@jwt_required()
def get_device_data(device_id):
    """Mendapatkan data perangkat berdasarkan ID dalam format JSON jika perangkat tersebut dimiliki oleh pengguna saat ini"""
    try:
        device = DeviceManager.query.get_or_404(device_id)

        return (
            jsonify(
                {
                    "ip_address": device.ip_address,
                    "username": device.username,
                    "password": device.password,
                    "ssh": device.ssh,
                    "device_name": device.device_name,
                    "vendor": device.vendor,
                    "description": device.description,
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": "Data tidak ditemukan"}), 404


# -----------------------------------------------------------
# API User Management
# -----------------------------------------------------------


@restapi_bp.route("/api/get-users", methods=["GET"])
@jwt_required()
def get_users():
    users_list = User.query.all()
    result = users_schema.dump(users_list)
    return jsonify(result)


@restapi_bp.route("/api/user-detail/<user_id>", methods=["GET"])
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


@restapi_bp.route("/api/user-update", methods=["PUT"])
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


@restapi_bp.route("/api/remove-user/<user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify(message=f"Anda menghapus user {user}."), 202
    else:
        return jsonify(message=f"User tidak ditemukan."), 404
