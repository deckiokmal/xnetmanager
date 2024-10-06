from flask import (
    Blueprint,
    jsonify,
    current_app,
    request,
)
from src import db
from src.models.app_models import DeviceManager, User, Role
import logging

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
# API Devices Management
# -----------------------------------------------------------


@restapi_bp.route("/api/get-devices", methods=["GET"])
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


@restapi_bp.route("/api/users", methods=["GET"])
def api_users():
    users = User.query.all()
    users_list = [{"id": u.id, "name": u.email} for u in users]
    return jsonify(user=users_list)


@restapi_bp.route("/api/create-user", methods=["POST"])
def create_user():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()
    
    if user:
        return jsonify(message='Email sudah terdaftar!.'), 409
    else:
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']

        new_user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password_hash=password
        )

        # Assign role 'User'
        user_role = Role.query.filter_by(name="User").first()
        if user_role:
            new_user.roles.append(user_role)

        db.session.add(new_user)
        db.session.commit()

        return jsonify(message='User berhasil dibuat.'), 201
