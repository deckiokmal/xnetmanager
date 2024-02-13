from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    current_app,
)
from flask_login import login_required, current_user
from functools import wraps
from app import db
from app.models.users import User
from app.models.device_manager import Device_manager
from app.models.network_manager import configTemplates
from app.utils.network_manager_class import netAuto
from werkzeug.utils import secure_filename
import os
import random


# Membuat blueprint main_bp dan error_bp
nm_bp = Blueprint("nm", __name__)
error_bp = Blueprint("error", __name__)
error_bp = Blueprint("error_handlers", __name__)


# Manangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("/main/404.html"), 404


# cek login session. jika user belum memiliki login sesi dan mencoba akses url valid maka kembali ke loginpage.
def login_required(func):
    """
    Decorator untuk memeriksa apakah pengguna sudah login sebelum mengakses halaman tertentu.
    Jika belum login, pengguna akan diarahkan ke halaman login.
    """

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("You need to login first.", "warning")
            return redirect(url_for("main.index"))
        return func(*args, **kwargs)

    return decorated_view


# Context processor untuk menambahkan username ke dalam konteks disemua halaman.
@nm_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        user_id = current_user.id
        user = User.query.get(user_id)
        return dict(username=user.username)
    return dict(username=None)


# Network Manager App Starting


# Network Manager route
@nm_bp.route("/nm", methods=["GET"])
@login_required
def index():
    # Tampilkan all devices per_page 10
    page = request.args.get("page", 1, type=int)
    per_page = 10
    all_devices = Device_manager.query.paginate(page=page, per_page=per_page)

    return render_template("/network_managers/network_manager.html")


@nm_bp.route("/send-command", methods=["POST"])
def send_command():
    """
    Route untuk mengirimkan perintah SSH ke perangkat.
    """
    data = request.get_json()
    ip_address = data.get("ip_address")
    username = data.get("username")
    password = data.get("password")
    ssh_port = data.get("ssh_port")
    command = data.get("command")

    if ip_address and username and password and ssh_port and command:
        device = netAuto(ip_address, username, password, ssh_port)
        result = device.send_command(command)
        if result:
            return (
                jsonify({"success": True, "message": "Command sent successfully."}),
                200,
            )
        else:
            return (
                jsonify({"success": False, "message": "Failed to send command."}),
                500,
            )
    else:
        return (
            jsonify({"success": False, "message": "Missing required parameters."}),
            400,
        )


@nm_bp.route("/check-status", methods=["POST"])
def check_status():
    """
    Route untuk memeriksa status perangkat dengan melakukan ping.
    """
    data = request.get_json()
    ip_address = data.get("ip_address")

    if ip_address:
        device = netAuto(
            ip_address, "", "", 22
        )  # Username, password, dan port SSH dapat dikosongkan karena tidak digunakan untuk ping
        result = device.check_device_status()
        if result:
            return jsonify({"success": True, "message": "Device is reachable."}), 200
        else:
            return jsonify({"success": False, "message": "Device is unreachable."}), 500
    else:
        return (
            jsonify({"success": False, "message": "Missing required parameters."}),
            400,
        )


@nm_bp.route("/send-command-by-id", methods=["POST"])
def send_command_by_id():
    """
    Route untuk mengirimkan perintah ke perangkat berdasarkan ID perangkat.
    """
    data = request.get_json()
    device_id = data.get("device_id")
    command = data.get("command")

    if device_id and command:
        device_list = netAuto.get_device_list_from_database()
        if device_id <= len(device_list):
            ip_address, username, password, ssh_port = device_list[
                device_id - 1
            ]  # Mengambil info perangkat dari database
            device = netAuto(ip_address, username, password, ssh_port)
            result = device.send_command(command)
            if result:
                return (
                    jsonify({"success": True, "message": "Command sent successfully."}),
                    200,
                )
            else:
                return (
                    jsonify({"success": False, "message": "Failed to send command."}),
                    500,
                )
        else:
            return jsonify({"success": False, "message": "Device not found."}), 404
    else:
        return (
            jsonify({"success": False, "message": "Missing required parameters."}),
            400,
        )
