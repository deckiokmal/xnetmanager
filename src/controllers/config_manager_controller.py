from flask import (
    Blueprint,
    render_template,
    jsonify,
    request,
    current_app,
    copy_current_request_context,
)
from flask_login import login_required, current_user
from src.models.app_models import DeviceManager, ConfigurationManager
from src.utils.config_manager_utils import ConfigurationManagerUtils
import os
from .decorators import login_required, role_required, required_2fa
from flask_paginate import Pagination, get_page_args
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import json
import random
from datetime import datetime
import string

# Membuat blueprint untuk Network Manager (nm_bp) dan Error Handling (error_bp)
nm_bp = Blueprint("nm", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging untuk aplikasi
logging.basicConfig(level=logging.INFO)


@nm_bp.before_app_request
def setup_logging():
    """
    Mengatur level logging untuk aplikasi.
    """
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


# Menangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    """
    Menangani error 404 dan menampilkan halaman 404.
    """
    current_app.logger.error(f"Error 404: {error}")
    return render_template("main/404.html"), 404


# Middleware untuk autentikasi dan otorisasi sebelum permintaan.
@nm_bp.before_request
def before_request_func():
    """
    Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan.
    Jika tidak, mengembalikan pesan 'Unauthorized access'.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return jsonify({"message": "Unauthorized access"}), 401


# Context processor untuk menambahkan first_name dan last_name ke dalam konteks di semua halaman.
@nm_bp.context_processor
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
# Config Management Section
# --------------------------------------------------------------------------------


GEN_TEMPLATE_FOLDER = "xmanager/gen_templates"


# Fungsi pembantu untuk menghasilkan nama file acak
def generate_random_filename(filename):
    random_str = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    date_str = datetime.now().strftime("%d.%m.%Y_%H.%M.%S")
    filename = f"{filename}_{random_str}_{date_str}"
    current_app.logger.info(
        f"Generated random filename: {filename}"
    )  # Logging nama file yang dihasilkan
    return filename


# Endpoint Network Manager index
@nm_bp.route("/nm", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Config"], page="Config Management"
)
def index():
    """
    Menampilkan halaman index Network Manager.
    Fitur: Pencarian perangkat, pagination, dan pengambilan data konfigurasi.
    """
    search_query = request.args.get("search", "")

    # Ambil halaman dan jumlah per halaman dari argumen URL
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    # Query perangkat berdasarkan pencarian atau semua perangkat jika tidak ada pencarian
    if search_query:
        devices_query = DeviceManager.query.filter(
            DeviceManager.device_name.ilike(f"%{search_query}%")
            | DeviceManager.ip_address.ilike(f"%{search_query}%")
            | DeviceManager.vendor.ilike(f"%{search_query}%")
        )
    else:
        devices_query = DeviceManager.query

    total_devices = devices_query.count()
    devices = devices_query.limit(per_page).offset(offset).all()
    config_file = ConfigurationManager.query.all()

    # Setup pagination
    pagination = Pagination(
        page=page,
        per_page=per_page,
        total=total_devices,
    )

    return render_template(
        "config_managers/index.html",
        devices=devices,
        config_file=config_file,
        page=page,
        per_page=per_page,
        pagination=pagination,
        search_query=search_query,
        total_devices=total_devices,
    )


# Endpoint untuk mengecek status perangkat
@nm_bp.route("/check_status", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Config"], page="Config Management"
)
def check_status():
    """
    Memeriksa status setiap perangkat di database.
    Mengembalikan status dalam format JSON untuk setiap perangkat.
    """
    devices = DeviceManager.query.all()
    device_status = {}

    # Mengecek status setiap perangkat
    for device in devices:
        check_device_status = ConfigurationManagerUtils(ip_address=device.ip_address)
        status_json = check_device_status.check_device_status_threaded()

        try:
            # Parsing hasil JSON dari status perangkat
            status_dict = json.loads(status_json)
            # Set status berdasarkan hasil ping
            if status_dict["status"] == "success":
                device_status[device.id] = "success"
            else:
                device_status[device.id] = "error"
        except json.JSONDecodeError as e:
            logging.error("Error decoding JSON response: %s", e)
            device_status[device.id] = "error"

    return jsonify(device_status)


# Endpoint untuk push konfigurasi ke perangkat
@nm_bp.route("/push_configs", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Config"], page="Config Management"
)
def push_configs():
    """
    Mengirimkan konfigurasi ke perangkat yang dipilih.
    Fitur: Memvalidasi input, membaca file konfigurasi, dan push konfigurasi secara paralel ke banyak perangkat.
    """
    data = request.get_json()
    device_ips = data.get("devices", [])
    config_id = data.get("config_id")

    # Validasi input
    if not device_ips:
        return jsonify({"success": False, "message": "No devices selected."}), 400
    if not config_id:
        return jsonify({"success": False, "message": "No config selected."}), 400

    # Query perangkat dan konfigurasi berdasarkan input
    devices = DeviceManager.query.filter(DeviceManager.ip_address.in_(device_ips)).all()
    if not devices:
        return (
            jsonify(
                {"success": False, "message": "No devices found for the provided IPs."}
            ),
            404,
        )

    config = ConfigurationManager.query.get(config_id)
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


# --------------------------------------------------------------------------------
# Backup Management Section
# --------------------------------------------------------------------------------


# Endpoint backup konfigurasi menu
@nm_bp.route("/backup_manager", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Config"], page="Config Management"
)
def backup_manager():
    """Menampilkan halaman Backup Manager dengan daftar perangkat."""
    search_query = request.args.get("search", "")

    # Ambil halaman dan jumlah per halaman dari argumen URL
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    # Query perangkat berdasarkan pencarian atau semua perangkat jika tidak ada pencarian
    if search_query:
        devices_query = DeviceManager.query.filter(
            DeviceManager.device_name.ilike(f"%{search_query}%")
            | DeviceManager.ip_address.ilike(f"%{search_query}%")
            | DeviceManager.vendor.ilike(f"%{search_query}%")
        )
    else:
        devices_query = DeviceManager.query

    total_devices = devices_query.count()
    devices = devices_query.limit(per_page).offset(offset).all()
    config_file = ConfigurationManager.query.all()

    # Setup pagination
    pagination = Pagination(
        page=page,
        per_page=per_page,
        total=total_devices,
    )

    return render_template(
        "config_managers/backup_manager.html",
        devices=devices,
        config_file=config_file,
        page=page,
        per_page=per_page,
        pagination=pagination,
        search_query=search_query,
        total_devices=total_devices,
    )


# Endpoint untuk backup konfigurasi perangkat
@nm_bp.route("/backup_config", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Config"], page="Config Management"
)
def backup_config():
    """Menerima ID perangkat dan perintah untuk backup."""
    data = request.get_json()
    device_ips = data.get("devices", [])
    command = data.get("command")

    # Validasi input
    if not device_ips:
        return jsonify({"success": False, "message": "No devices selected."}), 400
    if not command:
        return jsonify({"success": False, "message": "No config selected."}), 400

    # Query perangkat dan konfigurasi berdasarkan input
    devices = DeviceManager.query.filter(DeviceManager.ip_address.in_(device_ips)).all()
    if not devices:
        return (
            jsonify(
                {"success": False, "message": "No devices found for the provided IPs."}
            ),
            404,
        )

    results = []
    success = True

    # Fungsi untuk mengkonfigurasi perangkat
    @copy_current_request_context
    def configure_device(device):
        nonlocal success
        try:
            config_utils = ConfigurationManagerUtils(
                ip_address=device.ip_address,
                username=device.username,
                password=device.password,
                ssh=device.ssh,
            )
            response_json = config_utils.backup_configuration(command=command)
            response_dict = json.loads(response_json)
            backup_data = response_dict.get("message")

            # simpan hasil backup ke directory
            filename_gen = f"{device.ip_address}_{device.vendor}_{device.device_name}"
            random_filename = generate_random_filename(filename_gen)
            filename = f"{random_filename}.txt"
            path_backup = "xmanager/backups"
            file_path = os.path.join(current_app.static_folder, path_backup, filename)

            if backup_data:
                backup_data = (
                    backup_data.replace("\r\n", "\n").replace("\r", "\n").strip()
                )
            # Simpan konten backup ke dalam file
            with open(file_path, "w", encoding="utf-8") as backup_file:
                backup_file.write(backup_data)
            current_app.logger.info(
                f"Successfully saved backup content to file: {file_path}"
            )

            if response_dict.get("status") == "success":
                return {
                    "device_name": device.device_name,
                    "ip": device.ip_address,
                    "status": "success",
                    "message": "Backup sukses.",
                }
            else:
                return {
                    "device_name": device.device_name,
                    "ip": device.ip_address,
                    "status": response_dict.get("status", "error"),
                    "message": response_dict.get("message", "Konfigurasi gagal"),
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
