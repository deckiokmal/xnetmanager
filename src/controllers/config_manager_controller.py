from flask import (
    Blueprint,
    render_template,
    jsonify,
    request,
    current_app,
    redirect,
    url_for,
    flash,
)
from flask_login import (
    login_required,
    current_user,
    logout_user,
)
from .decorators import (
    role_required,
    required_2fa,
)
import logging
from src.models.app_models import DeviceManager, ConfigurationManager
from src.utils.config_manager_utils import ConfigurationManagerUtils
import os
from flask_paginate import Pagination, get_page_args
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import random
from datetime import datetime
import string
from src import db
import time
from sqlalchemy.exc import SQLAlchemyError

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
    Jika pengguna harus logout paksa, lakukan logout dan arahkan ke halaman login.
    Jika tidak terotentikasi, kembalikan pesan 'Unauthorized access'.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return render_template("main/404.html"), 404

    # Jika pengguna terotentikasi dan memiliki flag force_logout, lakukan logout
    if current_user.force_logout:
        current_user.force_logout = False  # Reset the flag
        db.session.commit()
        logout_user()
        flash("Your password has been updated. Please log in again.", "info")
        return redirect(url_for("main.login"))


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


GEN_TEMPLATE_FOLDER = "xmanager/configurations"


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
@nm_bp.route("/push-configuration", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Config and Backup"], page="Config Management"
)
def index():
    """
    Menampilkan halaman index Network Manager.
    Fitur: Pencarian perangkat, pagination, dan pengambilan data konfigurasi.
    """
    # Logging untuk akses ke endpoint
    current_app.logger.info(f"{current_user.email} accessed Push Configurations")

    search_query = request.args.get("search", "").lower()
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )
    if page < 1 or per_page < 1:
        flash("Invalid pagination values.", "danger")

    try:
        # Query untuk DeviceManager
        if current_user.has_role("Admin"):
            devices_query = DeviceManager.query
        else:
            devices_query = DeviceManager.query.filter_by(user_id=current_user.id)

        # Jika ada pencarian, tambahkan filter pencarian
        if search_query:
            devices_query = devices_query.filter(
                DeviceManager.device_name.ilike(f"%{search_query}%")
                | DeviceManager.ip_address.ilike(f"%{search_query}%")
                | DeviceManager.vendor.ilike(f"%{search_query}%")
            )

        # Pagination dan device query
        total_devices = devices_query.count()
        devices = devices_query.limit(per_page).offset(offset).all()
        pagination = Pagination(page=page, per_page=per_page, total=total_devices)

        if total_devices == 0:
            flash("Tidak ada data apapun di halaman ini.", "info")

        # Query untuk ConfigurationManager
        if current_user.has_role("Admin"):
            config_query = ConfigurationManager.query
        else:
            config_query = ConfigurationManager.query.filter_by(user_id=current_user.id)

        config_file = config_query.all()

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
    except SQLAlchemyError as e:
        # Specific database error handling
        current_app.logger.error(
            f"Database error while accessing Push Configuration page by user {current_user.email}: {str(e)}"
        )
        flash(
            "A database error occurred while accessing the Push Configuration. Please try again later.",
            "danger",
        )
        return redirect(url_for("users.dashboard"))
    except Exception as e:
        current_app.logger.error(
            f"Error accessing Push Configuration page by user {current_user.email}: {str(e)}"
        )
        flash(
            "An error occurred while accessing the Push Configuration. Please try again later.",
            "danger",
        )
        return redirect(url_for("users.dashboard"))


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


@nm_bp.route("/check_status", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Config and Backup"], page="Config Management"
)
def check_status():
    """
    Memeriksa status perangkat yang ada di halaman tertentu berdasarkan pagination dan search query.
    """
    try:
        # Ambil parameter page, per_page, dan search_query dari request JSON
        page = int(request.json.get("page", 1))  # Default halaman 1
        per_page = int(request.json.get("per_page", 10))  # Default 10 item per halaman
        search_query = (
            request.json.get("search_query", "").lower().strip()
        )  # Default pencarian kosong

        # Query perangkat sesuai dengan peran pengguna
        if current_user.has_role("Admin"):
            devices_query = DeviceManager.query
        else:
            devices_query = DeviceManager.query.filter_by(user_id=current_user.id)

        # Filter perangkat jika ada search query
        if search_query:
            devices_query = devices_query.filter(
                DeviceManager.device_name.ilike(f"%{search_query}%")
                | DeviceManager.ip_address.ilike(f"%{search_query}%")
                | DeviceManager.vendor.ilike(f"%{search_query}%")
            )

        # Pagination untuk devices
        devices = devices_query.limit(per_page).offset((page - 1) * per_page).all()

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

        # Gunakan ThreadPoolExecutor untuk melakukan pengecekan status secara paralel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(check_device_status, device): device
                for device in devices
            }

            # Iterasi melalui hasil pengecekan
            for future in as_completed(futures):
                try:
                    device_id, status = future.result()
                    device_status[device_id] = status
                except Exception as e:
                    logging.error(f"Error checking status for device: {e}")
                    device_status[device_id] = "error"

        # Kembalikan hasil dalam bentuk JSON untuk ditangani oleh UI
        return jsonify(device_status)

    except Exception as e:
        logging.error(f"Error checking device status: {str(e)}")
        return (
            jsonify({"error": "An error occurred while checking device status."}),
            500,
        )


# Endpoint untuk push konfigurasi ke perangkat
@nm_bp.route("/push_configs", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Config and Backup"], page="Config Management"
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

    # Query perangkat berdasarkan peran user
    if current_user.has_role("Admin"):
        devices = DeviceManager.query.filter(
            DeviceManager.ip_address.in_(device_ips)
        ).all()
    else:
        devices = DeviceManager.query.filter(
            DeviceManager.ip_address.in_(device_ips),
            DeviceManager.user_id == current_user.id,
        ).all()

    # Jika tidak ada perangkat yang ditemukan
    if not devices:
        return (
            jsonify(
                {"success": False, "message": "No devices found for the provided IPs."}
            ),
            404,
        )

    # Query konfigurasi berdasarkan peran user
    if current_user.has_role("Admin"):
        config = ConfigurationManager.query.filter_by(id=config_id).first()
    else:
        config = ConfigurationManager.query.filter_by(
            id=config_id, user_id=current_user.id
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


# Endpoint untuk push konfigurasi ke satu perangkat
@nm_bp.route("/push_config/<device_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Config and Backup"], page="Config Management"
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

    # Query perangkat berdasarkan device_id dan peran user
    if current_user.has_role("Admin"):
        device = DeviceManager.query.filter_by(id=device_id).first()
    else:
        device = DeviceManager.query.filter_by(
            id=device_id, user_id=current_user.id
        ).first()

    # Jika perangkat tidak ditemukan
    if not device:
        return jsonify({"success": False, "message": "Device not found."}), 404

    # Query konfigurasi berdasarkan peran user
    if current_user.has_role("Admin"):
        config = ConfigurationManager.query.filter_by(id=config_id).first()
    else:
        config = ConfigurationManager.query.filter_by(
            id=config_id, user_id=current_user.id
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
