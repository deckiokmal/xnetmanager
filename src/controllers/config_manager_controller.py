from flask import (
    Blueprint,
    render_template,
    jsonify,
    request,
    current_app,
)
from flask_login import login_required, current_user
from src.models.users_model import User
from src.models.xmanager_model import DeviceManager, ConfigurationManager
from src.utils.config_manager_utils import ConfigurationManagerUtils
from src import db
import os
from .decorators import login_required, role_required
from flask_paginate import Pagination, get_page_args
from threading import Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Membuat blueprint nm_bp dan error_bp
nm_bp = Blueprint("nm", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging
logging.basicConfig(level=logging.INFO)


@nm_bp.before_app_request
def setup_logging():
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


# middleware untuk autentikasi dan otorisasi
@nm_bp.before_request
def before_request_func():
    if not current_user.is_authenticated:
        return jsonify({"message": "Unauthorized access"}), 401


# Menangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("main/404.html"), 404


# Context processor untuk menambahkan username ke dalam konteks di semua halaman.
@nm_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        user_id = current_user.id
        user = User.query.get(user_id)
        return dict(username=user.username)
    return dict(username=None)


# Network Manager App Starting
GEN_TEMPLATE_FOLDER = "xmanager/gen_templates"


# Endpoint Network Manager index
@nm_bp.route("/nm", methods=["GET"])
@login_required
def index():
    search_query = request.args.get("search", "")

    # Ambil halaman dan per halaman dari argumen URL
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

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

    pagination = Pagination(
        page=page, per_page=per_page, total=total_devices, css_framework="bootstrap4"
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


# Endpoint untuk cek status perangkat
@nm_bp.route("/check_status", methods=["POST"])
@login_required
def check_status():
    devices = DeviceManager.query.filter_by(is_active=True).all()
    device_status = {}

    # Daftar untuk menyimpan thread
    threads = []

    def check_device(device):
        nonlocal device_status
        check_device_status = ConfigurationManagerUtils(
            ip_address=device.ip_address,
            username=device.username,
            password=device.password,
            ssh=int(device.ssh),  # Menggunakan port SSH sebagai integer
        )
        check_device_status.check_device_status_threaded()  # Menggunakan threading

        status = (
            check_device_status.device_status
        )  # Memperoleh status dari objek ConfigurationManagerUtils
        device_status[device.id] = status
        device.status = status
        db.session.commit()

    # Membuat dan memulai thread untuk setiap perangkat
    for device in devices:
        thread = Thread(target=check_device, args=(device,))
        threads.append(thread)
        thread.start()

    # Menunggu semua thread selesai
    for thread in threads:
        thread.join()

    return jsonify(device_status)


# Endpoint Push Config for multiple devices
@nm_bp.route("/push_configs", methods=["POST"])
@login_required
def push_configs():
    data = request.get_json()
    device_ips = data.get("devices", [])
    config_id = data.get("config_id")

    if not device_ips:
        return jsonify({"success": False, "message": "No devices selected."}), 400

    if not config_id:
        return jsonify({"success": False, "message": "No config selected."}), 400

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

    # Use ThreadPoolExecutor to manage threads
    def configure_device(device):
        nonlocal success
        try:
            config_utils = ConfigurationManagerUtils(
                ip_address=device.ip_address,
                username=device.username,
                password=device.password,
                ssh=device.ssh,
            )
            message, status = config_utils.configure_device(config_content)
            return {
                "device_name": device.device_name,
                "ip": device.ip_address,
                "status": status,
                "message": message,
            }
        except Exception as e:
            logging.error("Error configuring device %s: %s", device.ip_address, e)
            return {
                "device_name": device.device_name,
                "ip": device.ip_address,
                "status": "error",
                "message": str(e),
            }

    # Create a ThreadPoolExecutor with a maximum number of threads
    max_threads = 10  # Adjust as necessary
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


# Endpoint Push Config for single device
@nm_bp.route("/push_config/<int:device_id>", methods=["POST"])
@login_required
def push_config(device_id):
    # Mengambil perangkat dari database berdasarkan ID
    device = DeviceManager.query.get_or_404(device_id)
    templates = ConfigurationManager.query.all()

    # Fungsi untuk membaca konten template dengan penanganan error
    def read_template(filename):
        template_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, filename
        )
        try:
            # Membaca konten file template
            with open(template_path, "r") as file:
                return file.read()
        except FileNotFoundError:
            # Log kesalahan dan kembalikan response error
            current_app.logger.error(f"File konfigurasi tidak ditemukan: {filename}")
            return None
        except Exception as e:
            # Log kesalahan dan kembalikan response error
            current_app.logger.error(f"Gagal membaca file konfigurasi: {e}")
            return None

    if request.method == "POST":
        # Menginisialisasi ConfigurationManagerUtils dengan detail perangkat
        config = ConfigurationManagerUtils(
            ip_address=device.ip_address,
            username=device.username,
            password=device.password,
            ssh=device.ssh,
        )

        # Mendapatkan konten template dengan fungsi read_template()
        commands = []
        for template in templates:
            command = read_template(template.config_name)
            if command:  # Pastikan command tidak None
                commands.append(command)

        # Memeriksa jika ada command yang berhasil dibaca
        if commands:
            try:
                # Mengonfigurasi perangkat dengan command yang didapat
                for command in commands:
                    config.configure_device(command)
                # Kembalikan respon sukses jika konfigurasi berhasil dikirim
                current_app.logger.info(
                    f"Konfigurasi berhasil dikirim ke perangkat ID: {device_id}"
                )
                return jsonify(
                    {"success": True, "message": "Konfigurasi berhasil dikirim."}
                )
            except Exception as e:
                # Log kesalahan dan kembalikan response error
                current_app.logger.error(
                    f"Error pushing config ke perangkat ID {device_id}: {e}"
                )
                return (
                    jsonify(
                        {"success": False, "message": f"Error pushing config: {str(e)}"}
                    ),
                    400,
                )
        else:
            # Kembalikan response jika tidak ada command yang berhasil dibaca
            current_app.logger.error(
                f"Tidak ada konfigurasi yang berhasil dibaca untuk perangkat ID: {device_id}"
            )
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Tidak ada konfigurasi yang berhasil dibaca.",
                    }
                ),
                400,
            )
