from flask import (
    Blueprint,
    render_template,
    jsonify,
    request,
    redirect,
    url_for,
    flash,
    current_app,
)
from flask_login import login_required, current_user
from src.models.users import User
from src.models.networkautomation import DeviceManager, NetworkManager
from src.utils.network_manager_class import NetworkManagerUtils
from datetime import datetime
from src import db
import os
from .decorators import login_required, role_required
from flask_paginate import Pagination, get_page_args


# Membuat blueprint main_bp dan error_bp
nm_bp = Blueprint("nm", __name__)
error_bp = Blueprint("error", __name__)
error_bp = Blueprint("error_handlers", __name__)


# Manangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("/main/404.html"), 404


# Context processor untuk menambahkan username ke dalam konteks disemua halaman.
@nm_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        user_id = current_user.id
        user = User.query.get(user_id)
        return dict(username=user.username)
    return dict(username=None)


# Network Manager App Starting ###################################################
GEN_TEMPLATE_FOLDER = "xmanager/gen_templates"
BACKUP_FOLDER = "xmanager/device_backup"
SFTP_USERNAME = "admin"
SFTP_PASSWORD = "admin"
SFTP_ADDRESS = "192.168.1.1"


# Network Manager route
@nm_bp.route("/nm", methods=["GET"])
@login_required
def index():
    search_query = request.args.get("search", "")

    # Ambil halaman dan per halaman dari argumen URL
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    if search_query:
        # Jika ada pencarian, filter perangkat berdasarkan query
        devices_query = DeviceManager.query.filter(
            DeviceManager.device_name.ilike(f"%{search_query}%")
            | DeviceManager.ip_address.ilike(f"%{search_query}%")
            | DeviceManager.vendor.ilike(f"%{search_query}%")
        )
    else:
        # Jika tidak ada pencarian, ambil semua perangkat
        devices_query = DeviceManager.query

    total_devices = devices_query.count()
    devices = devices_query.limit(per_page).offset(offset).all()

    templates = NetworkManager.query.all()

    pagination = Pagination(
        page=page, per_page=per_page, total=total_devices, css_framework="bootstrap4"
    )

    return render_template(
        "/network_managers/network_manager.html",
        devices=devices,
        templates=templates,
        page=page,
        per_page=per_page,
        pagination=pagination,
        search_query=search_query,
    )


# Check status perangkat
@nm_bp.route("/check_status", methods=["POST"])
@login_required
def check_status():
    devices = DeviceManager.query.all()

    device_status = {}
    for device in devices:
        check_device_status = NetworkManagerUtils(ip_address=device.ip_address)
        check_device_status.check_device_status_threaded()

        device_status[device.id] = check_device_status.device_status

    return jsonify(device_status)


# Open Console
@nm_bp.route("/open_console/<int:device_id>", methods=["POST"])
@login_required
def open_console(device_id):
    device = DeviceManager.query.get_or_404(device_id)

    if request.method == "POST":
        console = NetworkManagerUtils(ip_address=device.ip_address)
        console.open_webconsole()

        return redirect(url_for("nm.index"))


# Push Config for multiple devices
@nm_bp.route("/push_configs", methods=["POST"])
@login_required
def push_configs():
    # Ambil data JSON dari request
    data = request.get_json()
    device_ips = data.get("devices", [])
    template_id = data.get("template_id")

    # Jika tidak ada perangkat yang dipilih, kembalikan respons dengan pesan error
    if not device_ips:
        flash("No devices selected.", "warning")
        return jsonify({"success": False, "message": "No devices selected."}), 400

    # Jika template tidak dipilih, kembalikan respons dengan pesan error
    if not template_id:
        flash("No template selected.", "warning")
        return jsonify({"success": False, "message": "No template selected."}), 400

    # Ambil perangkat dari database berdasarkan IP yang dipilih
    devices = DeviceManager.query.filter(DeviceManager.ip_address.in_(device_ips)).all()
    template = NetworkManager.query.get(template_id)

    # Jika template tidak ditemukan, kembalikan respons dengan pesan error
    if not template:
        flash("Selected template not found.", "danger")
        return (
            jsonify({"success": False, "message": "Selected template not found."}),
            404,
        )

    # Baca isi template dari file
    def read_template(filename):
        template_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, filename
        )
        try:
            with open(template_path, "r") as file:
                return file.read()
        except FileNotFoundError:
            flash("Template file not found.", "danger")
            return None
        except Exception as e:
            flash(f"Error reading template: {e}", "danger")
            return None

    # Baca template content
    template_content = read_template(template.template_name)
    if not template_content:
        return jsonify({"success": False, "message": "Error reading template."}), 500

    results = []
    success = True

    # Proses konfigurasi untuk setiap perangkat
    for device in devices:
        config = NetworkManagerUtils(
            ip_address=device.ip_address,
            username=device.username,
            password=device.password,
            ssh=device.ssh,
        )

        # Terapkan konfigurasi ke perangkat dan ambil hasil
        message, status = config.configure_device(template_content)
        results.append(
            {
                "device_name": device.device_name,
                "ip": device.ip_address,
                "status": status,
                "message": message,
            }
        )

        if status != "success":
            success = False

    # Kembalikan hasil dalam format JSON
    return jsonify({"success": success, "results": results})


# Backup Config
@nm_bp.route("/backup_config/<int:device_id>", methods=["POST"])
@login_required
def backup_config(device_id):
    # get device_id
    device = DeviceManager.query.get_or_404(device_id)

    if request.method == "POST":
        # get data device vendor
        vendor = device.vendor

        # Mikrotik
        if vendor.lower() == "mikrotik":
            command = "export compact"

        # Fortinet
        elif vendor.lower() == "fortinet":
            command = f"execute backup config sftp backup/backup.conf {SFTP_ADDRESS} {SFTP_USERNAME} {SFTP_PASSWORD}"

        # Cisco
        elif vendor.lower() == "cisco":
            command = "show running-config"
        else:
            flash("device vendor belum disupport.", "error")
            return redirect(url_for("nm.index"))

        # kirim perintah backup
        backup = NetworkManagerUtils(
            ip_address=device.ip_address,
            username=device.username,
            password=device.password,
            ssh=device.ssh,
        )
        # tangkap hasil backup
        backup_data = backup.backup_config(command)

        # Simpan dan buat file tangkapan hasil backup ke directory backup
        now = datetime.now()
        date_time_string = now.strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{device.vendor}_{date_time_string}backup.txt"
        filepath = os.path.join(
            current_app.static_folder,
            BACKUP_FOLDER,
            filename,
        )
        with open(filepath, "w") as f:
            f.write(backup_data)

        flash("Backup berhasil.", "success")
        return redirect(url_for("nm.index"))


# Template view page
@nm_bp.route("/templates")
@login_required
def templates():
    templates = NetworkManager.query.all()

    return render_template("/network_managers/templates.html", templates=templates)


# Templates update
@nm_bp.route("/network_template_update/<int:template_id>", methods=["GET", "POST"])
@login_required
def network_template_update(template_id):
    # 1. Dapatkan objek dari database berdasarkan ID
    template = NetworkManager.query.get_or_404(template_id)

    # Read file template content
    def read_template(filename=template.template_name):
        template_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, filename
        )
        with open(template_path, "r") as file:
            template_content = file.read()
        return template_content

    # 2. kirim hasil baca file ke content textarea update page.
    template_content = read_template()

    # 4. cek ketika user melakukan submit data dengan method 'POST'
    if request.method == "POST":
        new_template_name = request.form["template_name"]
        new_template_content = request.form["template_content"]

        # 5.1 Update file template_content jika ada perubahan
        if new_template_content != read_template():
            template_path = os.path.join(
                current_app.static_folder, GEN_TEMPLATE_FOLDER, template.template_name
            )
            with open(template_path, "w") as file:
                file.write(new_template_content)

        # 5.2 Update file name jika ada perubahan
        if new_template_name != template.template_name:
            # template_path
            new_path_template = os.path.join(
                current_app.static_folder, GEN_TEMPLATE_FOLDER, new_template_name
            )

            # cek filename exsisting, filename tidak boleh sama dengan filename exsisting
            if os.path.exists(new_path_template):
                flash("File with the new name already exists.", "info")
            else:
                # old_path_template
                old_path_template = os.path.join(
                    current_app.static_folder,
                    GEN_TEMPLATE_FOLDER,
                    template.template_name,
                )
                os.rename(old_path_template, new_path_template)
                template.template_name = new_template_name

        # 5.3 Update data ke dalam database
        template.template_name = new_template_name

        db.session.commit()
        flash("Template update berhasil.", "success")
        return redirect(url_for("nm.templates"))

    # 3. Tampilkan halaman template_update dengan data file di update page.
    return render_template(
        "/network_managers/template_update.html",
        template=template,
        template_content=template_content,
    )


# Templates delete
@nm_bp.route("/network_template_delete/<int:template_id>", methods=["POST"])
@login_required
@role_required("Admin", "network_template_delete")
def network_template_delete(template_id):

    # Dapatkan objek dari database berdasarkan ID
    template = NetworkManager.query.get_or_404(template_id)

    # Hapus file template
    file_path = os.path.join(
        current_app.static_folder, GEN_TEMPLATE_FOLDER, str(template.template_name)
    )
    if os.path.exists(file_path):
        os.remove(file_path)

    # Hapus data dari database
    db.session.delete(template)
    db.session.commit()

    # Redirect ke halaman templates
    return redirect(url_for("nm.templates"))
