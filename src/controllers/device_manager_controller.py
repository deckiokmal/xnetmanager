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
from src import db
from src.models.xmanager_model import DeviceManager
from .decorators import login_required, role_required, required_2fa
from src.utils.ip_validation_utils import is_valid_ip
from flask_paginate import Pagination, get_page_args
import logging

# Membuat blueprint untuk device manager
dm_bp = Blueprint("dm", __name__)
error_bp = Blueprint("error", __name__)


# Setup logging
logging.basicConfig(level=logging.INFO)


@dm_bp.before_app_request
def setup_logging():
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


# Menangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("main/404.html"), 404


# middleware untuk autentikasi dan otorisasi
@dm_bp.before_request
def before_request_func():
    if not current_user.is_authenticated:
        return jsonify({"message": "Unauthorized access"}), 401


# Context processor untuk menambahkan first_name dan last_name ke dalam konteks di semua halaman.
@dm_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")



# Halaman utama Device Manager
@dm_bp.route("/dm", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Devices", "View Devices"],
    page="Devices Management",
)
def index():
    # Mendapatkan parameter pencarian dari URL
    search_query = request.args.get("search", "").lower()

    # Mendapatkan halaman saat ini dan jumlah entri per halaman
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    if search_query:
        # Jika ada pencarian, filter perangkat berdasarkan query
        devices_query = DeviceManager.query.filter(
            DeviceManager.device_name.ilike(f"%{search_query}%")
            | DeviceManager.ip_address.ilike(f"%{search_query}%")
            | DeviceManager.vendor.ilike(f"%{search_query}%")
            | DeviceManager.description.ilike(f"%{search_query}%")
            | DeviceManager.created_by.ilike(f"%{search_query}%")
        )
    else:
        # Jika tidak ada pencarian, ambil semua perangkat
        devices_query = DeviceManager.query

    # Menghitung total perangkat dan mengambil perangkat untuk halaman saat ini
    total_devices = devices_query.count()
    devices = devices_query.limit(per_page).offset(offset).all()

    # Membuat objek pagination
    pagination = Pagination(
        page=page, per_page=per_page, total=total_devices, css_framework="bootstrap4"
    )

    # Menampilkan template dengan data perangkat dan pagination
    return render_template(
        "/device_managers/index.html",
        devices=devices,
        page=page,
        per_page=per_page,
        pagination=pagination,
        search_query=search_query,
        total_devices=total_devices,
    )


# Menambahkan perangkat baru
@dm_bp.route("/device_create", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def device_create():
    device_name = request.form["device_name"]
    vendor = request.form["vendor"]
    ip_address = request.form["ip_address"]
    username = request.form["username"]
    password = request.form["password"]
    ssh = request.form["ssh"]
    description = request.form["description"]

    # Mengecek apakah perangkat dengan IP atau nama sudah ada
    exist_address = DeviceManager.query.filter_by(ip_address=ip_address).first()
    exist_device = DeviceManager.query.filter_by(device_name=device_name).first()
    if exist_device or exist_address:
        flash("Device sudah terdaftar!", "info")
    # Validasi input dari form
    elif not username or not password or not ssh:
        flash("Username, password, dan SSH tidak boleh kosong!", "info")
    elif not is_valid_ip(ip_address):
        flash("IP Address tidak valid!", "error")
    elif not ssh.isdigit():
        flash("SSH port harus angka!", "error")
    else:
        # Menambahkan perangkat baru ke database
        new_device = DeviceManager(
            device_name=device_name,
            vendor=vendor,
            ip_address=ip_address,
            username=username,
            password=password,
            ssh=ssh,
            description=description,
            created_by=current_user.email,
        )
        db.session.add(new_device)
        db.session.commit()
        flash("Device berhasil ditambah!", "success")
        return redirect(url_for("dm.index"))

    return redirect(url_for("dm.index"))


# Mengupdate informasi perangkat
@dm_bp.route("/device_update/<int:device_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def device_update(device_id):
    device = DeviceManager.query.get(device_id)

    if request.method == "POST":
        new_device_name = request.form["device_name"]
        new_vendor = request.form["vendor"]
        new_ip_address = request.form["ip_address"]
        new_username = request.form["username"]
        new_password = request.form["password"]
        new_ssh = request.form["ssh"]
        new_description = request.form["description"]

        # Mengecek apakah nama perangkat atau IP sudah ada di perangkat lain
        exist_device = DeviceManager.query.filter(
            DeviceManager.device_name == new_device_name, DeviceManager.id != device.id
        ).first()
        exist_address = DeviceManager.query.filter(
            DeviceManager.ip_address == new_ip_address, DeviceManager.id != device.id
        ).first()
        if exist_device or exist_address:
            flash(
                "Device name atau IP Address sudah ada. Silahkan masukkan yang lain!",
                "error",
            )
        elif not new_username or not new_password or not new_ssh:
            flash("Username, password dan SSH tidak boleh kosong.", "info")
            return render_template("/device_managers/device_update.html", device=device)
        elif not new_ssh.isdigit():
            flash("SSH port harus angka!", "error")
        else:
            # Memperbarui informasi perangkat
            device.device_name = new_device_name
            device.vendor = new_vendor
            device.ip_address = new_ip_address
            device.username = new_username
            device.password = new_password
            device.ssh = new_ssh
            device.description = new_description

            db.session.commit()
            flash("Device update berhasil.", "success")
            return redirect(url_for("dm.index"))

    return render_template("/device_managers/device_update.html", device=device)


# Menghapus perangkat
@dm_bp.route("/device_delete/<int:device_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def device_delete(device_id):
    device = DeviceManager.query.get(device_id)
    if not device:
        flash("Device tidak ditemukan.", "info")
        return redirect(url_for("dm.index"))

    db.session.delete(device)
    db.session.commit()
    flash("Device telah dihapus.", "success")
    return redirect(url_for("dm.index"))


# Endpoint API get data all devices
@dm_bp.route("/api/get_devices", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def get_devices():
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
        }
        for device in devices
    ]
    return jsonify({"devices": device_list})


# Endpoint untuk mendapatkan data perangkat berdasarkan ID
@dm_bp.route("/api/get_device_data/<int:device_id>")
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def get_device_data(device_id):
    try:
        # Mengambil perangkat dari database berdasarkan ID
        device = DeviceManager.query.get_or_404(device_id)

        # Mengembalikan data perangkat dalam format JSON
        return jsonify(
            {
                "ip_address": device.ip_address,
                "username": device.username,
                "password": device.password,
                "ssh": device.ssh,
            }
        )
    except Exception as e:
        # Log kesalahan dan kembalikan respon error
        current_app.logger.error(
            f"Error mendapatkan data perangkat ID {device_id}: {e}"
        )
        return jsonify({"error": str(e)}), 400
