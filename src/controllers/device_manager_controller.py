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
    """Mengatur logging untuk aplikasi"""
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


@error_bp.app_errorhandler(404)
def page_not_found(error):
    """Menangani error 404 dan mengarahkan ke halaman 404.html"""
    current_app.logger.error(f"Error 404: {error}")
    return render_template("main/404.html"), 404


@dm_bp.before_request
def before_request_func():
    """Middleware untuk memastikan pengguna sudah terautentikasi sebelum akses"""
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return jsonify({"message": "Unauthorized access"}), 401


@dm_bp.context_processor
def inject_user():
    """Menambahkan informasi pengguna yang sedang login ke dalam konteks halaman"""
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


@dm_bp.route("/dm", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Devices", "View Devices"],
    page="Devices Management",
)
def index():
    """Menampilkan halaman utama Device Manager dengan data perangkat dan pagination"""
    search_query = request.args.get("search", "").lower()

    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    if search_query:
        devices_query = DeviceManager.query.filter(
            DeviceManager.device_name.ilike(f"%{search_query}%")
            | DeviceManager.ip_address.ilike(f"%{search_query}%")
            | DeviceManager.vendor.ilike(f"%{search_query}%")
            | DeviceManager.description.ilike(f"%{search_query}%")
            | DeviceManager.created_by.ilike(f"%{search_query}%")
        )
    else:
        devices_query = DeviceManager.query

    total_devices = devices_query.count()
    devices = devices_query.limit(per_page).offset(offset).all()

    pagination = Pagination(
        page=page, per_page=per_page, total=total_devices, css_framework="bootstrap4"
    )

    current_app.logger.info(f"User {current_user.email} accessed Device Manager page.")

    return render_template(
        "/device_managers/index.html",
        devices=devices,
        page=page,
        per_page=per_page,
        pagination=pagination,
        search_query=search_query,
        total_devices=total_devices,
    )


@dm_bp.route("/device_create", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def device_create():
    """Menambahkan perangkat baru ke dalam database"""
    device_name = request.form["device_name"]
    vendor = request.form["vendor"]
    ip_address = request.form["ip_address"]
    username = request.form["username"]
    password = request.form["password"]
    ssh = request.form["ssh"]
    description = request.form["description"]

    exist_address = DeviceManager.query.filter_by(ip_address=ip_address).first()
    exist_device = DeviceManager.query.filter_by(device_name=device_name).first()
    if exist_device or exist_address:
        flash("Device sudah terdaftar!", "info")
        current_app.logger.info(
            f"Duplicate device attempt: {device_name} or {ip_address}"
        )
    elif not username or not password or not ssh:
        flash("Username, password, dan SSH tidak boleh kosong!", "info")
    elif not is_valid_ip(ip_address):
        flash("IP Address tidak valid!", "error")
        current_app.logger.warning(f"Invalid IP attempt: {ip_address}")
    elif not ssh.isdigit():
        flash("SSH port harus angka!", "error")
    else:
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
        current_app.logger.info(
            f"Device created: {device_name} by {current_user.email}"
        )
        return redirect(url_for("dm.index"))

    return redirect(url_for("dm.index"))


@dm_bp.route("/device_update/<int:device_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def device_update(device_id):
    """Mengupdate informasi perangkat di database"""
    device = DeviceManager.query.get(device_id)

    if request.method == "POST":
        new_device_name = request.form["device_name"]
        new_vendor = request.form["vendor"]
        new_ip_address = request.form["ip_address"]
        new_username = request.form["username"]
        new_password = request.form["password"]
        new_ssh = request.form["ssh"]
        new_description = request.form["description"]

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
            current_app.logger.warning(
                f"Duplicate update attempt for device ID {device_id}"
            )
        elif not new_username or not new_password or not new_ssh:
            flash("Username, password dan SSH tidak boleh kosong.", "info")
            return render_template("/device_managers/device_update.html", device=device)
        elif not new_ssh.isdigit():
            flash("SSH port harus angka!", "error")
        else:
            device.device_name = new_device_name
            device.vendor = new_vendor
            device.ip_address = new_ip_address
            device.username = new_username
            device.password = new_password
            device.ssh = new_ssh
            device.description = new_description

            db.session.commit()
            flash("Device update berhasil.", "success")
            current_app.logger.info(
                f"Device ID {device_id} updated by {current_user.email}"
            )
            return redirect(url_for("dm.index"))

    return render_template("/device_managers/device_update.html", device=device)


@dm_bp.route("/device_delete/<int:device_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def device_delete(device_id):
    """Menghapus perangkat dari database"""
    device = DeviceManager.query.get(device_id)
    if not device:
        flash("Device tidak ditemukan.", "info")
        current_app.logger.warning(
            f"Delete attempt for non-existent device ID {device_id}"
        )
        return redirect(url_for("dm.index"))

    db.session.delete(device)
    db.session.commit()
    flash("Device telah dihapus.", "success")
    current_app.logger.info(f"Device ID {device_id} deleted by {current_user.email}")
    return redirect(url_for("dm.index"))


@dm_bp.route("/api/get_devices", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def get_devices():
    """Mendapatkan data semua perangkat dalam format JSON"""
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
    current_app.logger.info(f"User {current_user.email} retrieved all devices data.")
    return jsonify({"devices": device_list})


@dm_bp.route("/api/get_device_data/<int:device_id>")
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def get_device_data(device_id):
    """Mendapatkan data perangkat berdasarkan ID dalam format JSON"""
    try:
        device = DeviceManager.query.get_or_404(device_id)
        current_app.logger.info(
            f"User {current_user.email} accessed data for device ID {device_id}"
        )
        return jsonify(
            {
                "ip_address": device.ip_address,
                "username": device.username,
                "password": device.password,
                "ssh": device.ssh,
                "device_name": device.device_name,
                "vendor": device.vendor,
                "description": device.description,
            }
        )
    except Exception as e:
        current_app.logger.error(f"Error retrieving device ID {device_id}: {str(e)}")
        return jsonify({"error": "Data tidak ditemukan"}), 404
