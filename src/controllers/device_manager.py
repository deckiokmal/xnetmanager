from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from src import db
from src.models.users import User
from src.models.networkautomation import DeviceManager
from .decorators import login_required, role_required
from src.utils.mask_password import mask_password


# Membuat blueprint users
dm_bp = Blueprint("dm", __name__)
error_bp = Blueprint("error", __name__)
error_bp = Blueprint("error_handlers", __name__)


# Manangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("/main/404.html"), 404


# Context processor untuk menambahkan username ke dalam konteks disemua halaman.
@dm_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        device_id = current_user.id
        user = User.query.get(device_id)
        return dict(username=user.username)
    return dict(username=None)


# Device Manager Page
@dm_bp.route("/dm", methods=["GET"])
@login_required
def index():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    search_query = request.args.get("search", "")

    query = DeviceManager.query
    if search_query:
        query = query.filter(
            DeviceManager.device_name.ilike(f"%{search_query}%")
            | DeviceManager.vendor.ilike(f"%{search_query}%")
            | DeviceManager.ip_address.ilike(f"%{search_query}%")
        )

    all_devices = query.paginate(page=page, per_page=per_page)

    start_index = (page - 1) * per_page + 1
    end_index = min(start_index + per_page - 1, all_devices.total)

    return render_template(
        "/device_managers/device_manager.html",
        data=all_devices.items,
        total_count=all_devices.total,
        start_index=start_index,
        end_index=end_index,
        search_query=search_query,
        per_page=per_page,  # Pass per_page to the template
        all_devices=all_devices,  # Pass all_devices to handle pagination in the template
    )


# Create device
@dm_bp.route("/device_create", methods=["POST"])
@login_required
def device_create():
    device_name = request.form["device_name"]
    vendor = request.form["vendor"]
    ip_address = request.form["ip_address"]
    username = request.form["username"]
    password = request.form["password"]
    ssh = request.form["ssh"]

    exist_address = DeviceManager.query.filter_by(ip_address=ip_address).first()
    exist_device = DeviceManager.query.filter_by(device_name=device_name).first()
    if exist_device or exist_address:
        flash("Device sudah terdaftar!", "info")
    elif not username or not password or not ssh:
        flash("Username, password dan ssh tidak boleh kosong!", "info")
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
        )
        db.session.add(new_device)
        db.session.commit()
        flash("Device berhasil ditambah!", "success")
        return redirect(url_for("dm.index"))

    return redirect(url_for("dm.index"))


# Update device
@dm_bp.route("/device_update/<int:device_id>", methods=["GET", "POST"])
@login_required
def device_update(device_id):
    device = DeviceManager.query.get(device_id)

    if request.method == "POST":
        new_device_name = request.form["device_name"]
        new_vendor = request.form["vendor"]
        new_ip_address = request.form["ip_address"]
        new_username = request.form["username"]
        new_password = request.form["password"]
        new_ssh = request.form["ssh"]

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
            device.device_name = new_device_name
            device.vendor = new_vendor
            device.ip_address = new_ip_address
            device.username = new_username
            device.password = new_password
            device.ssh = new_ssh

            db.session.commit()
            flash("Device update berhasil.", "success")
            return redirect(url_for("dm.index"))

    return render_template("/device_managers/device_update.html", device=device)


# Delete device
@dm_bp.route("/device_delete/<int:device_id>", methods=["POST"])
@login_required
@role_required("Admin", "device_delete")
def device_delete(device_id):
    device = DeviceManager.query.get(device_id)
    if not device:
        flash("Device tidak ditemukan.", "info")
        return redirect(url_for("dm.index"))

    db.session.delete(device)
    db.session.commit()
    flash("Device telah dihapus.", "success")
    return redirect(url_for("dm.index"))
