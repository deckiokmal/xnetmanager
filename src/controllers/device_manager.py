from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from functools import wraps
from src import db
from src.models.users import User
from src.models.networkautomation import DeviceManager


# Membuat blueprint users
dm_bp = Blueprint("dm", __name__)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('You need to login first', 'info')
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function


# Context processor untuk menambahkan username ke dalam konteks disemua halaman.
@dm_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        device_id = current_user.id
        user = User.query.get(device_id)
        return dict(username=user.username)
    return dict(username=None)


# Device Manager App Starting


# Device Manager Page
@dm_bp.route("/dm", methods=["GET"])
@login_required
def index():
    # Tampilkan all devices per_page 10
    page = request.args.get("page", 1, type=int)
    per_page = 10
    all_devices = DeviceManager.query.paginate(page=page, per_page=per_page)

    return render_template("/device_managers/device_manager.html", data=all_devices)


# Create device
@dm_bp.route("/device_create", methods=["GET", "POST"])
@login_required
def device_create():
    if request.method == "POST":
        device_name = request.form["device_name"]
        vendor = request.form["vendor"]
        ip_address = request.form["ip_address"]
        username = request.form["username"]
        password = request.form["password"]
        ssh = request.form["ssh"]

        # 1. existing device ip address and device name checking
        exist_address = DeviceManager.query.filter_by(ip_address=ip_address).first()
        exist_device = DeviceManager.query.filter_by(device_name=device_name).first()
        if exist_device or exist_address:
            flash("Device sudah terdaftar!", "info")

        # 2. username dan password field check. - user tidak boleh input data kosong.
        elif not username or not password or not ssh:
            flash("Username, password dan ssh tidak boleh kosong!", "info")

        # 3. periksa ssh dengan isdigit()
        elif not ssh.isdigit():
            flash("ssh port harus angka!", "error")

        # jika error checking null, maka eksekusi device_create
        else:
            new_device = DeviceManager(
                device_name=device_name,
                vendor=vendor,
                ip_address=ip_address,
                username=username,
                password=password,
                ssh=ssh
            )
            db.session.add(new_device)
            db.session.commit()
            flash("Device berhasil ditambah!", "success")

            # kembali ke index
            return redirect(url_for("dm.index"))

    return redirect(url_for("dm.index"))


# Update device
@dm_bp.route("/device_update/<int:device_id>", methods=["GET", "POST"])
@login_required
def device_update(device_id):

    # Get data Device by id
    device = DeviceManager.query.get(device_id)

    if request.method == "POST":
        new_device_name = request.form["device_name"]
        new_vendor = request.form["vendor"]
        new_ip_address = request.form["ip_address"]
        new_username = request.form["username"]
        new_password = request.form["password"]
        new_ssh = request.form["ssh"]

        # Check jika device_name dan ip_address yang dimasukan sudah tersedia dan bukan user saat ini.
        exist_device = DeviceManager.query.filter(
            DeviceManager.device_name == new_device_name, DeviceManager.id != device.id
        ).first()
        exist_address = DeviceManager.query.filter(
            DeviceManager.ip_address == new_ip_address, DeviceManager.id != device.id
        ).first()
        if exist_device or exist_address:
            flash("Device name atau IP Address sudah ada. Silahkan masukkan yang lain!", "error")

        # Check jika username, password dan ssh kosong
        elif not new_username or not new_password or not new_ssh:
            flash("username, password dan ssh tidak boleh kosong.", "info")
            return render_template("/device_managers/device_update.html", device=device)
        
        # 3. periksa ssh dengan isdigit()
        elif not new_ssh.isdigit():
            flash("ssh port harus angka!", "error")

        else:
            # Update data
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
def device_delete(device_id):
    device = DeviceManager.query.get(device_id)
    if not device:
        flash("Device tidak ditemukan.", "info")
        return redirect(url_for("dm.index"))

    db.session.delete(device)
    db.session.commit()
    flash("Device telah dihapus.", "success")
    return redirect(url_for("dm.index"))
