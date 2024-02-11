from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from app import db
from app.models.users import User
from app.models.device_manager import Device_manager


# Membuat blueprint users
dm_bp = Blueprint("dm", __name__)


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
    all_devices = Device_manager.query.paginate(page=page, per_page=per_page)

    return render_template("/network_managers/device_manager.html", data=all_devices)


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
        exist_address = Device_manager.query.filter_by(ip_address=ip_address).first()
        exist_device = Device_manager.query.filter_by(device_name=device_name).first()
        if exist_device or exist_address:
            flash("Device sudah terdaftar!", "error")

        # 2. username dan password field check. - user tidak boleh input data kosong.
        elif not username or not password or not ssh:
            flash("Username, password dan ssh tidak boleh kosong!", "error")

        # 3. periksa ssh dengan isdigit()
        elif not ssh.isdigit():
            flash("ssh port harus angka!", "error")

        # jika error checking null, maka eksekusi device_create
        else:
            new_device = Device_manager(
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

    return render_template("/network_managers/device_create.html")


# Update device
@dm_bp.route("/device_update/<int:device_id>", methods=["GET", "POST"])
@login_required
def device_update(device_id):

    # Get data Device by id
    device = Device_manager.query.get(device_id)

    if request.method == "POST":
        new_device_name = request.form["device_name"]
        new_vendor = request.form["vendor"]
        new_ip_address = request.form["ip_address"]
        new_username = request.form["username"]
        new_password = request.form["password"]
        new_ssh = request.form["ssh"]

        # Check jika device_name dan ip_address yang dimasukan sudah tersedia dan bukan user saat ini.
        exist_device = Device_manager.query.filter(
            Device_manager.device_name == new_device_name, Device_manager.id != device.id
        ).first()
        exist_address = Device_manager.query.filter(
            Device_manager.ip_address == new_ip_address, Device_manager.id != device.id
        ).first()
        if exist_device or exist_address:
            flash("Device name atau IP Address sudah ada. Silahkan masukkan yang lain!", "error")

        # Check jika username, password dan ssh kosong
        elif not new_username or not new_password or not new_ssh:
            flash("username, password dan ssh tidak boleh kosong.", "error")
            return render_template("/network_managers/device_update.html", device=device)
        
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

    return render_template("/network_managers/device_update.html", device=device)


# Delete device
@dm_bp.route("/device_delete/<int:device_id>", methods=["POST"])
@login_required
def device_delete(device_id):
    device = Device_manager.query.get(device_id)
    if not device:
        flash("Device tidak ditemukan.", "error")
        return redirect(url_for("dm.index"))

    db.session.delete(device)
    db.session.commit()
    flash("Device telah dihapus.", "success")
    return redirect(url_for("dm.index"))
