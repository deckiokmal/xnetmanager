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
from functools import wraps
from src.models.users import User
from src.models.networkautomation import DeviceManager, NetworkManager
from src.utils.network_manager_class import NetworkManagerUtils
from datetime import datetime
from src import db
import os


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
    # Mengambil semua perangkat dan template konfigurasi dari database
    devices = DeviceManager.query.all()
    templates = NetworkManager.query.all()

    return render_template(
        "/network_managers/network_manager.html", devices=devices, templates=templates
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


# Push Config
@nm_bp.route("/push_config/<int:device_id>", methods=["POST"])
@login_required
def push_config(device_id):
    device = DeviceManager.query.get_or_404(device_id)
    templates = NetworkManager.query.all()  # Use template_id from device

    # Read template content with error handling
    def read_template(filename):
        template_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, filename
        )
        try:
            with open(template_path, "r") as file:
                return file.read()
        except FileNotFoundError:
            flash("Error: Template file not found.", "error")
            return redirect(url_for("nm.index"))  # Redirect on error
        except Exception as e:
            flash("Error reading template: " + str(e), "error")
            return redirect(url_for("nm.index"))  # Redirect on other errors

    if request.method == "POST":
        config = NetworkManagerUtils(
            ip_address=device.ip_address,
            username=device.username,
            password=device.password,
            ssh=device.ssh,
        )

        # Get template content using the improved read_template()
        for template in templates:
            command = read_template(template.template_name)

        # Check if command was read successfully before proceeding
        if command:
            try:
                config.configure_device(command)
                return redirect(url_for("nm.index"))
            except Exception as e:
                flash("Error pushing config: " + str(e), "error")
                return redirect(url_for("nm.index"))
        else:
            return redirect(url_for("nm.index"))


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

    return render_template(
        "/network_managers/templates.html", templates=templates
    )


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
                flash("File with the new name already exists.", "error")
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
