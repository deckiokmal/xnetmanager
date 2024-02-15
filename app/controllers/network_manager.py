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
from app.models.users import User
from app.models.device_manager import DeviceManager
from app.models.network_manager import NetworkManager
from app.utils.network_manager_class import NetworkManagerUtils
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
@nm_bp.route("/open_console/<int:device_id>", methods=["GET", "POST"])
@login_required
def open_console(device_id):
    device = DeviceManager.query.get_or_404(device_id)

    if request.method == "POST":
        console = NetworkManagerUtils(ip_address=device.ip_address)
        console.open_webconsole()

        return redirect(url_for("nm.index"))


@nm_bp.route("/push_config/<int:device_id>", methods=["POST"])
@login_required
def push_config(device_id):
    device = DeviceManager.query.get_or_404(device_id)
    templates = NetworkManager.query.all()  # Use template_id from device

    # Read template content with error handling
    def read_template(filename):
        template_path = os.path.join(current_app.static_folder, "network_templates", filename)
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
                flash("Push config successful!", "success")
                return redirect(url_for('nm.index'))
            except Exception as e:
                flash("Error pushing config: " + str(e), "error")
        else:  # If template read failed, handle the error
            # You can add more specific error handling here

            return redirect(url_for("nm.index"))
        