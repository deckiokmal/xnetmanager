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
from functools import wraps
from app import db
from app.models.users import User
from app.models.device_manager import Device_manager
from app.models.network_manager import configTemplates
from app.utils.network_manager_class import netAuto
from werkzeug.utils import secure_filename
import os
import json


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


# Network Manager App Starting


# Network Manager route
@nm_bp.route("/nm", methods=["GET"])
@login_required
def index():
    # Tampilkan all devices per_page 10
    page = request.args.get("page", 1, type=int)
    per_page = 10
    all_devices = Device_manager.query.paginate(page=page, per_page=per_page)

    return render_template("/network_managers/network_manager.html")


# Templates route
@nm_bp.route("/nm_template", methods=["GET"])
@login_required
def templates():
    # Tampilkan all devices per_page 10
    page = request.args.get("page", 1, type=int)
    per_page = 10
    all_templates = configTemplates.query.paginate(page=page, per_page=per_page)

    return render_template(
        "/network_managers/template_manager.html", all_templates=all_templates
    )


# Upload data template
UPLOAD_FOLDER = "network_templates"
TEMPLE_EXTENSIONS = {"j2"}
PARAMS_EXTENSIONS = {"yml", "yaml"}


def allowed_file_temple(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in TEMPLE_EXTENSIONS

def allowed_file_params(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in PARAMS_EXTENSIONS


@nm_bp.route("/template_upload", methods=["GET", "POST"])
@login_required
def template_upload():
    if request.method == "POST":
        # Ambil data dari formulir
        vendor = request.form["vendor"]
        version = request.form["version"]
        info = request.form["info"]

        # Cek apakah jinja2 file telah diunggah
        if "j2" not in request.files:
            flash("No j2 part")
            return redirect(request.url)

        j2 = request.files["j2"]

        # Cek apakah yaml file telah diunggah
        if "yaml" not in request.files:
            flash("No yaml part")
            return redirect(request.url)

        yaml = request.files["yaml"]

        # Cek apakah semua kolom telah diisi
        if not vendor or not version or not info:
            flash("Data tidak boleh kosong!", "error")
            return redirect(request.url)

        # Cek apakah file dipilih
        if j2.filename == "" or yaml.filename == "":
            flash("No selected file", "error")
            return redirect(request.url)

        # Cek apakah file memiliki ekstensi yang diizinkan
        if j2 and allowed_file_temple(j2.filename):
            template_name = secure_filename(j2.filename)
            file_path = os.path.join(
                current_app.static_folder, UPLOAD_FOLDER, template_name
            )
            j2.save(file_path)
        else:
            flash("Jenis file yang dimasukkan tidak sesuai. hint j2.", "error")
            return redirect(url_for("nm.templates"))

        # Cek apakah file memiliki ekstensi yang diizinkan
        if yaml and allowed_file_params(yaml.filename):
            parameter_name = secure_filename(yaml.filename)
            file_path = os.path.join(
                current_app.static_folder, UPLOAD_FOLDER, parameter_name
            )
            yaml.save(file_path)
        else:
            flash("Jenis file yang dimasukkan tidak sesuai. hint yml, yaml.", "error")
            return redirect(url_for("nm.templates"))
        
        # Simpan data ke dalam database
        new_template = configTemplates(
            template_name=template_name,
            parameter_name=parameter_name,
            vendor=vendor,
            version=version,
            info=info,
        )
        db.session.add(new_template)
        db.session.commit()

        flash("File berhasil upload.", "success")
        return redirect(url_for("nm.templates"))



# Templates update
@nm_bp.route("/template_update/<int:template_id>", methods=["GET", "POST"])
@login_required
def template_update(template_id):
    # 1. Dapatkan objek dari database berdasarkan ID
    template = configTemplates.query.get_or_404(template_id)

    # Read file J2 template content
    def read_template(filename=template.template_name):
        template_path = os.path.join(
            current_app.static_folder, "network_templates", filename
        )
        with open(template_path, "r") as file:
            template_content = file.read()
        return template_content

    # Read file YAML parameter content
    def read_parameter(filename=template.parameter_name):
        parameter_path = os.path.join(
            current_app.static_folder, "network_templates", filename
        )
        with open(parameter_path, "r") as file:
            parameter_content = file.read()
        return parameter_content

    # 2. kirim hasil baca file ke content textarea update page.
    template_content = read_template()
    parameter_content = read_parameter()

    # 4. cek ketika user melakukan submit data dengan method 'POST'
    if request.method == "POST":
        new_template_name = request.form["template_name"]
        new_parameter_name = request.form["parameter_name"]
        new_vendor = request.form["vendor"]
        new_version = request.form["version"]
        new_info = request.form["info"]
        new_template_content = request.form["template_content"]
        new_parameter_content = request.form["parameter_content"]

        # 5.1 Update file template_content jika ada perubahan
        if new_template_content != read_template():
            template_path = os.path.join(
                current_app.static_folder, "network_templates", template.template_name
            )
            with open(template_path, "w") as file:
                file.write(new_template_content)

        # 5.1 Update file parameter_content jika ada perubahan
        if new_parameter_content != read_parameter():
            parameter_path = os.path.join(
                current_app.static_folder, "network_templates", template.parameter_name
            )
            with open(parameter_path, "w") as file:
                file.write(new_parameter_content)

        # 5.2 Update file name jika ada perubahan
        if new_template_name != template.template_name:
            # template_path
            new_path_template = os.path.join(
                current_app.static_folder, "network_templates", new_template_name
            )

            # cek filename exsisting, filename tidak boleh sama dengan filename exsisting
            if os.path.exists(new_path_template):
                flash("File with the new name already exists.", "error")
            else:
                # old_path_template
                old_path_template = os.path.join(
                    current_app.static_folder,
                    "network_templates",
                    template.template_name,
                )
                os.rename(old_path_template, new_path_template)
                template.template_name = new_template_name

        # 5.2 Update file name jika ada perubahan
        if new_parameter_name != template.parameter_name:
            # parameter_path
            new_path_parameter = os.path.join(
                current_app.static_folder, "network_templates", new_parameter_name
            )

            # cek filename exsisting, filename tidak boleh sama dengan filename exsisting
            if os.path.exists(new_path_parameter):
                flash("File with the new name already exists.", "error")
            else:
                # old_path_parameter
                old_path_parameter = os.path.join(
                    current_app.static_folder,
                    "network_templates",
                    template.parameter_name,
                )
                os.rename(old_path_parameter, new_path_parameter)
                template.parameter_name = new_parameter_name

        # 5.3 Update data ke dalam database
        template.template_name = new_template_name
        template.parameter_name = new_parameter_name
        template.vendor = new_vendor
        template.version = new_version
        template.info = new_info

        db.session.commit()
        flash("Template update berhasil.", "success")
        return redirect(url_for("nm.templates"))

    # 3. Tampilkan halaman template_update dengan data file di update page.
    return render_template(
        "/network_managers/template_update.html",
        template=template,
        template_content=template_content,
        parameter_content=parameter_content,
    )


# Templates delete
@nm_bp.route("/template_delete/<int:template_id>", methods=["POST"])
@login_required
def template_delete(template_id):

    # Dapatkan objek dari database berdasarkan ID
    template = configTemplates.query.get_or_404(template_id)

    # Hapus file J2 template
    file_path = os.path.join(
        current_app.static_folder, "network_templates", str(template.template_name)
    )
    if os.path.exists(file_path):
        os.remove(file_path)

    # Hapus file YAML parameter
    file_path = os.path.join(
        current_app.static_folder, "network_templates", str(template.parameter_name)
    )
    if os.path.exists(file_path):
        os.remove(file_path)

    # Hapus data dari database
    db.session.delete(template)
    db.session.commit()

    # Redirect ke halaman templates
    return redirect(url_for("nm.templates"))


@nm_bp.route("/send-command", methods=["POST"])
def send_command():
    """
    Route untuk mengirimkan perintah SSH ke perangkat.
    """
    data = request.get_json()
    ip_address = data.get("ip_address")
    username = data.get("username")
    password = data.get("password")
    ssh_port = data.get("ssh_port")
    command = data.get("command")

    if ip_address and username and password and ssh_port and command:
        device = netAuto(ip_address, username, password, ssh_port)
        result = device.send_command(command)
        if result:
            return (
                jsonify({"success": True, "message": "Command sent successfully."}),
                200,
            )
        else:
            return (
                jsonify({"success": False, "message": "Failed to send command."}),
                500,
            )
    else:
        return (
            jsonify({"success": False, "message": "Missing required parameters."}),
            400,
        )


@nm_bp.route("/check-status", methods=["POST"])
def check_status():
    """
    Route untuk memeriksa status perangkat dengan melakukan ping.
    """
    data = request.get_json()
    ip_address = data.get("ip_address")

    if ip_address:
        device = netAuto(
            ip_address, "", "", 22
        )  # Username, password, dan port SSH dapat dikosongkan karena tidak digunakan untuk ping
        result = device.check_device_status()
        if result:
            return jsonify({"success": True, "message": "Device is reachable."}), 200
        else:
            return jsonify({"success": False, "message": "Device is unreachable."}), 500
    else:
        return (
            jsonify({"success": False, "message": "Missing required parameters."}),
            400,
        )


@nm_bp.route("/render-template", methods=["POST"])
def render_template_config():
    """
    Route untuk merender template Jinja2 dengan parameter YAML.
    """
    data = request.get_json()
    jinja_template = data.get("jinja_template")
    yaml_params = data.get("yaml_params")

    if jinja_template and yaml_params:
        device = netAuto(
            "", "", "", 22
        )  # Informasi perangkat dapat dikosongkan karena tidak digunakan dalam render template
        rendered_config = device.render_template(jinja_template, yaml_params)
        if rendered_config:
            return jsonify({"success": True, "rendered_config": rendered_config}), 200
        else:
            return (
                jsonify({"success": False, "message": "Failed to render template."}),
                500,
            )
    else:
        return (
            jsonify({"success": False, "message": "Missing required parameters."}),
            400,
        )


@nm_bp.route("/send-command-by-id", methods=["POST"])
def send_command_by_id():
    """
    Route untuk mengirimkan perintah ke perangkat berdasarkan ID perangkat.
    """
    data = request.get_json()
    device_id = data.get("device_id")
    command = data.get("command")

    if device_id and command:
        device_list = netAuto.get_device_list_from_database()
        if device_id <= len(device_list):
            ip_address, username, password, ssh_port = device_list[
                device_id - 1
            ]  # Mengambil info perangkat dari database
            device = netAuto(ip_address, username, password, ssh_port)
            result = device.send_command(command)
            if result:
                return (
                    jsonify({"success": True, "message": "Command sent successfully."}),
                    200,
                )
            else:
                return (
                    jsonify({"success": False, "message": "Failed to send command."}),
                    500,
                )
        else:
            return jsonify({"success": False, "message": "Device not found."}), 404
    else:
        return (
            jsonify({"success": False, "message": "Missing required parameters."}),
            400,
        )
