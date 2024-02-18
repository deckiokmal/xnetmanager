from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app,
)
from flask_login import login_required, current_user
from functools import wraps
from src import db
from src.models.users import User
from src.models.networkautomation import ConfigTemplate, NetworkManager
from src.utils.network_manager_class import NetworkManagerUtils
from werkzeug.utils import secure_filename
import os
from datetime import datetime


# Membuat blueprint main_bp dan error_bp
tm_bp = Blueprint("tm", __name__)
error_bp = Blueprint("error", __name__)
error_bp = Blueprint("error_handlers", __name__)


# Manangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("/main/404.html"), 404


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('You need to login first', 'info')
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function


# Context processor untuk menambahkan username ke dalam konteks disemua halaman.
@tm_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        user_id = current_user.id
        user = User.query.get(user_id)
        return dict(username=user.username)
    return dict(username=None)


# Network Manager App Starting
# Upload data template
RAW_TEMPLATE_FOLDER = "xmanager/raw_templates"
GEN_TEMPLATE_FOLDER = "xmanager/gen_templates"
UPLOAD_FOLDER = "network_templates"
TEMPLE_EXTENSIONS = {"j2"}
PARAMS_EXTENSIONS = {"yml", "yaml"}


# Templates route
@tm_bp.route("/tm", methods=["GET"])
@login_required
def templates():
    # Tampilkan all devices per_page 10
    page = request.args.get("page", 1, type=int)
    per_page = 10
    all_templates = ConfigTemplate.query.paginate(page=page, per_page=per_page)

    return render_template(
        "/template_managers/template_manager.html", all_templates=all_templates
    )


def allowed_file_temple(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in TEMPLE_EXTENSIONS


def allowed_file_params(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in PARAMS_EXTENSIONS


@tm_bp.route("/template_upload", methods=["GET", "POST"])
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
            flash("Data tidak boleh kosong!", "info")
            return redirect(request.url)

        # Cek apakah file dipilih
        if j2.filename == "" or yaml.filename == "":
            flash("No selected file", "error")
            return redirect(request.url)

        # Cek apakah file memiliki ekstensi yang diizinkan
        if j2 and allowed_file_temple(j2.filename):
            template_name = secure_filename(j2.filename)
            file_path = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, template_name
            )
            j2.save(file_path)
        else:
            flash("Jenis file yang dimasukkan tidak sesuai. hint j2.", "error")
            return redirect(url_for("tm.templates"))

        # Cek apakah file memiliki ekstensi yang diizinkan
        if yaml and allowed_file_params(yaml.filename):
            parameter_name = secure_filename(yaml.filename)
            file_path = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, parameter_name
            )
            yaml.save(file_path)
        else:
            flash("Jenis file yang dimasukkan tidak sesuai. hint yml, yaml.", "error")
            return redirect(url_for("tm.templates"))

        # Simpan data ke dalam database
        new_template = ConfigTemplate(
            template_name=template_name,
            parameter_name=parameter_name,
            vendor=vendor,
            version=version,
            info=info,
        )
        db.session.add(new_template)
        db.session.commit()

        flash("File berhasil upload.", "success")
        return redirect(url_for("tm.templates"))


# Templates update
@tm_bp.route("/template_update/<int:template_id>", methods=["GET", "POST"])
@login_required
def template_update(template_id):
    # 1. Dapatkan objek dari database berdasarkan ID
    template = ConfigTemplate.query.get_or_404(template_id)

    # Read file J2 template content
    def read_template(filename=template.template_name):
        template_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, filename
        )
        with open(template_path, "r") as file:
            template_content = file.read()
        return template_content

    # Read file YAML parameter content
    def read_parameter(filename=template.parameter_name):
        parameter_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, filename
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
                current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
            )
            with open(template_path, "w") as file:
                file.write(new_template_content)

        # 5.1 Update file parameter_content jika ada perubahan
        if new_parameter_content != read_parameter():
            parameter_path = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
            )
            with open(parameter_path, "w") as file:
                file.write(new_parameter_content)

        # 5.2 Update file name jika ada perubahan
        if new_template_name != template.template_name:
            # template_path
            new_path_template = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, new_template_name
            )

            # cek filename exsisting, filename tidak boleh sama dengan filename exsisting
            if os.path.exists(new_path_template):
                flash("File with the new name already exists.", "info")
            else:
                # old_path_template
                old_path_template = os.path.join(
                    current_app.static_folder,
                    RAW_TEMPLATE_FOLDER,
                    template.template_name,
                )
                os.rename(old_path_template, new_path_template)
                template.template_name = new_template_name

        # 5.2 Update file name jika ada perubahan
        if new_parameter_name != template.parameter_name:
            # parameter_path
            new_path_parameter = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, new_parameter_name
            )

            # cek filename exsisting, filename tidak boleh sama dengan filename exsisting
            if os.path.exists(new_path_parameter):
                flash("File with the new name already exists.", "info")
            else:
                # old_path_parameter
                old_path_parameter = os.path.join(
                    current_app.static_folder,
                    RAW_TEMPLATE_FOLDER,
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
        return redirect(url_for("tm.templates"))

    # 3. Tampilkan halaman template_update dengan data file di update page.
    return render_template(
        "/template_managers/template_update.html",
        template=template,
        template_content=template_content,
        parameter_content=parameter_content,
    )


# Templates delete
@tm_bp.route("/template_delete/<int:template_id>", methods=["POST"])
@login_required
def template_delete(template_id):

    # Dapatkan objek dari database berdasarkan ID
    template = ConfigTemplate.query.get_or_404(template_id)

    # Hapus file J2 template
    file_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, str(template.template_name)
    )
    if os.path.exists(file_path):
        os.remove(file_path)

    # Hapus file YAML parameter
    file_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, str(template.parameter_name)
    )
    if os.path.exists(file_path):
        os.remove(file_path)

    # Hapus data dari database
    db.session.delete(template)
    db.session.commit()

    # Redirect ke halaman templates
    return redirect(url_for("tm.templates"))


# Templates generator
@tm_bp.route("/template_generator/<int:template_id>", methods=["GET", "POST"])
@login_required
def template_generator(template_id):

    # Get template ID
    template = ConfigTemplate.query.get_or_404(template_id)

    # Path ke file template Jinja2
    jinja_template_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, str(template.template_name)
    )

    # Path ke file parameter YAML
    yaml_params_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, str(template.parameter_name)
    )

    # Baca isi file template Jinja2
    with open(jinja_template_path, "r") as jinja_template_file:
        jinja_template = jinja_template_file.read()

    # Baca isi file parameter YAML
    with open(yaml_params_path, "r") as yaml_params_file:
        yaml_params = yaml_params_file.read()

    # Render template Jinja2 dengan parameter YAML
    net_auto = NetworkManagerUtils(
        ip_address="0.0.0.0", username="none", password="none", ssh=22
    )
    rendered_config = net_auto.render_template_config(jinja_template, yaml_params)

    if rendered_config:
        now = datetime.now()
        date_time_string = now.strftime("%Y-%m-%d_%H-%M-%S")
        gen_filename = str(template.vendor)
        newFileName = gen_filename + "-" + date_time_string + ".txt"
        # Path ke file baru
        new_file_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, newFileName
        )

        # Tulis rendered_config ke file baru
        with open(new_file_path, "w") as new_file:
            new_file.write(rendered_config)

        # Simpan template generate ke dalam database network_manager
        new_template_generate = NetworkManager(template_name=newFileName)
        db.session.add(new_template_generate)
        db.session.commit()

        flash("Template berhasil di-generate.", "success")
    else:
        flash("Gagal merender template.", "error")

    return redirect(url_for("tm.templates"))
