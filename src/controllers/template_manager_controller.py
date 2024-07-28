from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app,
    jsonify,
)
from flask_login import login_required, current_user
from src import db
from src.models.xmanager_model import TemplateManager, ConfigurationManager
from src.utils.config_manager_utils import ConfigurationManagerUtils
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from .decorators import login_required, role_required
import random
import string
from flask_paginate import Pagination
import logging

# Blueprint untuk template manager
tm_bp = Blueprint("tm", __name__)
error_bp = Blueprint("error", __name__)


# Setup logging
logging.basicConfig(level=logging.INFO)


@tm_bp.before_app_request
def setup_logging():
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


# Menangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("main/404.html"), 404


# middleware untuk autentikasi dan otorisasi
@tm_bp.before_request
def before_request_func():
    if not current_user.is_authenticated:
        return jsonify({"message": "Unauthorized access"}), 401


# Context processor untuk menambahkan first_name dan last_name ke dalam konteks di semua halaman.
@tm_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")



# Folder untuk template
RAW_TEMPLATE_FOLDER = "xmanager/raw_templates"
GEN_TEMPLATE_FOLDER = "xmanager/gen_templates"
TEMPLE_EXTENSIONS = {"j2"}
PARAMS_EXTENSIONS = {"yml", "yaml"}


# Fungsi pembantu untuk menghasilkan nama file acak
def generate_random_filename(vendor_name):
    random_str = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{vendor_name}_{random_str}_{date_str}"


# Route untuk menampilkan daftar template
@tm_bp.route("/tm", methods=["GET"])
@login_required
@role_required(
    roles=["Admin", "User", "View"], permissions=["Manage Templates", "View Templates"], page="Templates Management"
)
def index():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    search_query = request.args.get("search", "")

    # Mencari template berdasarkan query pencarian
    query = TemplateManager.query
    if search_query:
        query = query.filter(
            TemplateManager.template_name.ilike(f"%{search_query}%")
            | TemplateManager.parameter_name.ilike(f"%{search_query}%")
            | TemplateManager.vendor.ilike(f"%{search_query}%")
            | TemplateManager.version.ilike(f"%{search_query}%")
        )

    all_templates = query.paginate(page=page, per_page=per_page)

    return render_template(
        "/template_managers/index.html",
        all_templates=all_templates,
        per_page=per_page,
        search_query=search_query,
    )


# Validasi ekstensi file untuk template dan parameter
def allowed_file_temple(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in TEMPLE_EXTENSIONS


def allowed_file_params(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in PARAMS_EXTENSIONS


# Route untuk meng-upload template
@tm_bp.route("/template_upload", methods=["POST"])
@login_required
@role_required(
    roles=["Admin", "User"], permissions=["Manage Templates"], page="Templates Management"
)
def template_upload():
    if "j2" not in request.files or "yaml" not in request.files:
        flash("No file part", "error")
        return redirect(request.url)

    j2 = request.files["j2"]
    yaml = request.files["yaml"]
    vendor = request.form.get("vendor")
    version = request.form.get("version")
    description = request.form.get("description")

    if not vendor or not version:
        flash("Data tidak boleh kosong!", "info")
        return redirect(request.url)

    if j2.filename and allowed_file_temple(j2.filename):
        template_name = secure_filename(j2.filename)
        file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, template_name
        )
        j2.save(file_path)
    else:
        flash("Jenis file yang dimasukkan tidak sesuai. hint j2.", "error")
        return redirect(request.url)

    if yaml.filename and allowed_file_params(yaml.filename):
        parameter_name = secure_filename(yaml.filename)
        file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, parameter_name
        )
        yaml.save(file_path)
    else:
        flash("Jenis file yang dimasukkan tidak sesuai. hint yml, yaml.", "error")
        return redirect(request.url)

    # Simpan data template ke database
    new_template = TemplateManager(
        template_name=template_name,
        parameter_name=parameter_name,
        vendor=vendor,
        version=version,
        description=description,
        created_by=current_user.username,
    )
    db.session.add(new_template)
    db.session.commit()

    flash("File berhasil upload.", "success")
    return redirect(url_for("tm.index"))


# Route untuk memperbarui template
@tm_bp.route("/template_update/<int:template_id>", methods=["GET", "POST"])
@login_required
@role_required(
    roles=["Admin", "User"], permissions=["Manage Templates"], page="Templates Management"
)
def template_update(template_id):
    template = TemplateManager.query.get_or_404(template_id)

    def read_file(filename):
        file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, filename
        )
        with open(file_path, "r") as file:
            return file.read()

    template_content = read_file(template.template_name)
    parameter_content = read_file(template.parameter_name)

    if request.method == "POST":
        new_template_name = request.form["template_name"]
        new_parameter_name = request.form["parameter_name"]
        new_vendor = request.form["vendor"]
        new_version = request.form["version"]
        new_description = request.form["description"]
        new_template_content = request.form["template_content"]
        new_parameter_content = request.form["parameter_content"]

        # Check if the new template or parameter name already exists in the database
        existing_template = TemplateManager.query.filter(
            TemplateManager.template_name == new_template_name,
            TemplateManager.id != template.id,
        ).first()
        existing_parameter = TemplateManager.query.filter(
            TemplateManager.parameter_name == new_parameter_name,
            TemplateManager.id != template.id,
        ).first()

        if existing_template:
            flash(f"Template name '{new_template_name}' already exists.", "danger")
            return redirect(url_for("tm.template_update", template_id=template_id))

        if existing_parameter:
            flash(f"Parameter name '{new_parameter_name}' already exists.", "danger")
            return redirect(url_for("tm.template_update", template_id=template_id))

        if new_template_content:
            # Gantikan semua jenis newline dengan newline Unix (\n) dan hapus newline tambahan di akhir
            new_template_content = (
                new_template_content.replace("\r\n", "\n").replace("\r", "\n").strip()
            )
        if new_parameter_content:
            # Gantikan semua jenis newline dengan newline Unix (\n) dan hapus newline tambahan di akhir
            new_parameter_content = (
                new_parameter_content.replace("\r\n", "\n").replace("\r", "\n").strip()
            )

        # Update konten file jika ada perubahan
        if new_template_content != read_file(template.template_name):
            template_path = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
            )
            with open(template_path, "w", encoding="utf-8") as file:
                file.write(new_template_content)

        if new_parameter_content != read_file(template.parameter_name):
            parameter_path = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
            )
            with open(parameter_path, "w", encoding="utf-8") as file:
                file.write(new_parameter_content)

        # Update nama file jika ada perubahan
        if new_template_name != template.template_name:
            new_path_template = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, new_template_name
            )
            old_path_template = os.path.join(
                current_app.static_folder,
                RAW_TEMPLATE_FOLDER,
                template.template_name,
            )
            os.rename(old_path_template, new_path_template)
            template.template_name = new_template_name

        if new_parameter_name != template.parameter_name:
            new_path_parameter = os.path.join(
                current_app.static_folder, RAW_TEMPLATE_FOLDER, new_parameter_name
            )
            old_path_parameter = os.path.join(
                current_app.static_folder,
                RAW_TEMPLATE_FOLDER,
                template.parameter_name,
            )
            os.rename(old_path_parameter, new_path_parameter)
            template.parameter_name = new_parameter_name

        # Update data template di database
        template.template_name = new_template_name
        template.parameter_name = new_parameter_name
        template.vendor = new_vendor
        template.version = new_version
        template.description = new_description

        db.session.commit()
        flash("Template update berhasil.", "success")
        return redirect(url_for("tm.index"))

    return render_template(
        "/template_managers/template_update.html",
        template=template,
        template_content=template_content,
        parameter_content=parameter_content,
    )


# Route untuk menghapus template
@tm_bp.route("/template_delete/<int:template_id>", methods=["POST"])
@login_required
@role_required(
    roles=["Admin", "User"], permissions=["Manage Templates"], page="Templates Management"
)
def template_delete(template_id):
    template = TemplateManager.query.get_or_404(template_id)

    # Hapus file template
    file_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
    )
    if os.path.exists(file_path):
        os.remove(file_path)

    # Hapus file parameter
    file_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
    )
    if os.path.exists(file_path):
        os.remove(file_path)

    # Hapus data dari database
    db.session.delete(template)
    db.session.commit()

    flash(f"Template berhasil dihapus oleh {current_user.username}", "success")
    return redirect(url_for("tm.index"))


# Route untuk menghasilkan template dari template Jinja dan parameter YAML
@tm_bp.route("/template_generator/<int:template_id>", methods=["POST"])
@login_required
@role_required(
    roles=["Admin", "User"], permissions=["Manage Templates"], page="Templates Management"
)
def template_generator(template_id):
    template = TemplateManager.query.get_or_404(template_id)

    jinja_template_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name
    )
    yaml_params_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name
    )

    # Baca konten template Jinja dan parameter YAML
    with open(jinja_template_path, "r") as jinja_template_file:
        jinja_template = jinja_template_file.read()

    with open(yaml_params_path, "r") as yaml_params_file:
        yaml_params = yaml_params_file.read()

    # Render template Jinja dengan parameter YAML
    net_auto = ConfigurationManagerUtils(
        ip_address="0.0.0.0", username="none", password="none", ssh=22
    )
    rendered_config = net_auto.render_template_config(jinja_template, yaml_params)

    if rendered_config:
        gen_filename = generate_random_filename(template.vendor)
        newFileName = f"{gen_filename}.txt"
        new_file_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, newFileName
        )
        description = f"{gen_filename} dibuat oleh {current_user.username}"

        # Simpan konfigurasi yang dirender ke file baru
        with open(new_file_path, "w") as new_file:
            new_file.write(rendered_config)

        # Simpan template yang dihasilkan ke database
        new_template_generate = ConfigurationManager(
            config_name=newFileName,
            description=description,
            created_by=current_user.username,
        )
        db.session.add(new_template_generate)
        db.session.commit()

        flash("Template berhasil di-generate.", "success")
    else:
        flash("Gagal merender template.", "error")

    return redirect(url_for("tm.index"))


# Route untuk melihat detail template
@tm_bp.route("/template_detail/<int:template_id>", methods=["GET"])
@login_required
@role_required(
    roles=["Admin", "User", "View"], permissions=["Manage Templates", "View Templates"], page="Templates Management"
)
def template_detail(template_id):
    template = TemplateManager.query.get_or_404(template_id)

    def read_file(filename):
        file_path = os.path.join(
            current_app.static_folder, RAW_TEMPLATE_FOLDER, filename
        )
        with open(file_path, "r") as file:
            return file.read()

    template_content = read_file(template.template_name)
    parameter_content = read_file(template.parameter_name)

    return render_template(
        "/template_managers/template_detail.html",
        template=template,
        template_content=template_content,
        parameter_content=parameter_content,
    )


# Route untuk membuat template manual
@tm_bp.route("/template_manual_create", methods=["POST"])
@login_required
@role_required(
    roles=["Admin", "User"], permissions=["Manage Templates"], page="Templates Management"
)
def template_manual_create():
    # Ambil data dari form
    vendor = request.form.get("vendor")
    version = request.form.get("version")
    description = request.form.get("description")
    template_content = request.form.get("template_content")
    parameter_content = request.form.get("parameter_content")

    # Validasi data vendor tidak boleh kosong
    if not vendor:
        flash("Data vendor tidak boleh kosong!", "info")
        return redirect(request.url)

    # Buat nama file dengan format vendor_tanggal
    gen_filename = generate_random_filename(vendor)
    template_filename = f"{gen_filename}.j2"
    parameter_filename = f"{gen_filename}.yml"

    # Tentukan path file
    template_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, template_filename
    )
    parameter_path = os.path.join(
        current_app.static_folder, RAW_TEMPLATE_FOLDER, parameter_filename
    )

    # Pastikan newline konsisten dan tidak ada newline tambahan
    if template_content:
        template_content = (
            template_content.replace("\r\n", "\n").replace("\r", "\n").strip()
        )
    if parameter_content:
        parameter_content = (
            parameter_content.replace("\r\n", "\n").replace("\r", "\n").strip()
        )

    # Simpan konten template ke dalam file
    with open(template_path, "w", encoding="utf-8") as template_file:
        template_file.write(template_content)

    # Simpan konten parameter ke dalam file
    with open(parameter_path, "w", encoding="utf-8") as parameter_file:
        parameter_file.write(parameter_content)

    # Simpan data ke dalam database
    new_template = TemplateManager(
        template_name=template_filename,
        parameter_name=parameter_filename,
        vendor=vendor,
        version=version,
        description=description,
        created_by=current_user.username,
    )
    db.session.add(new_template)
    db.session.commit()

    flash("Template berhasil dibuat.", "success")
    return redirect(url_for("tm.index"))


# File konfigurasi view page
@tm_bp.route("/template_results")
@login_required
@role_required(
    roles=["Admin", "User", "View"], permissions=["Manage Templates", "View Templates"], page="Configuration File Management"
)
def template_results():
    # Ambil halaman dan per halaman dari argumen URL
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    search_query = request.args.get("search", "")

    # Mencari template berdasarkan query pencarian
    query = ConfigurationManager.query
    if search_query:
        query = query.filter(
            ConfigurationManager.config_name.ilike(f"%{search_query}%")
            | ConfigurationManager.description.ilike(f"%{search_query}%")
        )

    # Mengambil total item dan pagination
    total_templates = query.count()
    all_templates = query.paginate(page=page, per_page=per_page)

    # Membuat objek pagination
    pagination = Pagination(
        page=page, per_page=per_page, total=total_templates, css_framework="bootstrap4"
    )

    # Read content for all templates
    template_contents = {}
    for template in all_templates.items:
        template_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, template.config_name
        )
        if os.path.exists(template_path):
            with open(template_path, "r", encoding="utf-8") as file:
                template_contents[template.id] = file.read()
        else:
            template_contents[template.id] = "File tidak ditemukan"

    return render_template(
        "/template_managers/template_results.html",
        all_templates=all_templates.items,
        template_contents=template_contents,
        per_page=per_page,
        search_query=search_query,
        pagination=pagination,
    )


# File konfigurasi update
@tm_bp.route(
    "/template_result_update/<int:template_result_id>", methods=["GET", "POST"]
)
@login_required
@role_required(
    roles=["Admin", "User"], permissions=["Manage Templates"], page="Configuration File Management"
)
def template_result_update(template_result_id):
    # 1. Dapatkan objek dari database berdasarkan ID
    template = ConfigurationManager.query.get_or_404(template_result_id)

    # Fungsi untuk membaca isi file template
    def read_template(filename):
        template_path = os.path.join(
            current_app.static_folder, GEN_TEMPLATE_FOLDER, filename
        )
        with open(template_path, "r", encoding="utf-8") as file:
            return file.read()

    # Membaca konten template
    template_content = read_template(template.config_name)

    # Ketika user mengirimkan form dengan method 'POST'
    if request.method == "POST":
        new_template_name = request.form["template_name"]
        new_description = request.form["description"]
        new_template_content = request.form["template_content"].strip()

        # Memastikan newline konsisten
        new_template_content = new_template_content.replace("\r\n", "\n").replace(
            "\r", "\n"
        )

        # 5.1 Update file template_content jika ada perubahan
        if new_template_content != template_content:
            template_path = os.path.join(
                current_app.static_folder, GEN_TEMPLATE_FOLDER, template.config_name
            )
            with open(template_path, "w", encoding="utf-8") as file:
                file.write(new_template_content)

        # 5.2 Update file name jika ada perubahan
        if new_template_name != template.config_name:
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
                    template.config_name,
                )
                os.rename(old_path_template, new_path_template)
                template.config_name = new_template_name

        # 5.3 Update data ke dalam database
        template.description = new_description
        template.config_name = new_template_name

        db.session.commit()
        flash("Template update berhasil.", "success")
        return redirect(url_for("tm.template_results"))

    # 3. Tampilkan halaman template_update dengan data file di update page.
    return render_template(
        "/template_managers/template_result_update.html",
        template=template,
        template_content=template_content,
    )


# File konfigurasi delete
@tm_bp.route("/template_result_delete/<int:template_id>", methods=["POST"])
@login_required
@role_required(
    roles=["Admin", "User"], permissions=["Manage Templates"], page="Configuration File Management"
)
def template_result_delete(template_id):

    # Dapatkan objek dari database berdasarkan ID
    template = ConfigurationManager.query.get_or_404(template_id)

    # Hapus file template
    file_path = os.path.join(
        current_app.static_folder, GEN_TEMPLATE_FOLDER, str(template.config_name)
    )
    if os.path.exists(file_path):
        os.remove(file_path)

    # Hapus data dari database
    db.session.delete(template)
    db.session.commit()

    # Redirect ke halaman templates
    return redirect(url_for("tm.template_results"))


# Route untuk membuat file konfigurasi manual
@tm_bp.route("/configuration_manual_create", methods=["POST"])
@login_required
@role_required(
    roles=["Admin", "User"], permissions=["Manage Templates"], page="Configuration File Management"
)
def configuration_manual_create():
    filename = request.form.get("filename")
    configuration_description = request.form.get("configuration_description")
    configuration_content = request.form.get("configuration_content")

    # Memastikan newline konsisten dan tidak ada newline tambahan
    if configuration_content:
        # Gantikan semua jenis newline dengan newline Unix (\n) dan hapus newline tambahan di akhir
        configuration_content = (
            configuration_content.replace("\r\n", "\n").replace("\r", "\n").strip()
        )

    # Cek jika data filename kosong
    if not filename:
        flash("Data tidak boleh kosong!", "info")
        return redirect(request.url)

    # Generate nama file dengan ekstensi .txt
    configuration_name = f"{filename}.txt"

    # Tentukan path file
    file_path = os.path.join(
        current_app.static_folder, GEN_TEMPLATE_FOLDER, configuration_name
    )

    # Simpan konten ke dalam file .txt
    with open(file_path, "w", encoding="utf-8") as configuration_file:
        configuration_file.write(configuration_content)

    # Simpan data ke dalam database
    new_configuration = ConfigurationManager(
        config_name=configuration_name,
        description=configuration_description,
        created_by=current_user.username,
    )
    db.session.add(new_configuration)
    db.session.commit()

    flash("File konfigurasi berhasil dibuat.", "success")
    return redirect(url_for("tm.template_results"))
