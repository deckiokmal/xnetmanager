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
from src import db
from src.models.users import User
from src.models.networkautomation import ConfigTemplate, NetworkManager
from src.utils.network_manager_class import NetworkManagerUtils
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from .decorators import login_required, role_required
import random
import string

# Blueprint untuk template manager
tm_bp = Blueprint("tm", __name__)

# Folder untuk template
RAW_TEMPLATE_FOLDER = "xmanager/raw_templates"
GEN_TEMPLATE_FOLDER = "xmanager/gen_templates"
TEMPLE_EXTENSIONS = {"j2"}
PARAMS_EXTENSIONS = {"yml", "yaml"}

# Fungsi pembantu untuk menghasilkan nama file acak
def generate_random_filename(vendor_name):
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{vendor_name}_{random_str}_{date_str}"

# Route untuk menampilkan daftar template
@tm_bp.route("/tm", methods=["GET"])
@login_required
def index():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    search_query = request.args.get("search", "")
    
    # Mencari template berdasarkan query pencarian
    query = ConfigTemplate.query
    if search_query:
        query = query.filter(
            ConfigTemplate.template_name.ilike(f"%{search_query}%") |
            ConfigTemplate.parameter_name.ilike(f"%{search_query}%") |
            ConfigTemplate.vendor.ilike(f"%{search_query}%") |
            ConfigTemplate.version.ilike(f"%{search_query}%")
        )
        
    all_templates = query.paginate(page=page, per_page=per_page)

    return render_template(
        "/template_managers/template_manager.html",
        all_templates=all_templates,
        per_page=per_page,
        search_query=search_query
    )

# Validasi ekstensi file untuk template dan parameter
def allowed_file_temple(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in TEMPLE_EXTENSIONS

def allowed_file_params(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in PARAMS_EXTENSIONS

# Route untuk meng-upload template
@tm_bp.route("/template_upload", methods=["POST"])
@login_required
def template_upload():
    if "j2" not in request.files or "yaml" not in request.files:
        flash("No file part", "error")
        return redirect(request.url)

    j2 = request.files["j2"]
    yaml = request.files["yaml"]
    vendor = request.form.get("vendor")
    version = request.form.get("version")
    info = request.form.get("info")

    if not vendor or not version or not info:
        flash("Data tidak boleh kosong!", "info")
        return redirect(request.url)

    if j2.filename and allowed_file_temple(j2.filename):
        template_name = secure_filename(j2.filename)
        file_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, template_name)
        j2.save(file_path)
    else:
        flash("Jenis file yang dimasukkan tidak sesuai. hint j2.", "error")
        return redirect(request.url)

    if yaml.filename and allowed_file_params(yaml.filename):
        parameter_name = secure_filename(yaml.filename)
        file_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, parameter_name)
        yaml.save(file_path)
    else:
        flash("Jenis file yang dimasukkan tidak sesuai. hint yml, yaml.", "error")
        return redirect(request.url)

    # Simpan data template ke database
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
    return redirect(url_for("tm.index"))

# Route untuk memperbarui template
@tm_bp.route("/template_update/<int:template_id>", methods=["GET", "POST"])
@login_required
def template_update(template_id):
    template = ConfigTemplate.query.get_or_404(template_id)

    def read_file(filename):
        file_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, filename)
        with open(file_path, "r") as file:
            return file.read()

    template_content = read_file(template.template_name)
    parameter_content = read_file(template.parameter_name)

    if request.method == "POST":
        new_template_name = request.form["template_name"]
        new_parameter_name = request.form["parameter_name"]
        new_vendor = request.form["vendor"]
        new_version = request.form["version"]
        new_info = request.form["info"]
        new_template_content = request.form["template_content"]
        new_parameter_content = request.form["parameter_content"]

        # Update konten file jika ada perubahan
        if new_template_content != read_file(template.template_name):
            template_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name)
            with open(template_path, "w") as file:
                file.write(new_template_content)

        if new_parameter_content != read_file(template.parameter_name):
            parameter_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name)
            with open(parameter_path, "w") as file:
                file.write(new_parameter_content)

        # Update nama file jika ada perubahan
        if new_template_name != template.template_name:
            new_path_template = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, new_template_name)
            if os.path.exists(new_path_template):
                flash("File with the new name already exists.", "info")
            else:
                old_path_template = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name)
                os.rename(old_path_template, new_path_template)
                template.template_name = new_template_name

        if new_parameter_name != template.parameter_name:
            new_path_parameter = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, new_parameter_name)
            if os.path.exists(new_path_parameter):
                flash("File with the new name already exists.", "info")
            else:
                old_path_parameter = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name)
                os.rename(old_path_parameter, new_path_parameter)
                template.parameter_name = new_parameter_name

        # Update data template di database
        template.template_name = new_template_name
        template.parameter_name = new_parameter_name
        template.vendor = new_vendor
        template.version = new_version
        template.info = new_info

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
@role_required('Admin', 'template_delete')
def template_delete(template_id):
    template = ConfigTemplate.query.get_or_404(template_id)

    # Hapus file template
    file_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name)
    if os.path.exists(file_path):
        os.remove(file_path)

    # Hapus file parameter
    file_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name)
    if os.path.exists(file_path):
        os.remove(file_path)

    # Hapus data dari database
    db.session.delete(template)
    db.session.commit()

    flash("Template berhasil dihapus.", "success")
    return redirect(url_for("tm.index"))

# Route untuk menghasilkan template dari template Jinja dan parameter YAML
@tm_bp.route("/template_generator/<int:template_id>", methods=["POST"])
@login_required
def template_generator(template_id):
    template = ConfigTemplate.query.get_or_404(template_id)

    jinja_template_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, template.template_name)
    yaml_params_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, template.parameter_name)

    # Baca konten template Jinja dan parameter YAML
    with open(jinja_template_path, "r") as jinja_template_file:
        jinja_template = jinja_template_file.read()

    with open(yaml_params_path, "r") as yaml_params_file:
        yaml_params = yaml_params_file.read()

    # Render template Jinja dengan parameter YAML
    net_auto = NetworkManagerUtils(
        ip_address="0.0.0.0", username="none", password="none", ssh=22
    )
    rendered_config = net_auto.render_template_config(jinja_template, yaml_params)

    if rendered_config:
        now = datetime.now()
        date_time_string = now.strftime("%Y%m%d_%H%M%S")
        gen_filename = generate_random_filename(template.vendor)
        newFileName = f"{gen_filename}.txt"
        new_file_path = os.path.join(current_app.static_folder, GEN_TEMPLATE_FOLDER, newFileName)

        # Simpan konfigurasi yang dirender ke file baru
        with open(new_file_path, "w") as new_file:
            new_file.write(rendered_config)

        # Simpan template yang dihasilkan ke database
        new_template_generate = NetworkManager(template_name=newFileName)
        db.session.add(new_template_generate)
        db.session.commit()

        flash("Template berhasil di-generate.", "success")
    else:
        flash("Gagal merender template.", "error")

    return redirect(url_for("tm.index"))

# Route untuk melihat detail template
@tm_bp.route("/template_detail/<int:template_id>", methods=["GET"])
@login_required
def template_detail(template_id):
    template = ConfigTemplate.query.get_or_404(template_id)

    def read_file(filename):
        file_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, filename)
        with open(file_path, "r") as file:
            return file.read()

    template_content = read_file(template.template_name)
    parameter_content = read_file(template.parameter_name)

    return render_template(
        "/template_managers/template_detail.html",
        template=template,
        template_content=template_content,
        parameter_content=parameter_content
    )

# Route untuk membuat template manual
@tm_bp.route("/template_manual_create", methods=["POST"])
@login_required
def template_manual_create():
    vendor = request.form.get("vendor")
    version = request.form.get("version")
    info = request.form.get("info")
    template_content = request.form.get("template_content")
    parameter_content = request.form.get("parameter_content")

    if not vendor or not version or not info:
        flash("Data tidak boleh kosong!", "info")
        return redirect(request.url)

    template_name = f"{generate_random_filename(vendor)}.j2"
    parameter_name = f"{generate_random_filename(vendor)}.yaml"

    template_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, template_name)
    parameter_path = os.path.join(current_app.static_folder, RAW_TEMPLATE_FOLDER, parameter_name)

    with open(template_path, "w") as template_file:
        template_file.write(template_content)

    with open(parameter_path, "w") as parameter_file:
        parameter_file.write(parameter_content)

    new_template = ConfigTemplate(
        template_name=template_name,
        parameter_name=parameter_name,
        vendor=vendor,
        version=version,
        info=info,
    )
    db.session.add(new_template)
    db.session.commit()

    flash("Template berhasil dibuat.", "success")
    return redirect(url_for("tm.index"))
