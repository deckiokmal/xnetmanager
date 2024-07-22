from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
)
from flask_login import login_required, current_user
from src import db, bcrypt
from src.models.users import User, Role, User_role
from src.models.networkautomation import DeviceManager, NetworkManager, ConfigTemplate
from src.utils.forms import RegisterForm
from .decorators import login_required, role_required


# Membuat blueprint users
users_bp = Blueprint("users", __name__)
error_bp = Blueprint("error", __name__)
error_bp = Blueprint("error_handlers", __name__)


# Manangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    return render_template("/main/404.html"), 404


# Context processor untuk menambahkan username ke dalam konteks disemua halaman.
@users_bp.context_processor
def inject_user():
    if current_user.is_authenticated:
        user_id = current_user.id
        user = User.query.get(user_id)
        return dict(username=user.username)
    return dict(username=None)


# Users App Starting


# Menampilkan halaman dashboard setelah user login success.
@users_bp.route("/")
@login_required
def dashboard():
    # Mengambil semua perangkat dan template konfigurasi dari database
    devices = DeviceManager.query.all()
    templates = ConfigTemplate.query.all()

    # Menghitung jumlah perangkat berdasarkan vendor
    device_vendor_count = {}
    for device in devices:
        vendor = device.vendor
        if vendor in device_vendor_count:
            device_vendor_count[vendor] += 1
        else:
            device_vendor_count[vendor] = 1
    
    # Menghitung jumlah template berdasarkan vendor
    template_vendor_count = {}
    for template in templates:
        vendor = template.vendor
        if vendor in template_vendor_count:
            template_vendor_count[vendor] += 1
        else:
            template_vendor_count[vendor] = 1

    return render_template(
        "/users/dashboard.html",
        device_vendor_keys=list(device_vendor_count.keys()),
        device_vendor_values=list(device_vendor_count.values()),
        template_vendor_keys=list(template_vendor_count.keys()),
        template_vendor_values=list(template_vendor_count.values()),
    )


# Users Management Page
@users_bp.route("/users", methods=["GET", "POST"])
@login_required
@role_required("Admin", "users")
def index():
    # Tampilkan all users per_page 10
    page = request.args.get("page", 1, type=int)
    per_page = 10
    all_users = User.query.paginate(page=page, per_page=per_page)

    # Modal Form Create users
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        try:
            # Buat objek User baru dan simpan ke database
            user = User(username=form.username.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()

            return redirect(url_for("users.index"))
        except Exception:
            # Jika registrasi gagal, batalkan perubahan dan beri pesan kesalahan
            db.session.rollback()
            flash("Registration failed. Please try again.", "error")

    return render_template("/users/user_manager.html", data=all_users, form=form)


# Update user
@users_bp.route("/user_update/<int:user_id>", methods=["GET", "POST"])
@login_required
def user_update(user_id):
    # Mengambil objek User berdasarkan user_id
    user = User.query.get(user_id)

    # Jika metode request adalah POST, proses update user
    if request.method == "POST":
        new_username = request.form["username"]
        old_password = request.form["password-input"]
        new_password = request.form["newpassword-input1"]
        repeat_new_password = request.form["newpassword-input2"]

        # Memeriksa apakah username baru sudah ada di database
        exist_user = User.query.filter(
            User.username == new_username, User.id != user.id
        ).first()
        if exist_user:
            flash("Username already exists. Please choose another username!", "info")

        # Memeriksa apakah password lama tidak kosong
        if not old_password:
            flash("Password must not be empty.", "error")
            return render_template("/users/user_update.html", user=user)

        # Memeriksa apakah password lama benar
        if not bcrypt.check_password_hash(user.password, old_password):
            flash("Incorrect password!", "error")
            return render_template("/users/user_update.html", user=user)
        else:
            # Memeriksa apakah new_password sama dengan repeat_new_password
            if new_password != repeat_new_password:
                flash("New passwords do not match.", "error")
                return render_template("/users/user_update.html", user=user)

            # Mengupdate password baru jika valid
            if new_password:
                user.password = bcrypt.generate_password_hash(new_password).decode(
                    "utf-8"
                )

            # Mengupdate username dan password baru jika valid
            user.username = new_username

            # Commit perubahan ke database
            db.session.commit()
            flash("User edited successfully.", "success")
            return redirect(url_for("users.index"))

    # Render halaman update user dengan data user yang akan diupdate
    return render_template("/users/user_update.html", user=user)


# Delete user
@users_bp.route("/user_delete/<int:user_id>", methods=["POST"])
@login_required
@role_required("Admin", "user_delete")
def user_delete(user_id):
    if current_user.id == user_id:
        flash("Anda tidak bisa delete akun anda sendiri.", "warning")
        return redirect(url_for("users.index"))

    user = User.query.get(user_id)
    if not user:
        flash("User tidak ditemukan.", "info")
        return redirect(url_for("users.index"))

    db.session.delete(user)
    db.session.commit()
    flash("User telah dihapus.", "success")
    return redirect(url_for("users.index"))


# Users profile
@users_bp.route("/user_profile", methods=["GET", "POST"])
@login_required
def user_profile():
    # Get data current user
    user_id = current_user.id
    user = User.query.get(user_id)

    return render_template("/users/user_profile.html", user=user)


# Users Role Page
@users_bp.route("/user_role", methods=["GET", "POST"])
@login_required
@role_required("Admin", "user_role")
def roles():
    # Tampilkan all user role per_page 10
    page = request.args.get("page", 1, type=int)
    per_page = 10
    all_role = Role.query.paginate(page=page, per_page=per_page)

    return render_template("/users/role_users.html", all_role=all_role)


# Create role
@users_bp.route("/create_role", methods=["GET", "POST"])
@login_required
@role_required("Admin", "create_role")
def create_role():
    if request.method == "POST":
        role_name = request.form["name"]
        role_permissions = request.form["permissions"]

        # 1. existing role name check
        exist_role = Role.query.filter_by(name=role_name).first()
        if exist_role:
            flash("Role sudah ada!", "error")

        # 2. name dan permissions field check. - user tidak boleh input data kosong.
        elif not role_name or not role_permissions:
            flash("role name dan permissions tidak boleh kosong!", "warning")

        # jika error checking null, maka eksekusi create_role
        else:
            new_role = Role(
                name=role_name,
                permissions=role_permissions,
            )
            db.session.add(new_role)
            db.session.commit()
            flash("Role berhasil ditambah!", "success")

            # kembali ke index
            return redirect(url_for("users.roles"))

    return redirect(url_for("users.roles"))


# Role Update
@users_bp.route("/role_update/<int:role_id>", methods=["GET", "POST"])
@login_required
@role_required("Admin", "role_update")
def role_update(role_id):
    # Mengambil objek Role berdasarkan role_id
    role = Role.query.get(role_id)

    # Jika metode request adalah POST, proses update role
    if request.method == "POST":
        role_name = request.form["name"]
        role_permissions = request.form["permissions"]

        # 1. existing role name check
        exist_role = Role.query.filter(
            Role.id != role.id, Role.name == role_name
        ).first()
        if exist_role:
            flash("Role dengan nama tersebut sudah ada!", "error")
        else:
            # Mengupdate data role name
            role.name = role_name
            role.permissions = role_permissions

            # Commit perubahan ke database
            db.session.commit()
            flash("Role berhasil diubah.", "success")
            return redirect(url_for("users.roles"))

    # Render halaman update user dengan data user yang akan diupdate
    return render_template("/users/role_update.html", role=role)


# Role Delete
@users_bp.route("/role_delete/<int:role_id>", methods=["POST"])
@login_required
@role_required("Admin", "role_delete")
def role_delete(role_id):
    role = Role.query.get_or_404(role_id)

    if role.users.count(role.users) > 0:
        flash(
            "Role tidak dapat dihapus karena masih terasosiasi dengan pengguna.",
            "warning",
        )
        return redirect(url_for("users.roles"))

    db.session.delete(role)
    db.session.commit()
    flash("Role berhasil dihapus.", "success")
    return redirect(url_for("users.roles"))


# tambah user to role
@users_bp.route("/add_user_to_role", methods=["POST"])
@login_required
@role_required("Admin", "add_user_to_role")
def add_user_to_role():
    if request.method == "POST":
        username = request.form["username"]
        role_name = request.form["role_name"]

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"})

        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return jsonify({"status": "error", "message": "Role not found"})

        user_role = User_role(user_id=user.id, role_id=role.id)
        db.session.add(user_role)
        db.session.commit()

        return jsonify(
            {
                "status": "success",
                "message": f"User {username} berhasil ditambahkan ke role {role_name}.",
            }
        )

    return jsonify({"status": "error", "message": "Invalid request"})
