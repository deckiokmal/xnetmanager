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
from src import db
from src.models.app_models import DeviceManager
from .decorators import login_required, role_required, required_2fa
from src.utils.forms_utils import DeviceForm, DeviceUpdateForm
from flask_paginate import Pagination, get_page_args
import logging

# Membuat blueprint untuk device manager
dm_bp = Blueprint("dm", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging untuk aplikasi
logging.basicConfig(level=logging.INFO)


@dm_bp.before_app_request
def setup_logging():
    """
    Mengatur level logging untuk aplikasi.
    """
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


@error_bp.app_errorhandler(404)
def page_not_found(error):
    """
    Menangani error 404 dan menampilkan halaman 404.
    """
    current_app.logger.error(f"Error 404: {error}")
    return render_template("main/404.html"), 404


@dm_bp.before_request
def before_request_func():
    """
    Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan.
    Jika tidak, mengembalikan pesan 'Unauthorized access'.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return jsonify({"message": "Unauthorized access"}), 401


@dm_bp.context_processor
def inject_user():
    """
    Menyediakan first_name dan last_name pengguna yang terotentikasi ke dalam template.
    """
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


# -----------------------------------------------------------
# Devices Manager Section
# -----------------------------------------------------------


@dm_bp.route("/dm", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Devices", "View Devices"],
    page="Devices Management",
)
def index():
    """Menampilkan halaman utama Device Manager dengan data perangkat dan pagination"""
    form = DeviceForm(request.form)

    search_query = request.args.get("search", "").lower()

    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    if search_query:
        devices_query = DeviceManager.query.filter(
            DeviceManager.device_name.ilike(f"%{search_query}%")
            | DeviceManager.ip_address.ilike(f"%{search_query}%")
            | DeviceManager.vendor.ilike(f"%{search_query}%")
            | DeviceManager.description.ilike(f"%{search_query}%")
            | DeviceManager.created_by.ilike(f"%{search_query}%")
        )
    else:
        devices_query = DeviceManager.query

    total_devices = devices_query.count()
    devices = devices_query.limit(per_page).offset(offset).all()

    pagination = Pagination(page=page, per_page=per_page, total=total_devices)

    current_app.logger.info(f"User {current_user.email} accessed Device Manager page.")

    return render_template(
        "/device_managers/index.html",
        devices=devices,
        page=page,
        per_page=per_page,
        pagination=pagination,
        search_query=search_query,
        total_devices=total_devices,
        form=form,
    )


@dm_bp.route("/device_create", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def device_create():
    """Menambahkan perangkat baru ke dalam database"""
    form = DeviceForm(request.form)

    if request.method == "POST":
        if form.validate_on_submit():
            try:
                # Accessing .data attribute to get the actual input value
                exist_address = DeviceManager.query.filter_by(
                    ip_address=form.ip_address.data
                ).first()
                exist_device = DeviceManager.query.filter_by(
                    device_name=form.device_name.data
                ).first()

                if exist_device or exist_address:
                    flash("Device sudah terdaftar!", "info")
                    current_app.logger.info(
                        f"Duplicate device attempt: {form.device_name.data} or {form.ip_address.data}"
                    )
                else:
                    new_device = DeviceManager(
                        device_name=form.device_name.data.strip(),
                        vendor=form.vendor.data.strip(),
                        ip_address=form.ip_address.data.strip(),
                        username=form.username.data.strip(),
                        password=form.password.data.strip(),
                        ssh=form.ssh.data.strip(),
                        description=form.description.data.strip(),
                        created_by=current_user.email,
                    )
                    db.session.add(new_device)
                    db.session.commit()
                    flash("Device berhasil ditambah!", "success")
                    current_app.logger.info(
                        f"Device created: {form.device_name.data.strip()} by {current_user.email}"
                    )
                    return redirect(url_for("dm.index"))
            except Exception as e:
                current_app.logger.error(
                    f"Error creating device {form.device_name.data.strip()}: {str(e)}"
                )
                flash("An error occurred while creating the device.", "danger")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(
                        f"Error in {getattr(form, field).label.text}: {error}", "danger"
                    )
            current_app.logger.warning("Form validation failed during device creation.")

    return redirect(url_for("dm.index"))


@dm_bp.route("/device_update/<int:device_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def device_update(device_id):
    """Mengupdate informasi perangkat di database"""
    device = DeviceManager.query.get_or_404(device_id)

    # Load existing data into the form
    form = DeviceUpdateForm(obj=device)

    if request.method == "POST":
        if form.validate_on_submit():
            try:
                # Check if the password field is not empty
                if form.password.data:
                    # Update password if the field is filled
                    device.password = form.password.data.strip()
                    current_app.logger.info(
                        f"Password updated for Device ID {device_id} by {current_user.email}"
                    )
                else:
                    # Keep the existing password if the field is empty
                    current_app.logger.info(
                        f"Password unchanged for Device ID {device_id} updated by {current_user.email}"
                    )

                # Update the other fields, except password
                device.device_name = form.device_name.data.strip()
                device.vendor = form.vendor.data.strip()
                device.ip_address = form.ip_address.data.strip()
                device.username = form.username.data.strip()
                device.ssh = form.ssh.data.strip()
                device.description = form.description.data.strip()

                # Commit all the changes to the database
                db.session.commit()
                flash("Device update berhasil.", "success")
                current_app.logger.info(
                    f"Device ID {device_id} updated by {current_user.email}"
                )
                return redirect(url_for("dm.index"))
            except Exception as e:
                current_app.logger.error(
                    f"Error updating device ID {device_id}: {str(e)}"
                )
                flash("An error occurred while updating the device.", "danger")
        else:
            # Flashing individual field errors
            for field, errors in form.errors.items():
                for error in errors:
                    flash(
                        f"Error in {getattr(form, field).label.text}: {error}", "danger"
                    )
            current_app.logger.warning(
                f"Form validation failed during device update for device ID {device_id}."
            )

    # Set a placeholder text to indicate that the password is already set
    form.password.render_kw = {
        "placeholder": "Enter new password if you want to change it"
    }

    return render_template(
        "/device_managers/device_update.html", form=form, device=device
    )


@dm_bp.route("/device_delete/<int:device_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def device_delete(device_id):
    """Menghapus perangkat dari database"""
    try:
        device = DeviceManager.query.get_or_404(device_id)
        db.session.delete(device)
        db.session.commit()
        flash("Device telah dihapus.", "success")
        current_app.logger.info(
            f"Device ID {device_id} deleted by {current_user.email}"
        )
    except Exception as e:
        current_app.logger.error(f"Error deleting device ID {device_id}: {str(e)}")
        flash("An error occurred while deleting the device.", "danger")

    return redirect(url_for("dm.index"))


# -----------------------------------------------------------
# API Devices Section
# -----------------------------------------------------------


@dm_bp.route("/api/get_devices", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def get_devices():
    """Mendapatkan data semua perangkat dalam format JSON"""
    devices = DeviceManager.query.all()
    device_list = [
        {
            "id": device.id,
            "device_name": device.device_name,
            "vendor": device.vendor,
            "ip_address": device.ip_address,
            "username": device.username,
            "password": device.password,
            "ssh": device.ssh,
            "description": device.description,
        }
        for device in devices
    ]
    current_app.logger.info(f"User {current_user.email} retrieved all devices data.")
    return jsonify({"devices": device_list})


@dm_bp.route("/api/get_device_data/<int:device_id>")
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def get_device_data(device_id):
    """Mendapatkan data perangkat berdasarkan ID dalam format JSON"""
    try:
        device = DeviceManager.query.get_or_404(device_id)
        current_app.logger.info(
            f"User {current_user.email} accessed data for device ID {device_id}"
        )
        return jsonify(
            {
                "ip_address": device.ip_address,
                "username": device.username,
                "password": device.password,
                "ssh": device.ssh,
                "device_name": device.device_name,
                "vendor": device.vendor,
                "description": device.description,
            }
        )
    except Exception as e:
        current_app.logger.error(f"Error retrieving device ID {device_id}: {str(e)}")
        return jsonify({"error": "Data tidak ditemukan"}), 404
