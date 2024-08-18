from flask import (
    Blueprint,
    render_template,
    jsonify,
    request,
    current_app,
    copy_current_request_context,
    redirect,
    url_for,
    flash,
)
from src import db
from flask_login import login_required, current_user
from src.models.app_models import (
    DeviceManager,
    BackupData,
    UserBackupShare,
)
from src.utils.config_manager_utils import ConfigurationManagerUtils
import os
from .decorators import login_required, role_required, required_2fa
from flask_paginate import Pagination, get_page_args
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import json
import random
from datetime import datetime
import string

# Membuat blueprint untuk Backup Manager (backup_bp) dan Error Handling (error_bp)
backup_bp = Blueprint("backup", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging untuk aplikasi
logging.basicConfig(level=logging.INFO)


@backup_bp.before_app_request
def setup_logging():
    """Mengatur level logging untuk aplikasi."""
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


# Menangani error 404 menggunakan blueprint error_bp dan redirect ke 404.html page.
@error_bp.app_errorhandler(404)
def page_not_found(error):
    """Menangani error 404 dan menampilkan halaman 404."""
    current_app.logger.error(f"Error 404: {error}")
    return render_template("main/404.html"), 404


# Middleware untuk autentikasi dan otorisasi sebelum permintaan.
@backup_bp.before_request
def before_request_func():
    """Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan."""
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return jsonify({"message": "Unauthorized access"}), 401


# Context processor untuk menambahkan first_name dan last_name ke dalam konteks di semua halaman.
@backup_bp.context_processor
def inject_user():
    """Menyediakan first_name dan last_name pengguna yang terotentikasi ke dalam template."""
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


# --------------------------------------------------------------------------------
# Backup Management Section
# --------------------------------------------------------------------------------

BACKUP_FOLDER = "xmanager/backups"


# Fungsi pembantu untuk menghasilkan nama file acak
def generate_random_filename(filename):
    random_str = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    date_str = datetime.now().strftime("%d.%m.%Y_%H.%M.%S")
    filename = f"{filename}_{random_str}_{date_str}"
    current_app.logger.info(f"Generated random filename: {filename}")
    return filename


# Endpoint untuk menampilkan daftar backup yang dimiliki oleh pengguna saat ini
@backup_bp.route("/backups", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def backups():
    try:
        search_query = request.args.get("search", "")
        page, per_page, offset = get_page_args(
            page_parameter="page", per_page_parameter="per_page", per_page=10
        )

        backups_query = BackupData.query.filter_by(user_id=current_user.id)
        if search_query:
            backups_query = backups_query.filter(
                BackupData.backup_name.ilike(f"%{search_query}%")
            )

        total_backups = backups_query.count()
        backups = backups_query.limit(per_page).offset(offset).all()

        pagination = Pagination(
            page=page,
            per_page=per_page,
            total=total_backups,
        )

        current_app.logger.info(f"User {current_user.email} accessed backups page.")
        return render_template(
            "backup_managers/index.html",
            backups=backups,
            page=page,
            per_page=per_page,
            pagination=pagination,
            search_query=search_query,
            total_backups=total_backups,
        )
    except Exception as e:
        current_app.logger.error(f"Error accessing backups page: {e}")
        return (
            jsonify({"success": False, "message": "Failed to load backups page."}),
            500,
        )


@backup_bp.route("/backup/<int:backup_id>", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def get_backup_detail(backup_id):
    try:
        backup = BackupData.query.filter_by(
            id=backup_id, user_id=current_user.id
        ).first()
        if not backup:
            return jsonify({"success": False, "message": "Backup not found."}), 404

        backup_detail = {
            "backup_name": backup.backup_name,
            "backup_content_path": backup.backup_content_path,
            "version": backup.version,
            "created_at": backup.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return jsonify(backup_detail)
    except Exception as e:
        current_app.logger.error(f"Error retrieving backup detail: {e}")
        return (
            jsonify({"success": False, "message": "Failed to retrieve backup detail."}),
            500,
        )


# Endpoint untuk menampilkan form update dan mengupdate backup yang sudah ada
@backup_bp.route("/backup_update/<int:backup_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def backup_update(backup_id):
    try:
        backup = BackupData.query.filter_by(
            id=backup_id, user_id=current_user.id
        ).first()

        if not backup:
            current_app.logger.warning(
                f"Unauthorized or not found backup update attempt by {current_user.email} for backup ID {backup_id}."
            )
            return (
                jsonify(
                    {"success": False, "message": "Backup not found or unauthorized."}
                ),
                404,
            )

        if request.method == "GET":
            try:
                with open(backup.backup_content_path, "r") as file:
                    backup_content = file.read()
            except Exception as e:
                current_app.logger.error(f"Error reading backup file: {e}")
                backup_content = "Error reading backup file."

            return render_template(
                "backup_managers/backup_update.html",
                backup=backup,
                backup_content=backup_content,
            )

        if request.method == "POST":
            data = request.form

            new_backup_name = data.get("backup_name", backup.backup_name)
            new_backup_content = data.get("backup_content")

            if new_backup_name != backup.backup_name:
                new_backup_name = generate_random_filename(new_backup_name)
                backup.backup_name = new_backup_name

            if new_backup_content and new_backup_content != backup_content:
                try:
                    with open(backup.backup_content_path, "w") as file:
                        file.write(new_backup_content)
                    current_app.logger.info(
                        f"Backup content updated for {backup.backup_name}."
                    )
                except Exception as e:
                    current_app.logger.error(f"Error writing backup file: {e}")
                    return (
                        jsonify(
                            {
                                "success": False,
                                "message": "Failed to update backup content.",
                            }
                        ),
                        500,
                    )

            db.session.commit()
            current_app.logger.info(
                f"Backup ID {backup_id} updated by user {current_user.email}."
            )
            return redirect(url_for("backup.backups"))

    except Exception as e:
        current_app.logger.error(f"Error updating backup ID {backup_id}: {e}")
        db.session.rollback()
        return jsonify({"success": False, "message": "Failed to update backup."}), 500


# Endpoint untuk menghapus backup yang dimiliki oleh pengguna saat ini
@backup_bp.route("/backup_delete/<int:backup_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def delete_backup(backup_id):
    try:
        backup = BackupData.query.filter_by(
            id=backup_id, user_id=current_user.id
        ).first()

        if not backup:
            current_app.logger.warning(
                f"Unauthorized or not found backup delete attempt by {current_user.email} for backup ID {backup_id}."
            )
            return (
                jsonify(
                    {"success": False, "message": "Backup not found or unauthorized."}
                ),
                404,
            )

        try:
            backup_file_path = os.path.join(
                current_app.static_folder, BACKUP_FOLDER, backup.backup_name
            )
            if os.path.exists(backup_file_path):
                os.remove(backup_file_path)
                current_app.logger.info(
                    f"Backup file {backup.backup_name} deleted from filesystem."
                )
            else:
                current_app.logger.warning(
                    f"Backup file {backup.backup_name} not found on filesystem."
                )
        except Exception as e:
            current_app.logger.error(f"Error deleting backup file: {e}")
            return (
                jsonify({"success": False, "message": "Failed to delete backup file."}),
                500,
            )

        db.session.delete(backup)
        db.session.commit()
        current_app.logger.info(
            f"Backup ID {backup_id} deleted by user {current_user.email}."
        )
        flash(f"Backup successfully deleted by {current_user.email}", "success")
    except Exception as e:
        current_app.logger.error(f"Error deleting backup ID {backup_id}: {e}")
        db.session.rollback()
        flash(f"Backup deletion failed by {current_user.email}", "danger")
    return redirect(url_for("backup.backups"))


# Endpoint untuk berbagi backup dengan pengguna lain
@backup_bp.route("/share_backup/<int:backup_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def share_backup(backup_id):
    try:
        backup = BackupData.query.filter_by(
            id=backup_id, user_id=current_user.id
        ).first()

        if not backup:
            current_app.logger.warning(
                f"Unauthorized or not found backup share attempt by {current_user.email} for backup ID {backup_id}."
            )
            return (
                jsonify(
                    {"success": False, "message": "Backup not found or unauthorized."}
                ),
                404,
            )

        data = request.get_json()
        user_id_to_share = data.get("user_id")

        if not user_id_to_share:
            current_app.logger.warning(
                f"Missing user ID for backup share by {current_user.email}."
            )
            return (
                jsonify(
                    {"success": False, "message": "User ID to share with is required."}
                ),
                400,
            )

        new_share = UserBackupShare(user_id=user_id_to_share, backup_id=backup.id)
        db.session.add(new_share)
        db.session.commit()
        current_app.logger.info(
            f"Backup ID {backup_id} shared by {current_user.email} with user ID {user_id_to_share}."
        )
        return jsonify({"success": True, "message": "Backup shared successfully."}), 200
    except Exception as e:
        current_app.logger.error(f"Error sharing backup ID {backup_id}: {e}")
        db.session.rollback()
        return jsonify({"success": False, "message": "Failed to share backup."}), 500


# --------------------------------------------------------------------------------
# Fungsi Backup Perangkat Section
# --------------------------------------------------------------------------------


# Endpoint backup konfigurasi menu device yang akan di backup
@backup_bp.route("/backup_manager", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def backup_manager():
    try:
        search_query = request.args.get("search", "")

        page, per_page, offset = get_page_args(
            page_parameter="page", per_page_parameter="per_page", per_page=10
        )

        devices_query = DeviceManager.query.filter_by(user_id=current_user.id)
        if search_query:
            devices_query = devices_query.filter(
                DeviceManager.device_name.ilike(f"%{search_query}%")
                | DeviceManager.ip_address.ilike(f"%{search_query}%")
                | DeviceManager.vendor.ilike(f"%{search_query}%")
            )

        total_devices = devices_query.count()
        devices = devices_query.limit(per_page).offset(offset).all()

        subquery = (
            db.session.query(
                BackupData.backup_name,
                db.func.max(BackupData.version).label("latest_version"),
            )
            .filter(BackupData.user_id == current_user.id)
            .group_by(BackupData.backup_name)
            .subquery()
        )

        backups = (
            db.session.query(BackupData)
            .join(
                subquery,
                db.and_(
                    BackupData.backup_name == subquery.c.backup_name,
                    BackupData.version == subquery.c.latest_version,
                ),
            )
            .filter(BackupData.user_id == current_user.id)
            .all()
        )

        pagination = Pagination(
            page=page,
            per_page=per_page,
            total=total_devices,
        )

        current_app.logger.info(
            f"User {current_user.email} accessed backup manager page."
        )
        return render_template(
            "backup_managers/backup_manager.html",
            devices=devices,
            backups=backups,
            page=page,
            per_page=per_page,
            pagination=pagination,
            search_query=search_query,
            total_devices=total_devices,
        )
    except Exception as e:
        current_app.logger.error(f"Error accessing backup manager page: {e}")
        return (
            jsonify({"success": False, "message": "Failed to load backup manager."}),
            500,
        )


# Endpoint untuk backup konfigurasi perangkat
@backup_bp.route("/backup_config", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def backup_config():
    try:
        data = request.get_json()
        device_ips = data.get("devices", [])
        command = data.get("command")

        if not device_ips:
            current_app.logger.warning("No devices selected for backup.")
            return jsonify({"success": False, "message": "No devices selected."}), 400
        if not command:
            current_app.logger.warning("No command provided for backup.")
            return jsonify({"success": False, "message": "No command provided."}), 400

        devices = DeviceManager.query.filter(
            DeviceManager.ip_address.in_(device_ips),
            DeviceManager.user_id == current_user.id,
        ).all()

        if not devices:
            current_app.logger.warning(f"No devices found for IPs: {device_ips}")
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "No devices found for the provided IPs.",
                    }
                ),
                404,
            )

        results = []
        success = True

        @copy_current_request_context
        def configure_device(device):
            nonlocal success
            try:
                config_utils = ConfigurationManagerUtils(
                    ip_address=device.ip_address,
                    username=device.username,
                    password=device.password,
                    ssh=device.ssh,
                )
                response_json = config_utils.backup_configuration(command=command)
                response_dict = json.loads(response_json)
                backup_data = response_dict.get("message")

                filename_gen = (
                    f"{device.ip_address}_{device.vendor}_{device.device_name}"
                )
                random_filename = generate_random_filename(filename_gen)
                filename = f"{random_filename}.txt"
                path_backup = BACKUP_FOLDER
                file_path = os.path.join(
                    current_app.static_folder, path_backup, filename
                )

                if backup_data:
                    backup_data = (
                        backup_data.replace("\r\n", "\n").replace("\r", "\n").strip()
                    )
                with open(file_path, "w", encoding="utf-8") as backup_file:
                    backup_file.write(backup_data)
                current_app.logger.info(
                    f"Successfully saved backup content to file: {file_path}"
                )

                BackupData.create_backup(
                    backup_name=random_filename,
                    backup_content_path=file_path,
                    user_id=current_user.id,
                )

                if response_dict.get("status") == "success":
                    return {
                        "device_name": device.device_name,
                        "ip": device.ip_address,
                        "status": "success",
                        "message": "Backup sukses.",
                    }
                else:
                    return {
                        "device_name": device.device_name,
                        "ip": device.ip_address,
                        "status": response_dict.get("status", "error"),
                        "message": response_dict.get("message", "Backup gagal"),
                    }
            except json.JSONDecodeError as e:
                logging.error("Error decoding JSON response: %s", e)
                return {
                    "device_name": device.device_name,
                    "ip": device.ip_address,
                    "status": "error",
                    "message": "Error decoding JSON response",
                }
            except Exception as e:
                logging.error("Error configuring device %s: %s", device.ip_address, e)
                return {
                    "device_name": device.device_name,
                    "ip": device.ip_address,
                    "status": "error",
                    "message": str(e),
                }

        max_threads = 10
        with ThreadPoolExecutor(max_threads) as executor:
            futures = {
                executor.submit(configure_device, device): device for device in devices
            }

            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if result["status"] != "success":
                    success = False

        return jsonify({"success": success, "results": results})
    except Exception as e:
        current_app.logger.error(f"Error performing backup: {e}")
        return jsonify({"success": False, "message": "Failed to perform backup."}), 500
