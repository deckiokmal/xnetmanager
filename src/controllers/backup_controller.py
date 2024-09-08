from flask import (
    Blueprint,
    render_template,
    jsonify,
    request,
    current_app,
)
from flask_login import (
    login_required,
    current_user,
)
from .decorators import (
    role_required,
    required_2fa,
)
from src import db
from src.models.app_models import (
    DeviceManager,
    BackupData,
    UserBackupShare,
    User,
    GitBackupVersion,
)
from src.utils.config_manager_utils import ConfigurationManagerUtils
from src.utils.git_version_utils import GitUtils
from src.utils.path_check_utils import check_path_compatibility
import os
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


@backup_bp.before_request
def before_request_func():
    """
    Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan.
    Jika tidak, mengembalikan pesan 'Unauthorized access'.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return render_template("main/404.html"), 404


@backup_bp.context_processor
def inject_user():
    """
    Menyediakan first_name dan last_name pengguna yang terotentikasi ke dalam template.
    """
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


# --------------------------------------------------------------------------------
# Backup Management Section
# --------------------------------------------------------------------------------

# Pengaturan BASE_FOLDER untuk pengembangan dan produksi
BASE_FOLDER = (
    os.path.abspath("D:\\0. MY PROJECT\\16. BYOAI PROJECT XNETMANAGER\\backups")
    if os.name == "nt"
    else "/app/backups"
)
BACKUP_FOLDER = BASE_FOLDER


# Modifikasi fungsi terkait path untuk menggunakan BASE_FOLDER dan user_id
def get_user_backup_folder(user_id):
    """
    Mengembalikan path ke folder backup untuk pengguna tertentu.
    Membuat folder jika belum ada.
    """
    user_backup_folder = os.path.join(BACKUP_FOLDER, str(user_id))
    if not os.path.exists(user_backup_folder):
        os.makedirs(user_backup_folder)
    return user_backup_folder


# Fungsi pembantu untuk menghasilkan nama file acak
def generate_random_filename(filename):
    random_str = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    date_str = datetime.now().strftime("%d.%m.%Y_%H.%M.%S")
    filename = f"{filename}_{random_str}_{date_str}"
    current_app.logger.info(f"Generated random filename: {filename}")
    return filename


@backup_bp.route("/backups")
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def backup_dashboard():
    devices = DeviceManager.query.filter_by(user_id=current_user.id).all()
    return render_template("backup_managers/backup_dashboard.html", devices=devices)


# Endpoint untuk Membuat Backup Baru
@backup_bp.route("/backup_create", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def create_backup():
    try:
        data = request.get_json()
        device_ips = data.get("devices", [])
        command = data.get("command")
        user_id = current_user.id

        if not device_ips or not command:
            return (
                jsonify({"status": "error", "message": "Devices or command missing."}),
                400,
            )

        devices = DeviceManager.query.filter(
            DeviceManager.ip_address.in_(device_ips), DeviceManager.user_id == user_id
        ).all()

        results = []
        backup_folder = get_user_backup_folder(user_id)

        for device in devices:
            config_utils = ConfigurationManagerUtils(
                ip_address=device.ip_address,
                username=device.username,
                password=device.password,
                ssh=device.ssh,
            )
            response_json = config_utils.backup_configuration(command=command)
            response_dict = json.loads(response_json)
            backup_data = response_dict.get("message")

            if response_dict.get("status") == "success" and backup_data:
                filename = generate_random_filename(device.device_name)
                file_path = os.path.join(backup_folder, filename)
                description = f"Backup created by {current_user.email}."

                with open(file_path, "w", encoding="utf-8") as backup_file:
                    backup_file.write(backup_data)

                backup = BackupData.create_backup(
                    backup_name=filename, description=description, user_id=user_id
                )

                git_utils = GitUtils(repo_path=backup_folder)
                commit_hash = git_utils.commit_backup(
                    file_path, f"Backup {filename} for {device.device_name}"
                )
                git_version = GitBackupVersion(
                    backup_id=backup.id,
                    commit_hash=commit_hash,
                    commit_message=f"Backup {filename} created.",
                    file_path=file_path,
                )
                db.session.add(git_version)
                db.session.commit()

                results.append(
                    {
                        "device_name": device.device_name,
                        "status": "success",
                        "message": "Backup successful.",
                        "file_path": file_path,
                    }
                )
            else:
                results.append(
                    {
                        "device_name": device.device_name,
                        "status": "error",
                        "message": response_dict.get("message", "Backup failed."),
                    }
                )

        return jsonify({"status": "success", "results": results})
    except Exception as e:
        current_app.logger.error(f"Error creating backup: {e}")
        return jsonify({"status": "error", "message": "Failed to create backup."}), 500


# Endpoint untuk Mengupdate Backup
@backup_bp.route("/backup_update/<backup_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def update_backup(backup_id):
    try:
        backup = BackupData.query.filter_by(
            id=backup_id, user_id=current_user.id
        ).first()
        if not backup:
            return (
                jsonify(
                    {"status": "error", "message": "Backup not found or unauthorized."}
                ),
                404,
            )

        backup_folder = get_user_backup_folder(current_user.id)
        data = request.form
        new_backup_content = data.get("backup_content")

        if new_backup_content:
            file_path = os.path.join(backup_folder, backup.backup_name)
            with open(file_path, "w", encoding="utf-8") as backup_file:
                backup_file.write(new_backup_content)

            git_utils = GitUtils(repo_path=backup_folder)
            commit_hash = git_utils.commit_backup(
                file_path, f"Update {backup.backup_name}"
            )
            git_version = GitBackupVersion(
                backup_id=backup.id,
                commit_hash=commit_hash,
                commit_message=f"Updated backup {backup.backup_name}.",
                file_path=file_path,
            )
            db.session.add(git_version)
            db.session.commit()

            return (
                jsonify(
                    {"status": "success", "message": "Backup updated successfully."}
                ),
                200,
            )

        return (
            jsonify({"status": "error", "message": "No content provided for update."}),
            400,
        )
    except Exception as e:
        current_app.logger.error(f"Error updating backup: {e}")
        db.session.rollback()
        return jsonify({"status": "error", "message": "Failed to update backup."}), 500


# Endpoint untuk Menghapus Backup
@backup_bp.route("/backup_delete/<backup_id>", methods=["DELETE"])
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
            return (
                jsonify(
                    {"status": "error", "message": "Backup not found or unauthorized."}
                ),
                404,
            )

        backup_folder = get_user_backup_folder(current_user.id)
        file_path = os.path.join(backup_folder, backup.backup_name)
        if os.path.exists(file_path):
            os.remove(file_path)

        GitBackupVersion.query.filter_by(backup_id=backup.id).delete()

        db.session.delete(backup)
        db.session.commit()
        return (
            jsonify({"status": "success", "message": "Backup deleted successfully."}),
            200,
        )
    except Exception as e:
        current_app.logger.error(f"Error deleting backup: {e}")
        db.session.rollback()
        return jsonify({"status": "error", "message": "Failed to delete backup."}), 500


# Endpoint untuk Rollback ke Versi Sebelumnya
@backup_bp.route("/rollback/<backup_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def rollback_backup(backup_id):
    try:
        backup = BackupData.query.filter_by(
            id=backup_id, user_id=current_user.id
        ).first()
        if not backup:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Backup not found or unauthorized.",
                        "device": "N/A",
                    }
                ),
                404,
            )

        version_id = request.json.get("version_id")
        git_version = GitBackupVersion.query.filter_by(
            id=version_id, backup_id=backup.id
        ).first()

        if not git_version:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Backup version not found.",
                        "device": backup.backup_name,
                    }
                ),
                404,
            )

        backup_folder = get_user_backup_folder(current_user.id)

        # Check path compatibility before performing any file operations
        if not check_path_compatibility(backup_folder):
            current_app.logger.error("Path compatibility check failed.")
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Path compatibility check failed.",
                        "device": "N/A",
                    }
                ),
                500,
            )

        git_utils = GitUtils(repo_path=backup_folder)
        git_utils.rollback_to_commit(git_version.commit_hash)

        # Push the configuration to the device
        device = DeviceManager.query.filter_by(
            user_id=current_user.id, device_name=backup.backup_name
        ).first()
        if not device:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Device not found.",
                        "device": backup.backup_name,
                    }
                ),
                404,
            )

        config_utils = ConfigurationManagerUtils(
            ip_address=device.ip_address,
            username=device.username,
            password=device.password,
            ssh=device.ssh,
        )
        with open(git_version.file_path, "r", encoding="utf-8") as file:
            command = file.read()
        response_json = config_utils.configure_device(command)
        response_dict = json.loads(response_json)

        if response_dict.get("status") == "success":
            return (
                jsonify({"status": "success", "message": "Rollback successful."}),
                200,
            )
        else:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Rollback failed.",
                        "device": device.device_name,
                    }
                ),
                500,
            )
    except Exception as e:
        current_app.logger.error(f"Error during rollback: {e}")
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Failed to perform rollback.",
                    "device": "N/A",
                }
            ),
            500,
        )


# Endpoint untuk Menampilkan Riwayat Backup
@backup_bp.route("/backup_history/<backup_id>", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def backup_history(backup_id):
    try:
        backup = BackupData.query.filter_by(id=backup_id).first()
        if not backup or (
            backup.user_id != current_user.id and not current_user.has_role("Admin")
        ):
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Backup not found or unauthorized.",
                        "device": "N/A",
                    }
                ),
                404,
            )

        git_utils = GitUtils(repo_path=get_user_backup_folder(backup.user_id))
        commits = git_utils.get_commit_history(max_count=10)
        commit_list = [
            {
                "hash": commit.hexsha,
                "message": commit.message,
                "date": commit.committed_datetime.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for commit in commits
        ]

        return jsonify({"status": "success", "commits": commit_list}), 200
    except Exception as e:
        current_app.logger.error(f"Error retrieving commit history: {e}")
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Failed to retrieve commit history.",
                    "device": "N/A",
                }
            ),
            500,
        )


# Endpoint untuk Mendapatkan Diff Antar Commit
@backup_bp.route("/backup_diff/<backup_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def backup_diff(backup_id):
    try:
        data = request.get_json()
        old_commit_hash = data.get("old_commit")
        new_commit_hash = data.get("new_commit")

        backup = BackupData.query.filter_by(id=backup_id).first()
        if not backup or (
            backup.user_id != current_user.id and not current_user.has_role("Admin")
        ):
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Backup not found or unauthorized.",
                        "device": "N/A",
                    }
                ),
                404,
            )

        git_utils = GitUtils(repo_path=get_user_backup_folder(backup.user_id))
        diff = git_utils.get_diff_between_commits(old_commit_hash, new_commit_hash)
        diff_content = "\n".join([str(d) for d in diff])

        return jsonify({"status": "success", "diff": diff_content}), 200
    except Exception as e:
        current_app.logger.error(f"Error retrieving diff between commits: {e}")
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Failed to get diff between commits.",
                    "device": "N/A",
                }
            ),
            500,
        )


# Endpoint untuk Mendapatkan Konten File pada Commit Tertentu
@backup_bp.route("/backup_file_at_commit/<backup_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def backup_file_at_commit(backup_id):
    try:
        data = request.get_json()
        commit_hash = data.get("commit_hash")

        backup = BackupData.query.filter_by(id=backup_id).first()
        if not backup or (
            backup.user_id != current_user.id and not current_user.has_role("Admin")
        ):
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Backup not found or unauthorized.",
                        "device": "N/A",
                    }
                ),
                404,
            )

        git_utils = GitUtils(repo_path=get_user_backup_folder(backup.user_id))
        file_content = git_utils.get_file_at_commit(backup.backup_name, commit_hash)

        return jsonify({"status": "success", "content": file_content}), 200
    except Exception as e:
        current_app.logger.error(f"Error retrieving file at commit: {e}")
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Failed to retrieve file at commit.",
                    "device": "N/A",
                }
            ),
            500,
        )


# Endpoint untuk Berbagi Backup dengan Pengguna Lain
@backup_bp.route("/share_backup/<backup_id>", methods=["POST"])
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
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Backup not found or unauthorized.",
                        "device": "N/A",
                    }
                ),
                404,
            )

        data = request.get_json()
        user_email = data.get("user_email")

        user_to_share = User.query.filter_by(email=user_email).first()
        if not user_to_share:
            return (
                jsonify(
                    {"status": "error", "message": "User not found.", "device": "N/A"}
                ),
                404,
            )

        new_share = UserBackupShare(user_id=user_to_share.id, backup_id=backup.id)
        db.session.add(new_share)
        db.session.commit()

        current_app.logger.info(
            f"Backup ID {backup_id} shared with user ID {user_to_share.id} by {current_user.email}."
        )

        return (
            jsonify({"status": "success", "message": "Backup shared successfully."}),
            200,
        )
    except Exception as e:
        current_app.logger.error(f"Error sharing backup: {e}")
        db.session.rollback()
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Failed to share backup.",
                    "device": "N/A",
                }
            ),
            500,
        )


# Endpoint untuk Menampilkan Backup yang Dibagikan
@backup_bp.route("/shared_backups", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Backups"], page="Backup Management"
)
def shared_backups():
    try:
        shared_backups_query = (
            db.session.query(BackupData)
            .join(UserBackupShare)
            .filter(UserBackupShare.user_id == current_user.id)
        )

        shared_backups = shared_backups_query.all()
        shared_backups_list = [
            {
                "backup_id": backup.id,
                "backup_name": backup.backup_name,
                "description": backup.description,
                "created_at": backup.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "version": backup.version,
            }
            for backup in shared_backups
        ]

        return (
            jsonify({"status": "success", "shared_backups": shared_backups_list}),
            200,
        )
    except Exception as e:
        current_app.logger.error(f"Error retrieving shared backups: {e}")
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Failed to retrieve shared backups.",
                    "device": "N/A",
                }
            ),
            500,
        )
