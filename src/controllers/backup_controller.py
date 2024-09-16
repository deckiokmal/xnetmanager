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
from flask_login import login_required, current_user, logout_user
from src.models.app_models import (
    BackupData,
    UserBackupShare,
    GitBackupVersion,
    BackupTag,
    BackupAuditLog,
    DeviceManager,
    User,
)
from src.utils.backupUtils import BackupUtils
from .decorators import login_required, role_required, required_2fa
from flask_paginate import Pagination, get_page_args
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from datetime import datetime
from flask import copy_current_request_context
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
from src.utils.forms_utils import UpdateBackupForm
from src.utils.config_manager_utils import ConfigurationManagerUtils

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
    """
    Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan.
    Jika pengguna harus logout paksa, lakukan logout dan arahkan ke halaman login.
    Jika tidak terotentikasi, kembalikan pesan 'Unauthorized access'.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return render_template("main/404.html"), 404

    # Jika pengguna terotentikasi dan memiliki flag force_logout, lakukan logout
    if current_user.force_logout:
        current_user.force_logout = False  # Reset the flag
        db.session.commit()
        logout_user()
        flash("Your password has been updated. Please log in again.", "info")
        return redirect(url_for("main.login"))


# Context processor untuk menambahkan first_name dan last_name ke dalam konteks di semua halaman.
@backup_bp.context_processor
def inject_user():
    """Menyediakan first_name dan last_name pengguna yang terotentikasi ke dalam template."""
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(first_name="", last_name="")


# ------------------------------------------------------------
# CRUD OPERATIONS for BackupData
# ------------------------------------------------------------


# Read/List Backups
@backup_bp.route("/backups", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User", "View"],
    permissions=["Manage Backups"],
    page="Index Backups",
)
def index():
    # Logging untuk akses ke endpoint
    current_app.logger.info(f"{current_user.email} accessed Index Backups")

    # Search Function
    search_query = request.args.get("search", "").lower()
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )
    if page < 1 or per_page < 1:
        flash("Invalid pagination values.", "danger")

    try:
        # Query untuk BackupData
        if current_user.has_role("Admin"):
            backups_query = BackupData.query
        else:
            # Backup yang dimiliki oleh pengguna
            backups_query = BackupData.query.filter_by(user_id=current_user.id)

            # Backup yang di-share dengan pengguna
            shared_backups_query = BackupData.query.join(
                UserBackupShare, UserBackupShare.backup_id == BackupData.id
            ).filter(UserBackupShare.user_id == current_user.id)

            # Gabungkan backup yang dimiliki dengan yang di-share
            backups_query = backups_query.union(shared_backups_query)

        # Lakukan join dengan tabel DeviceManager agar bisa melakukan pencarian device_name
        backups_query = backups_query.join(
            DeviceManager, BackupData.device_id == DeviceManager.id
        )

        # Jika ada pencarian, tambahkan filter untuk device_name, backup_name, atau backup_type
        if search_query:
            backups_query = backups_query.filter(
                BackupData.backup_name.ilike(f"%{search_query}%")
                | BackupData.backup_type.ilike(f"%{search_query}%")
                | DeviceManager.device_name.ilike(f"%{search_query}%")
            )

        # Lakukan eager loading untuk menghindari query N+1 dan mengambil data device
        backups_query = backups_query.options(joinedload(BackupData.device))

        # Pagination dan Backups query
        total_backups = backups_query.count()
        backups = backups_query.limit(per_page).offset(offset).all()
        pagination = Pagination(page=page, per_page=per_page, total=total_backups)

        if total_backups == 0:
            flash("Tidak ada backups apapun di halaman ini.", "info")

        return render_template(
            "backup_managers/index.html",
            backups=backups,
            page=page,
            per_page=per_page,
            pagination=pagination,
            search_query=search_query,
            total_backups=total_backups,
        )
    except SQLAlchemyError as e:
        # Specific database error handling
        current_app.logger.error(
            f"Database error while accessing Backups page by user {current_user.email}: {str(e)}"
        )
        flash(
            "A database error occurred while accessing the Backups. Please try again later.",
            "danger",
        )
        return redirect(url_for("users.dashboard"))
    except Exception as e:
        current_app.logger.error(
            f"Error accessing Backups page by user {current_user.email}: {str(e)}"
        )
        flash(
            "An error occurred while accessing the Backups. Please try again later.",
            "danger",
        )
        return redirect(url_for("users.dashboard"))


@backup_bp.route("/backups/create_multiple", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Backups"],
    page="Index Backups",
)
def create_backup_multiple():
    try:
        data = request.get_json()
        device_ips = data.get("devices", [])
        backup_name = data.get("backup_name", None)
        description = data.get("description", "")
        backup_type = data.get("backup_type", "full")
        retention_days = data.get("retention_days", None)
        command = data.get("command")
        user_id = current_user.id

        if not device_ips:
            return jsonify({"message": "No devices selected."}), 400

        devices = DeviceManager.query.filter(
            DeviceManager.ip_address.in_(device_ips)
        ).all()

        if not devices:
            return jsonify({"message": "No devices found."}), 404

        vendors = {device.vendor for device in devices}
        if len(vendors) > 1:
            return jsonify({"message": "Devices must have the same vendor."}), 400

        results = []
        success = True

        @copy_current_request_context
        def backup_device(app, device, command):
            nonlocal success
            try:
                with app.app_context():
                    new_backup = BackupData.create_backup(
                        backup_name=backup_name,
                        description=description,
                        user_id=user_id,
                        device_id=device.id,
                        backup_type=backup_type,
                        retention_days=retention_days,
                        command=command,
                    )
                    results.append(
                        {
                            "device_name": device.device_name,
                            "ip": device.ip_address,
                            "status": "success",
                            "message": "Backup successful",
                            "backup_id": new_backup.id,
                        }
                    )
            except Exception as e:
                current_app.logger.error(
                    f"Error during backup for {device.ip_address}: {e}"
                )
                success = False
                results.append(
                    {
                        "device_name": device.device_name,
                        "ip": device.ip_address,
                        "status": "error",
                        "message": str(e),
                    }
                )

        app = current_app._get_current_object()
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(backup_device, app, device, command): device
                for device in devices
            }
            for future in as_completed(futures):
                future.result()

        return jsonify({"success": success, "results": results}), (
            200 if success else 500
        )

    except Exception as e:
        current_app.logger.error(f"Error creating backup: {e}")
        return jsonify({"message": f"Error creating backup: {str(e)}"}), 500


@backup_bp.route("/backups/create_single/<device_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Backups"],
    page="Index Backups",
)
def create_backup_single(device_id):
    """
    Create a backup for a single device.

    :param device_id: The ID of the device to back up.
    """
    try:
        # Get the JSON payload from the request
        data = request.get_json()
        backup_name = data.get("backup_name", None)
        description = data.get("description", "")
        backup_type = data.get("backup_type", "full")
        retention_days = data.get("retention_days", None)
        command = data.get("command")  # Ensure command is retrieved correctly
        user_id = current_user.id

        # Validate that a backup name is provided
        if not backup_name or not backup_name.strip():
            return jsonify({"message": "Backup name is required."}), 400

        # Query the device by its ID
        device = DeviceManager.query.get(device_id)

        if not device:
            return jsonify({"message": f"Device with ID {device_id} not found."}), 404

        # Ensure the current user is the owner of the device or is an Admin
        if current_user.has_role("Admin") or device.owner_id == user_id:
            try:
                # Create a new backup for this device using the static method
                new_backup = BackupData.create_backup(
                    backup_name=backup_name,
                    description=description,
                    user_id=user_id,
                    device_id=device_id,
                    backup_type=backup_type,
                    retention_days=retention_days,
                    command=command,
                )

                return (
                    jsonify(
                        {
                            "success": True,
                            "message": "Backup created successfully.",
                            "backup_id": new_backup.id,
                            "backup_path": new_backup.backup_path,
                        }
                    ),
                    201,
                )

            except Exception as e:
                current_app.logger.error(
                    f"Error creating backup for device {device.ip_address}: {e}"
                )
                return jsonify({"message": f"Error creating backup: {str(e)}"}), 500
        else:
            return (
                jsonify(
                    {"message": "You do not have permission to back up this device."}
                ),
                403,
            )

    except Exception as e:
        current_app.logger.error(f"Error processing backup for device {device_id}: {e}")
        return jsonify({"message": f"Error processing backup: {str(e)}"}), 500


# Read Backup by ID
@backup_bp.route("/detail-backup/<backup_id>", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Backups"],
    page="Index Backups",
)
def detail_backup(backup_id):
    # Query the backup by ID
    backup = BackupData.query.get(backup_id)

    # Check if backup exists
    if not backup:
        return jsonify({"message": "Backup not found"}), 404

    # Check if user is Admin or owns the backup
    if current_user.has_role("Admin") or backup.user_id == current_user.id:
        permission_level = "owner"  # Admins or owners have full access
    else:
        # Check if user has been shared this backup
        shared_access = UserBackupShare.query.filter_by(
            user_id=current_user.id, backup_id=backup_id
        ).first()
        if not shared_access:
            return jsonify({"message": "Unauthorized access"}), 403
        permission_level = shared_access.permission_level

    # Read the content of the backup file based on permission level
    try:
        if permission_level == "read-only":
            # Only read the backup if permission level is read-only
            backup_content = BackupUtils.read_backup_file(backup.backup_path)
        elif permission_level in ["edit", "owner"]:
            # Read and allow more actions if permission is edit or owner
            backup_content = BackupUtils.read_backup_file(backup.backup_path)
        else:
            return jsonify({"message": "Invalid permission level"}), 403
    except FileNotFoundError:
        return jsonify({"message": "Backup file not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error reading backup: {str(e)}"}), 500

    # Return the backup details if authorized
    return (
        jsonify(
            {
                "backup_name": backup.backup_name,
                "description": backup.description,
                "version": backup.version,
                "created_at": backup.created_at.isoformat(),
                "is_encrypted": backup.is_encrypted,
                "is_compressed": backup.is_compressed,
                "tags": [tag.tag for tag in backup.tags],
                "integrity_check": backup.integrity_check,
                "file_content": (
                    backup_content
                    if permission_level != "read-only"
                    else "Content hidden due to read-only access"
                ),
                "permission_level": permission_level,
            }
        ),
        200,
    )


@backup_bp.route("/update-backup/<backup_id>", methods=["GET", "POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Backups"],
    page="Update Backups",
)
def update_backup(backup_id):
    try:
        # Fetch the backup record from the database
        backup = BackupData.query.get(backup_id)
        if not backup:
            return jsonify({"message": "Backup not found"}), 404

        # Check if the user is either an Admin or the owner of the backup
        if not current_user.has_role("Admin") and backup.user_id != current_user.id:
            return jsonify({"message": "Unauthorized access"}), 403

        # Initialize the form and populate it with the current backup data
        form = UpdateBackupForm(
            backup_name=backup.backup_name,
            description=backup.description,
            retention_days=backup.retention_period_days,
            is_encrypted=backup.is_encrypted,
            is_compressed=backup.is_compressed,
            tags=", ".join(
                [tag.tag for tag in backup.tags]
            ),  # Convert tags to a comma-separated string
        )

        # Handle the form submission
        if form.validate_on_submit():
            # Update the backup details
            backup.backup_name = form.backup_name.data
            backup.description = form.description.data
            backup.retention_period_days = form.retention_days.data
            backup.is_encrypted = form.is_encrypted.data
            backup.is_compressed = form.is_compressed.data

            # Process tags (comma-separated input from the form)
            new_tags = [tag.strip() for tag in form.tags.data.split(",") if tag.strip()]

            # Clear existing tags and add new ones
            backup.tags.clear()
            for tag_text in new_tags:
                tag_instance = BackupTag.query.filter_by(tag=tag_text).first()
                if not tag_instance:
                    tag_instance = BackupTag(tag=tag_text)
                backup.tags.append(tag_instance)

            # Save the changes
            db.session.commit()

            flash("Backup updated successfully!", "success")
            return redirect(url_for("backup.index", backup_id=backup.id))

        # Render the update template
        return render_template("backup_managers/update.html", form=form, backup=backup)

    except Exception as e:
        current_app.logger.error(f"Error updating backup: {e}")
        db.session.rollback()
        flash(f"Error updating backup: {str(e)}", "danger")
        return redirect(url_for("backup.update_backup", backup_id=backup.id))


# Delete Backup
@backup_bp.route("/delete-backup/<backup_id>", methods=["DELETE"])  # Changed to DELETE
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Backups"],
    page="Delete Backups",
)
def delete_backup(backup_id):
    try:
        # Query the backup from the database
        backup = BackupData.query.get(backup_id)

        # Check if the backup exists
        if not backup:
            return jsonify({"message": "Backup not found."}), 404

        # Authorization check: Admins can delete any backup, non-admins can only delete their own backups
        if not current_user.has_role("Admin") and backup.user_id != current_user.id:
            return jsonify({"message": "Unauthorized to delete this backup."}), 403

        # Perform the actual deletion
        db.session.delete(backup)
        db.session.commit()

        # Optionally, delete the backup file from the filesystem
        try:
            BackupUtils.delete_backup_file(backup.backup_path)
        except Exception as e:
            current_app.logger.error(f"Error deleting backup file: {e}")
            # We don't rollback the DB transaction if the file deletion fails, just log the error

        # Return success response
        return jsonify({"message": "Backup successfully deleted."}), 200

    except Exception as e:
        current_app.logger.error(f"Error deleting backup: {e}")
        db.session.rollback()
        return jsonify({"message": f"Error deleting backup: {e}"}), 500


# ------------------------------------------------------------
# Sharing Backup with Other Users
# ------------------------------------------------------------


@backup_bp.route("/share-backup", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Backups"],
    page="Index Backups",
)
def share_backup():
    """
    Endpoint untuk berbagi backup dengan pengguna lain.
    """
    data = request.get_json()
    user_email_to_share = data.get("user_email")
    backup_id = data.get("backup_id")
    permission_level = data.get("permission_level", "read-only")

    # Log untuk memeriksa data yang diterima
    current_app.logger.info(
        f"User Email: {user_email_to_share}, Backup ID: {backup_id}, Permission Level: {permission_level}"
    )

    # Validasi input
    if not user_email_to_share or not backup_id:
        return jsonify({"message": "User Email and Backup ID are required"}), 400

    if permission_level not in ["read-only", "edit", "transfer"]:
        return jsonify({"message": "Invalid permission level"}), 400

    # Query user berdasarkan email
    user_to_share = User.query.filter_by(email=user_email_to_share).first()
    if not user_to_share:
        return (
            jsonify({"message": f"User with email {user_email_to_share} not found"}),
            404,
        )

    # Query backup berdasarkan backup_id
    backup = BackupData.query.get(backup_id)
    if not backup:
        return jsonify({"message": f"Backup with ID {backup_id} not found"}), 404

    # Pastikan bahwa pengguna memiliki backup ini (jika bukan Admin)
    if not current_user.has_role("Admin") and backup.user_id != current_user.id:
        return (
            jsonify({"message": "You do not have permission to share this backup"}),
            403,
        )

    # Cek apakah sudah ada share sebelumnya
    existing_share = UserBackupShare.query.filter_by(
        user_id=user_to_share.id, backup_id=backup_id
    ).first()

    if existing_share:
        # Jika sudah dibagikan, perbarui permission level
        existing_share.permission_level = permission_level

        # Jika permission level adalah 'transfer', perbarui kepemilikan backup
        if permission_level == "transfer":
            backup.user_id = user_to_share.id  # Update pemilik backup
            current_app.logger.info(
                f"Backup ownership transferred to {user_to_share.email}"
            )

        db.session.commit()
        return (
            jsonify(
                {
                    "message": f"Backup permission updated for user {user_to_share.email} to {permission_level} access"
                }
            ),
            200,
        )

    # Buat record baru di UserBackupShare
    new_share = UserBackupShare(
        user_id=user_to_share.id,
        backup_id=backup_id,
        permission_level=permission_level,
    )

    db.session.add(new_share)

    # Jika permission level adalah 'transfer', perbarui kepemilikan backup
    if permission_level == "transfer":
        backup.user_id = user_to_share.id  # Update pemilik backup
        current_app.logger.info(
            f"Backup ownership transferred to {user_to_share.email}"
        )

    db.session.commit()

    return (
        jsonify(
            {
                "message": f"Backup shared with user {user_to_share.email} with {permission_level} access"
            }
        ),
        200,
    )


# ------------------------------------------------------------
# Backup Versioning (Git Integration)
# ------------------------------------------------------------


# Rollback to Specific Version
@backup_bp.route("/rollback-backup/<backup_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"],
    permissions=["Manage Backups"],
    page="Index Backups",
)
def rollback_backup(backup_id):
    # Query the backup by ID
    backup = BackupData.query.get(backup_id)

    # Check if backup exists
    if not backup:
        return jsonify({"message": "Backup not found"}), 404

    # Check if user is Admin or owns the backup
    if not current_user.has_role("Admin") and backup.user_id != current_user.id:
        return jsonify({"message": "Unauthorized access"}), 403

    # Baca isi backup dari filesystem
    try:
        backup_content = BackupUtils.read_backup_file(backup.backup_path)

        # Lakukan rollback dengan mengirimkan konfigurasi lama ke perangkat
        device = DeviceManager.query.get(backup.device_id)
        command = backup_content  # Menggunakan isi backup sebagai perintah rollback

        config_utils = ConfigurationManagerUtils(
            ip_address=device.ip_address,
            username=device.username,
            password=device.password,
            ssh=device.ssh,
        )
        result = config_utils.configure_device(command)

        return jsonify({"message": "Rollback berhasil", "result": result}), 200
    except Exception as e:
        return jsonify({"message": f"Error during rollback: {e}"}), 500


# ------------------------------------------------------------
# Backup Tags
# ------------------------------------------------------------


# Add Tag to Backup
@backup_bp.route("/backups/<backup_id>/tags", methods=["POST"])
@login_required
def add_tag_to_backup(backup_id):
    backup = BackupData.query.get(backup_id)
    if not backup or backup.user_id != current_user.id:
        return jsonify({"message": "Backup not found or unauthorized"}), 404

    data = request.get_json()
    tag = data.get("tag")

    try:
        new_tag = BackupTag(backup_id=backup.id, tag=tag)
        db.session.add(new_tag)
        db.session.commit()

        # Add Audit log
        log_action(backup.id, "tag_added", current_user.id)

        return jsonify({"message": "Tag added to backup"}), 201
    except Exception as e:
        return jsonify({"message": f"Error adding tag: {str(e)}"}), 500


# ------------------------------------------------------------
# Backup Audit Logging
# ------------------------------------------------------------


def log_action(backup_id, action, user_id):
    """Helper function to log actions related to backups."""
    audit_log = BackupAuditLog(
        backup_id=backup_id,
        action=action,
        performed_by=user_id,
        timestamp=datetime.utcnow(),
    )
    db.session.add(audit_log)
    db.session.commit()


# Get Audit Logs for a Backup
@backup_bp.route("/backups/<backup_id>/logs", methods=["GET"])
@login_required
def get_audit_logs(backup_id):
    backup = BackupData.query.get(backup_id)
    if not backup or backup.user_id != current_user.id:
        return jsonify({"message": "Backup not found or unauthorized"}), 404

    audit_logs = BackupAuditLog.query.filter_by(backup_id=backup_id).all()
    logs_list = [
        {
            "action": log.action,
            "timestamp": log.timestamp,
            "performed_by": log.performed_by,
        }
        for log in audit_logs
    ]
    return jsonify(logs_list), 200
