def get_repo_path():
    return os.path.join(current_app.static_folder, BACKUP_FOLDER)


from src.utils.git_version_utils import GitUtils


# Inisialisasi GitUtils dengan path repositori
def get_git_utils():
    repo_path = get_repo_path()
    return GitUtils(repo_path)


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

        backup_content_path = os.path.join(get_repo_path(), backup.backup_name)
        backup_content = None

        if request.method == "GET":
            try:
                with open(backup_content_path, "r") as file:
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
            new_backup_content = (
                data.get("backup_content")
                .replace("\r\n", "\n")
                .replace("\r", "\n")
                .strip()
            )
            commit_message = data.get("commit_message", "Update backup")

            if new_backup_name != backup.backup_name:
                new_backup_name = generate_random_filename(new_backup_name)
                backup.backup_name = new_backup_name
                backup_content_path = os.path.join(get_repo_path(), new_backup_name)

            if new_backup_content:
                try:
                    with open(backup_content_path, "w") as file:
                        file.write(new_backup_content)
                    current_app.logger.info(
                        f"Backup content updated for {backup.backup_name}."
                    )

                    # Commit changes using GitUtils
                    git_utils = get_git_utils()
                    formatted_commit_message = f"{commit_message} - Backup updated for {backup.backup_name} by {current_user.email} on {datetime.now()}"
                    commit_hash = git_utils.commit_backup(
                        backup_content_path, formatted_commit_message
                    )

                    # Create new GitBackupVersion entry
                    git_version = GitBackupVersion(
                        backup_id=backup.id,
                        commit_hash=commit_hash,
                        commit_message=formatted_commit_message,
                        file_path=backup_content_path,
                    )
                    db.session.add(git_version)

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
            flash(f"Backup file updated successfully", "success")
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

        related_versions = BackupData.query.filter_by(
            backup_name=backup.backup_name
        ).all()

        if len(related_versions) == 1:
            try:
                backup_file_path = os.path.join(get_repo_path(), backup.backup_name)
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
                    jsonify(
                        {"success": False, "message": "Failed to delete backup file."}
                    ),
                    500,
                )
        else:
            current_app.logger.info(
                f"Backup file {backup.backup_name} not deleted because other versions are still using it."
            )

        git_versions = GitBackupVersion.query.filter_by(backup_id=backup.id).all()
        for git_version in git_versions:
            db.session.delete(git_version)

        shares = UserBackupShare.query.filter_by(backup_id=backup.id).all()
        for share in shares:
            db.session.delete(share)

        db.session.delete(backup)
        db.session.commit()
        current_app.logger.info(
            f"Backup ID {backup_id} deleted by user {current_user.email}."
        )
        flash(f"Backup version successfully deleted by {current_user.email}", "success")
    except Exception as e:
        current_app.logger.error(f"Error deleting backup ID {backup_id}: {e}")
        db.session.rollback()
        flash(f"Backup deletion failed by {current_user.email}", "danger")
        return redirect(url_for("backup.backups"))

    return redirect(url_for("backup.backups"))


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
        commit_message = data.get("commit_message", "Create backup")
        user_id = current_user.id
        user_email = current_user.email

        if not device_ips:
            current_app.logger.warning("No devices selected for backup.")
            return jsonify({"success": False, "message": "No devices selected."}), 400
        if not command:
            current_app.logger.warning("No command provided for backup.")
            return jsonify({"success": False, "message": "No command provided."}), 400

        devices = DeviceManager.query.filter(
            DeviceManager.ip_address.in_(device_ips),
            DeviceManager.user_id == user_id,
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

        def configure_device(app, device, user_email, commit_message):
            nonlocal success
            try:
                with app.app_context():
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
                        filename_gen = (
                            f"{device.ip_address}_{device.vendor}_{device.device_name}"
                        )
                        filename = f"{filename_gen}.backup"
                        file_path = os.path.join(get_repo_path(), filename)
                        description = f"Backup file {filename} created by {user_email}"

                        backup_data = (
                            backup_data.replace("\r\n", "\n")
                            .replace("\r", "\n")
                            .strip()
                        )
                        with open(file_path, "w", encoding="utf-8") as backup_file:
                            backup_file.write(backup_data)
                        current_app.logger.info(
                            f"Successfully saved backup content to file: {file_path}"
                        )

                        git_utils = get_git_utils()
                        formatted_commit_message = f"{commit_message} - Backup created for {device.device_name} by {user_email} on {datetime.now()}"
                        commit_hash = git_utils.commit_backup(
                            file_path, formatted_commit_message
                        )

                        BackupData.create_backup(
                            backup_name=filename,
                            description=description,
                            user_id=user_id,
                            commit_hash=commit_hash,
                        )

                        return {
                            "device_name": device.device_name,
                            "ip": device.ip_address,
                            "status": "success",
                            "message": "Backup sukses.",
                        }
                    else:
                        current_app.logger.error(
                            f"Backup failed for device {device.ip_address}: {response_dict.get('message', 'Unknown error')}"
                        )
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

        app = current_app._get_current_object()

        max_threads = 10
        with ThreadPoolExecutor(max_threads) as executor:
            futures = {
                executor.submit(
                    configure_device, app, device, user_email, commit_message
                ): device
                for device in devices
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
