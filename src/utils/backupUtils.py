import os
import json
import difflib
import hashlib
from datetime import datetime
from flask import current_app
from .config_manager_utils import ConfigurationManagerUtils
from src import db


class BackupUtils:
    @staticmethod
    def perform_backup(
        backup_type, device, user_id, backup_name, description, command, version
    ):
        """
        Main method to perform the backup based on the type.

        :param backup_type: Type of the backup (full, incremental, differential)
        :param device: Device object for which the backup is being performed.
        :param user_id: ID of the user performing the backup.
        :param backup_name: Name of the backup.
        :param description: Description of the backup.
        :param command: The command to be used for the backup (based on device type).
        :param version: Version of the backup.
        :return: A dictionary with the result of the backup process.
        """
        previous_backup = BackupUtils.determine_previous_backup(device, backup_type)

        # Perform backup based on type
        try:
            if backup_type == "full":
                backup_data = BackupUtils.full_backup(device, command)
            elif backup_type == "incremental":
                if not previous_backup:
                    raise ValueError(
                        "Previous backup is required for incremental backup."
                    )
                backup_data = BackupUtils.incremental_backup(
                    device, previous_backup, command
                )
            elif backup_type == "differential":
                if not previous_backup:
                    raise ValueError(
                        "Previous full backup is required for differential backup."
                    )
                backup_data = BackupUtils.differential_backup(
                    device, previous_backup, command
                )
            else:
                raise ValueError(f"Unknown backup type: {backup_type}")

            # Save to file
            backup_path = BackupUtils.generate_backup_path(
                user_id, backup_name, version
            )
            BackupUtils.save_backup_to_file(backup_data["message"], backup_path)

            # Calculate integrity hash
            integrity_hash = BackupUtils.calculate_integrity(backup_path)

            return {
                "status": "success",
                "backup_path": backup_path,
                "message": backup_data["message"],
                "integrity_hash": integrity_hash,
            }

        except Exception as e:
            current_app.logger.error(f"Backup failed: {e}")
            return {"status": "error", "message": f"Backup failed: {str(e)}"}

    @staticmethod
    def full_backup(device, command):
        """
        Perform a full backup of the device configuration.

        :param device: Device object for which the backup is being performed.
        :param command: The command to execute on the device.
        :return: Dictionary with backup result or raise an error if failed.
        """
        config_utils = ConfigurationManagerUtils(
            ip_address=device.ip_address,
            username=device.username,
            password=device.password,
            ssh=device.ssh,
        )
        response_json = config_utils.backup_configuration(command=command)
        response_dict = json.loads(response_json)

        if response_dict.get("status") == "success":
            return {"status": "success", "message": response_dict.get("message", "")}
        else:
            error_message = response_dict.get("message", "Unknown error")
            raise RuntimeError(f"Full backup failed: {error_message}")

    @staticmethod
    def incremental_backup(device, previous_backup, command):
        current_config = BackupUtils.get_device_config(device, command)
        previous_config = BackupUtils.read_backup_file(previous_backup.backup_path)
        changes = BackupUtils.compare_data_for_incremental(
            previous_config, current_config
        )

        if changes:
            return {"status": "success", "message": changes}
        else:
            return {"status": "success", "message": "No changes detected"}

    @staticmethod
    def differential_backup(device, previous_backup, command):
        current_config = BackupUtils.get_device_config(device, command)
        previous_config = BackupUtils.read_backup_file(previous_backup.backup_path)
        changes = BackupUtils.compare_data_for_differential(
            previous_config, current_config
        )

        if changes:
            return {"status": "success", "message": changes}
        else:
            return {"status": "success", "message": "No changes detected"}

    @staticmethod
    def get_device_config(device, command):
        config_utils = ConfigurationManagerUtils(
            ip_address=device.ip_address,
            username=device.username,
            password=device.password,
            ssh=device.ssh,
        )
        response_json = config_utils.backup_configuration(command=command)
        response_dict = json.loads(response_json)

        if response_dict.get("status") == "success":
            return response_dict.get("message", "")
        else:
            error_message = response_dict.get("message", "Unknown error")
            raise RuntimeError(f"Failed to retrieve device config: {error_message}")

    @staticmethod
    def calculate_integrity(backup_path):
        hash_md5 = hashlib.md5()
        with open(backup_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    @staticmethod
    def compare_data_for_incremental(previous_data, current_data):
        diff = difflib.unified_diff(
            previous_data.splitlines(), current_data.splitlines(), lineterm=""
        )
        return "\n".join(list(diff))

    @staticmethod
    def compare_data_for_differential(previous_data, current_data):
        diff = difflib.unified_diff(
            previous_data.splitlines(), current_data.splitlines(), lineterm=""
        )
        return "\n".join(list(diff))

    @staticmethod
    def read_backup_file(backup_path):
        if os.path.exists(backup_path):
            with open(backup_path, "r") as backup_file:
                return backup_file.read()
        return ""

    @staticmethod
    def save_backup_to_file(backup_data, backup_path):
        try:
            with open(backup_path, "w", encoding="utf-8") as backup_file:
                backup_file.write(backup_data)
            current_app.logger.info(f"Backup saved to file {backup_path}.")
        except Exception as e:
            current_app.logger.error(f"Error saving backup to file {backup_path}: {e}")
            raise RuntimeError(f"Failed to save backup: {e}")

    @staticmethod
    def determine_previous_backup(device, backup_type):
        from src.models.app_models import (
            BackupData,
        )  # Move import here to avoid circular import

        if backup_type == "incremental":
            return (
                BackupData.query.filter(
                    BackupData.device_id == device.id,
                    BackupData.backup_type.in_(["full", "incremental"]),
                )
                .order_by(BackupData.created_at.desc())
                .first()
            )
        elif backup_type == "differential":
            return (
                BackupData.query.filter(
                    BackupData.device_id == device.id, BackupData.backup_type == "full"
                )
                .order_by(BackupData.created_at.desc())
                .first()
            )
        return None

    @staticmethod
    def generate_backup_path(user_id, backup_name, version):
        backup_dir = os.path.join(current_app.config["BACKUP_DIR"], str(user_id))
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        backup_filename = f"{backup_name}_v{version}.backup"
        return os.path.join(backup_dir, backup_filename)

    @staticmethod
    def delete_backup_file(backup_path):
        if os.path.exists(backup_path):
            try:
                os.remove(backup_path)
                current_app.logger.info(f"Backup file {backup_path} deleted.")
            except Exception as e:
                raise RuntimeError(f"Failed to delete backup file {backup_path}: {e}")
        else:
            current_app.logger.warning(f"Backup file {backup_path} does not exist.")

    @staticmethod
    def check_backup_exists(device_id):
        from src.models.app_models import (
            BackupData,
        )  # Move import here to avoid circular import

        existing_backup = (
            db.session.query(BackupData).filter_by(device_id=device_id).first()
        )
        return existing_backup is not None
