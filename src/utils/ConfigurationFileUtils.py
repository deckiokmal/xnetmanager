import os
from flask import current_app
import random
import string
from datetime import datetime


# Utility untuk memvalidasi kepemilikan file konfigurasi
def check_ownership(config, user):
    """
    Mengecek apakah pengguna adalah admin atau pemilik dari konfigurasi.
    """
    if not user.has_role("Admin") and config.user_id != user.id:
        current_app.logger.warning(
            f"Unauthorized access attempt by user {user.email} on configuration ID {config.id}"
        )
        return False
    return True


# Utility untuk membaca file
def read_file(filepath):
    """
    Membaca konten file dari path yang diberikan. Mengembalikan None jika file tidak ditemukan atau error.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        current_app.logger.error(f"File not found: {filepath}")
        return None
    except Exception as e:
        current_app.logger.error(f"Error reading file {filepath}: {e}")
        return None


# Utility untuk menghasilkan nama file acak
def generate_random_filename(vendor_name):
    """
    Menghasilkan nama file acak berdasarkan nama vendor dan tanggal.
    """
    random_str = "".join(random.choices(string.ascii_letters + string.digits, k=6))
    date_str = datetime.now().strftime("%d_%m_%Y")
    filename = f"{vendor_name}_{random_str}_{date_str}"
    current_app.logger.info(f"Generated random filename: {filename}")
    return filename


# Utility untuk memastikan path aman (tidak ada akses luar folder)
def is_safe_path(file_path, base_directory):
    """
    Memastikan bahwa file_path berada di dalam base_directory dan aman untuk diakses.
    """
    return os.path.commonpath([file_path, base_directory]) == base_directory


# Utility untuk menghapus file dengan pengecekan keamanan
def delete_file_safely(file_path):
    """
    Menghapus file dari sistem dengan memastikan file path aman.
    """
    if not is_safe_path(file_path, current_app.static_folder):
        current_app.logger.warning(f"Unauthorized file access attempt.")
        return False, "Unauthorized file access."

    if os.path.exists(file_path):
        os.remove(file_path)
        current_app.logger.info(f"File deleted: {file_path}")
        return True, "File deleted successfully."

    current_app.logger.warning(f"File not found: {file_path}")
    return False, "File not found."
