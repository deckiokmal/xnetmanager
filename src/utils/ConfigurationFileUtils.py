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
    random_str = "".join(random.choices(string.ascii_letters + string.digits, k=3))
    date_str = datetime.now().strftime("%d_%m_%Y")
    filename = f"{vendor_name}_{random_str}_{date_str}"
    current_app.logger.info(f"Generated random filename: {filename}")
    return filename


# Utility untuk memastikan path aman (tidak ada akses luar folder)
def is_safe_path(file_path, base_directory):
    """
    Memastikan bahwa file_path berada di dalam base_directory dan aman untuk diakses.
    """
    # Konversi ke path absolut sebelum perbandingan
    abs_file_path = os.path.abspath(file_path)
    abs_base_directory = os.path.abspath(base_directory)

    return os.path.commonpath([abs_file_path, abs_base_directory]) == abs_base_directory


# Utility untuk menghapus file dengan pengecekan keamanan
def delete_file_safely(file_path, base_directory=None):
    """
    Menghapus file dari sistem dengan memastikan file path aman.
    :param file_path: Path file yang akan dihapus.
    :param base_directory: Direktori dasar yang diizinkan, default ke `CONFIG_DIR` dari konfigurasi aplikasi.
    :return: Tuple (status: bool, message: str)
    """
    # Tentukan base_directory dari konfigurasi aplikasi jika tidak diberikan
    base_directory = base_directory or current_app.config.get("CONFIG_DIR")

    # Periksa keamanan file path sebelum menghapus
    if not is_safe_path(file_path, base_directory):
        current_app.logger.warning(f"Unauthorized file access attempt to {file_path}.")
        return False, "Unauthorized file access."

    # Hapus file jika ada
    if os.path.isfile(file_path):
        try:
            os.remove(file_path)
            current_app.logger.info(f"File successfully deleted: {file_path}")
            return True, "File deleted successfully."
        except Exception as e:
            current_app.logger.error(f"Error deleting file {file_path}: {e}")
            return False, f"Error deleting file: {e}"

    current_app.logger.warning(f"File not found or is not a file: {file_path}")
    return False, "File not found."
