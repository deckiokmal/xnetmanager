import os
import platform
import logging


def check_path_compatibility(base_path):
    try:
        # Tentukan apakah aplikasi berjalan di Windows atau Linux
        if platform.system() == "Windows":
            logging.info("Running in development mode on Windows.")
        else:
            logging.info("Running in production mode on Docker/Linux.")

        # Pastikan path dalam format yang benar
        normalized_path = os.path.normpath(base_path)

        # Uji akses ke direktori dan file
        test_file_path = os.path.join(normalized_path, "test_file.txt")
        with open(test_file_path, "w") as f:
            f.write("Test content")
        with open(test_file_path, "r") as f:
            content = f.read()
        os.remove(test_file_path)

        logging.info("Path compatibility check passed.")
        return True
    except Exception as e:
        logging.error(f"Path compatibility check failed: {e}")
        return False
