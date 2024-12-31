from flask import session, flash
from time import time
import logging

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class LoginUtils:
    @staticmethod
    def check_login_attempts(username):
        """
        Memeriksa apakah user saat ini diblokir dan menangani percobaan login.
        """
        login_attempts_key = f"{username}_login_attempts"
        block_until_key = f"{username}_block_until"

        login_attempts = session.get(login_attempts_key, 0)
        block_until = session.get(block_until_key, 0)

        if block_until > time():
            remaining_block_time = int(block_until - time())
            flash(
                f"Akun Anda diblokir sementara. Silahkan coba lagi dalam {remaining_block_time} detik.",
                "danger",
            )
            logging.info(
                f"Terlalu banyak percobaan login. Akun {remaining_block_time} diblokir sementara selama 1 menit."
            )
            return False  # User masih diblokir

        return True  # User tidak diblokir

    @staticmethod
    def increment_login_attempts(username):
        """
        Menambahkan jumlah percobaan login dan memblokir user jika percobaan melebihi batas.
        """
        login_attempts_key = f"{username}_login_attempts"
        block_until_key = f"{username}_block_until"

        login_attempts = session.get(login_attempts_key, 0)
        login_attempts += 1
        session[login_attempts_key] = login_attempts

        if login_attempts >= 3:
            session[block_until_key] = time() + 60  # Blokir selama 1 menit
            flash(
                "Terlalu banyak percobaan login. Akun Anda diblokir sementara selama 1 menit.",
                "danger",
            )
            logging.info(
                f"Terlalu banyak percobaan login. Akun {username} diblokir sementara selama 1 menit."
            )
            session[login_attempts_key] = 0  # Reset percobaan login setelah blokir
        else:
            flash(
                f"Percobaan login gagal. Anda memiliki {3 - login_attempts} percobaan tersisa.",
                "danger",
            )

    @staticmethod
    def reset_login_attempts(username):
        """
        Mereset percobaan login setelah login berhasil.
        """
        login_attempts_key = f"{username}_login_attempts"
        block_until_key = f"{username}_block_until"

        session.pop(login_attempts_key, None)
        session.pop(block_until_key, None)
