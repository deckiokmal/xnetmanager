from datetime import datetime
import pytz
from src.models.app_models import Activity
from src import db
from flask_login import current_user


def log_activity(user_id, action, details=None):
    """
    Mencatat aktivitas pengguna ke database dengan timestamp dalam format string.

    Args:
        user_id (int): ID pengguna yang melakukan aktivitas.
        action (str): Jenis aksi yang dilakukan pengguna.
        timezone (str): Zona waktu yang diinginkan (default: Asia/Jakarta).
        details (str, optional): Detail tambahan tentang aktivitas. Defaults to None.
    """

    user_tz = current_user.time_zone if current_user.time_zone else "Asia/Jakarta"

    try:
        # Ambil zona waktu lokal
        local_tz = pytz.timezone(user_tz)
        # Waktu sekarang dalam zona waktu lokal
        local_time = datetime.now(local_tz)
        # Format waktu sebagai string
        formatted_time = local_time.strftime(
            "%d-%m-%Y %H:%M"
        )  # Contoh: "20-03-2025 22:00"

        # Simpan waktu dalam bentuk string ke database
        new_activity = Activity(
            user_id=user_id, action=action, timestamp=formatted_time, details=details
        )

        db.session.add(new_activity)
        db.session.commit()

    except Exception as e:
        print(f"Error logging activity: {e}")
        db.session.rollback()
