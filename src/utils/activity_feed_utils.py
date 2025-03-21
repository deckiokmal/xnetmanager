from datetime import datetime, timezone
import pytz
from src.models.app_models import Activity, User
from src import db


def log_activity(user_id, action, details=None):
    # Ambil user dari database
    user = User.query.get(user_id)

    # Jika user tidak ditemukan, gunakan default time_zone Asia/Jakarta
    user_timezone = user.time_zone if user and user.time_zone else "Asia/Jakarta"

    # Konversi waktu ke zona waktu user
    local_time = get_local_time(user_timezone)

    # Simpan ke database
    new_activity = Activity(
        user_id=user_id, action=action, timestamp=local_time, details=details
    )
    db.session.add(new_activity)
    db.session.commit()


def get_local_time(user_timezone):
    """Mengonversi UTC ke zona waktu lokal pengguna"""
    try:
        tz = pytz.timezone(user_timezone)  # Coba set timezone
    except pytz.UnknownTimeZoneError:
        tz = pytz.timezone("Asia/Jakarta")  # Jika tidak valid, default ke Asia/Jakarta

    utc_now = datetime.now(timezone.utc)  # Ambil waktu sekarang dalam UTC
    local_time = utc_now.astimezone(tz)  # Konversi ke waktu lokal
    return local_time
