from decouple import config, UndefinedValueError
import logging
from sqlalchemy.types import String
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
import os


# Validasi variabel lingkungan untuk memastikan semua yang diperlukan tersedia
def validate_config():
    """Validasi environment variabel untuk memastikan semua yang diperlukan tersedia."""
    try:
        config("SECRET_KEY")
        config("DATABASE_URL")
        config("APP_NAME")
        config("BCRYPT_LOG_ROUNDS")
    except UndefinedValueError as e:
        raise RuntimeError(f"Missing environment variable: {e}")


validate_config()

# Database URI
DATABASE_URI = config("DATABASE_URL", default="sqlite:///xnetmanager.sqlite")

# Ubah prefix dari PostgreSQL jika diperlukan
if DATABASE_URI.startswith("postgres://"):
    DATABASE_URI = DATABASE_URI.replace("postgres://", "postgresql://", 1)


def get_uuid_type(database_uri):
    """Menentukan tipe UUID berdasarkan URI database."""
    if database_uri.startswith("sqlite"):
        return String(36)  # Menggunakan String untuk UUID di SQLite
    else:
        return PostgresUUID(as_uuid=True)  # Menggunakan UUID asli di PostgreSQL


class Config(object):
    """Konfigurasi dasar aplikasi."""

    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    SECRET_KEY = config("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BCRYPT_LOG_ROUNDS = int(config("BCRYPT_LOG_ROUNDS", default=13))
    WTF_CSRF_ENABLED = True
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    APP_NAME = config("APP_NAME")

    # Set BASE_DIR to the project root
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # In production, use an environment variable for the backup directory (Docker volume)
    BACKUP_DIR = config("BACKUP_DIR", default=os.path.join(BASE_DIR, "static", "xmanager", "backups"))
    CONFIG_DIR = config("CONFIG_DIR", default=os.path.join(BASE_DIR, "static", "xmanager", "configurations"))
    TEMPLATE_DIR = config("TEMPLATE_DIR", default=os.path.join(BASE_DIR, "static", "xmanager", "templates"))

    # Pengaturan untuk keamanan cookies
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Pengaturan logging
    LOGGING_LEVEL = logging.DEBUG if DEBUG else logging.INFO
    LOGGING_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOGGING_LOCATION = "app.log"

    # Pengaturan untuk email
    MAIL_SERVER = config("MAIL_SERVER", default="smtp.gmail.com")
    MAIL_USERNAME = config("MAIL_USERNAME")
    MAIL_PASSWORD = config("MAIL_PASSWORD")
    MAIL_USE_TLS = config("MAIL_USE_TLS", default=True, cast=bool)
    MAIL_USE_SSL = config("MAIL_USE_SSL", default=False, cast=bool)
    MAIL_PORT = 465 if MAIL_USE_SSL else 587

    # Pengaturan Flask-Talisman
    TALISMAN_FORCE_HTTPS = True
    TALISMAN_STRICT_TRANSPORT_SECURITY = True
    TALISMAN_STRICT_TRANSPORT_SECURITY_MAX_AGE = 31536000  # 1 year
    TALISMAN_CONTENT_SECURITY_POLICY = {
        "default-src": ["'self'", "https://www.youtube.com"],
        "img-src": ["'self'", "data:", "cdn.jsdelivr.net", "via.placeholder.com"],
        "style-src": [
            "'self'",
            "'unsafe-inline'",
            "fonts.googleapis.com",
            "cdn.jsdelivr.net",
        ],
        "script-src": [
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'",
            "kit.fontawesome.com",
            "cdn.jsdelivr.net",
        ],
        "script-src-elem": [
            "'self'",
            "'unsafe-inline'",
            "kit.fontawesome.com",
            "cdn.jsdelivr.net",
        ],
        "font-src": [
            "'self'",
            "fonts.gstatic.com",
            "fonts.googleapis.com",
            "https://ka-f.fontawesome.com",
        ],
        "connect-src": ["'self'", "https://ka-f.fontawesome.com"],
        "object-src": ["'none'"],
        "frame-ancestors": ["'none'"],
    }


class DevelopmentConfig(Config):
    """Konfigurasi khusus untuk lingkungan pengembangan."""

    DEVELOPMENT = True
    DEBUG = True
    WTF_CSRF_ENABLED = False
    DEBUG_TB_ENABLED = True

    # Pengaturan Flask-Talisman untuk pengembangan
    TALISMAN_FORCE_HTTPS = False
    TALISMAN_STRICT_TRANSPORT_SECURITY = False
    TALISMAN_CONTENT_SECURITY_POLICY = {
        "default-src": ["'self'", "https://www.youtube.com"],
        "img-src": [
            "'self'",
            "data:",
            "cdn.jsdelivr.net",
            "via.placeholder.com",
            "https://iili.io",
        ],
        "style-src": [
            "'self'",
            "'unsafe-inline'",
            "fonts.googleapis.com",
            "cdn.jsdelivr.net",
        ],
        "script-src": [
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'",
            "kit.fontawesome.com",
            "cdn.jsdelivr.net",
        ],
        "script-src-elem": [
            "'self'",
            "'unsafe-inline'",
            "kit.fontawesome.com",
            "cdn.jsdelivr.net",
        ],
        "font-src": [
            "'self'",
            "fonts.gstatic.com",
            "fonts.googleapis.com",
            "https://ka-f.fontawesome.com",
        ],
        "connect-src": ["'self'", "https://ka-f.fontawesome.com"],
        "object-src": ["'none'"],
        "frame-ancestors": ["'none'"],
    }


class TestingConfig(Config):
    """Konfigurasi khusus untuk lingkungan pengujian."""

    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    BCRYPT_LOG_ROUNDS = 1
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """Konfigurasi khusus untuk lingkungan produksi."""

    DEBUG = False
    DEBUG_TB_ENABLED = False

    # Pengaturan Flask-Talisman untuk produksi
    TALISMAN_FORCE_HTTPS = True
    TALISMAN_STRICT_TRANSPORT_SECURITY = True
    TALISMAN_STRICT_TRANSPORT_SECURITY_MAX_AGE = 31536000  # 1 year
    TALISMAN_CONTENT_SECURITY_POLICY = {
        "default-src": ["'self'", "https://www.youtube.com"],
        "img-src": [
            "'self'",
            "data:",
            "cdn.jsdelivr.net",
            "via.placeholder.com",
            "https://iili.io",
        ],
        "style-src": [
            "'self'",
            "'unsafe-inline'",
            "fonts.googleapis.com",
            "cdn.jsdelivr.net",
        ],
        "script-src": [
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'",
            "kit.fontawesome.com",
            "cdn.jsdelivr.net",
        ],
        "script-src-elem": [
            "'self'",
            "'unsafe-inline'",
            "kit.fontawesome.com",
            "cdn.jsdelivr.net",
        ],
        "font-src": [
            "'self'",
            "fonts.gstatic.com",
            "fonts.googleapis.com",
            "https://ka-f.fontawesome.com",
        ],
        "connect-src": ["'self'", "https://ka-f.fontawesome.com"],
        "object-src": ["'none'"],
        "frame-ancestors": ["'none'"],
    }
