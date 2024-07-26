from decouple import config, UndefinedValueError
import logging


# Validasi variabel lingkungan untuk memastikan semua yang diperlukan tersedia
def validate_config():
    """Validasi variabel lingkungan untuk memastikan semua yang diperlukan tersedia."""
    try:
        secret_key = config("SECRET_KEY")
        database_url = config("DATABASE_URL")
        app_name = config("APP_NAME")
        bcrypt_log_rounds = config("BCRYPT_LOG_ROUNDS")
    except UndefinedValueError as e:
        raise RuntimeError(f"Missing environment variable: {e}")


validate_config()

# Database URI
DATABASE_URI = config("DATABASE_URL")
if DATABASE_URI.startswith("postgres://"):
    DATABASE_URI = DATABASE_URI.replace("postgres://", "postgresql://", 1)


class Config(object):
    """Konfigurasi dasar aplikasi."""

    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    SECRET_KEY = config("SECRET_KEY", default="guess-me")
    SQLALCHEMY_DATABASE_URI = DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BCRYPT_LOG_ROUNDS = int(config("BCRYPT_LOG_ROUNDS", default=13))
    WTF_CSRF_ENABLED = True
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    APP_NAME = config("APP_NAME")

    # Pengaturan untuk keamanan cookies
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Pengaturan logging
    LOGGING_LEVEL = logging.DEBUG
    LOGGING_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOGGING_LOCATION = "app.log"


class DevelopmentConfig(Config):
    """Konfigurasi khusus untuk lingkungan pengembangan."""

    DEVELOPMENT = True
    DEBUG = True
    WTF_CSRF_ENABLED = False
    DEBUG_TB_ENABLED = True


class TestingConfig(Config):
    """Konfigurasi khusus untuk lingkungan pengujian."""

    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///testdb.sqlite"
    BCRYPT_LOG_ROUNDS = 1
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """Konfigurasi khusus untuk lingkungan produksi."""

    DEBUG = False
    DEBUG_TB_ENABLED = False
