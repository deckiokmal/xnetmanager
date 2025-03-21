from logging.config import dictConfig
from logging.handlers import RotatingFileHandler


def configure_logging():
    LOG_CONFIG = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "INFO",
                "formatter": "standard",
                "stream": "ext://sys.stdout",
            },
            "file": {
                "()": RotatingFileHandler,
                "level": "INFO",
                "formatter": "standard",
                "filename": "app.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
                "encoding": "utf8",
            },
            "error_file": {
                "()": RotatingFileHandler,
                "level": "WARNING",
                "formatter": "standard",
                "filename": "app-error.log",
                "maxBytes": 10485760,
                "backupCount": 5,
                "encoding": "utf8",
            },
        },
        "loggers": {
            "": {  # Root logger
                "handlers": ["console", "file", "error_file"],
                "level": "DEBUG",
                "propagate": True,
            }
        },
    }

    dictConfig(LOG_CONFIG)
