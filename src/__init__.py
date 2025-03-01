from decouple import config as decouple_config
from flask import Flask
import logging
from logging import StreamHandler
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
from src.utils.is_active_utils import is_active
from src.utils.mask_password_utils import mask_password
from src.config import DevelopmentConfig, TestingConfig, ProductionConfig, get_uuid_type
from flask_mail import Mail
from flask_talisman import Talisman
from openai import OpenAI
import os
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager
from werkzeug.middleware.proxy_fix import ProxyFix

# Load .env file variable
load_dotenv()

# Initialize extensions
bcrypt = Bcrypt()
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
mail = Mail()
ma = Marshmallow()
jwt = JWTManager()

# Global variable for UUID type
UUID_TYPE = None


def create_app():
    global UUID_TYPE

    app = Flask(__name__)

    # Membaca konfigurasi dari file .env
    config_name = decouple_config("CONFIG_NAME", default="Production")

    # Memilih konfigurasi berdasarkan nama
    if config_name == "Development":
        app.config.from_object(DevelopmentConfig)
    elif config_name == "Testing":
        app.config.from_object(TestingConfig)
    elif config_name == "Production":
        app.config.from_object(ProductionConfig)
    else:
        raise ValueError(
            "Invalid CONFIG_NAME. Expected 'Development', 'Testing', or 'Production'."
        )

    # Pastikan semua direktori yang dibutuhkan ada
    for directory in [
        app.config["BACKUP_DIR"],
        app.config["CONFIG_DIR"],
        app.config["TEMPLATE_DIR"],
    ]:
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
                app.logger.info(f"Created missing directory: {directory}")
            else:
                app.logger.info(f"Directory already exists: {directory}")
        except OSError as e:
            app.logger.error(f"Error creating directory {directory}: {e}")
            raise RuntimeError(f"Failed to create directory: {directory}")

    # Inisiasi pustaka OpenAI dengan API key
    openai_api_key = decouple_config("OPENAI_API_KEY", default=None)
    talita_api_key = decouple_config("TALITA_API_KEY", default=None)
    talita_url = decouple_config("TALITA_URL", default=None)

    # JWT Secret Key
    jwt_secret_key = decouple_config("JWT_SECRET_KEY", default=None)

    # Pengecekan apakah variabel konfigurasi penting telah dimuat
    if not openai_api_key:
        raise ValueError("Missing required configuration: OPENAI_API_KEY")
    if not talita_api_key:
        raise ValueError("Missing required configuration: TALITA_API_KEY")
    if not talita_url:
        raise ValueError("Missing required configuration: TALITA_URL")

    # Set API key untuk OpenAI
    client_openai = OpenAI(api_key=openai_api_key)

    # Simpan TALITA API Key dan URL ke dalam konfigurasi aplikasi
    app.config["TALITA_API_KEY"] = talita_api_key
    app.config["TALITA_URL"] = talita_url

    # set config for JWT Extended Library
    app.config["JWT_SECRET_KEY"] = jwt_secret_key
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = False

    # Initialize extensions
    bcrypt.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)
    ma.init_app(app)
    jwt.init_app(app)
    talisman = Talisman(
        app,
        content_security_policy=app.config["TALISMAN_CONTENT_SECURITY_POLICY"],
        force_https=app.config["TALISMAN_FORCE_HTTPS"],
        strict_transport_security=app.config["TALISMAN_STRICT_TRANSPORT_SECURITY"],
        strict_transport_security_max_age=app.config["TALISMAN_STRICT_TRANSPORT_SECURITY_MAX_AGE"],
        strict_transport_security_include_subdomains=app.config.get(
        "TALISMAN_STRICT_TRANSPORT_SECURITY_INCLUDE_SUBDOMAINS", True
        ),
        strict_transport_security_preload=app.config.get(
            "TALISMAN_STRICT_TRANSPORT_SECURITY_PRELOAD", False
        ),
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # Set UUID type based on database type
    UUID_TYPE = get_uuid_type(app.config["SQLALCHEMY_DATABASE_URI"])

    # Konfigurasi logger
    # Konfigurasi logger
    stream_handler = StreamHandler()
    stream_handler.setLevel(logging.INFO)
    file_handler = logging.FileHandler('app.log')
    file_handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    app.logger.addHandler(stream_handler)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

    # Register context processor
    app.jinja_env.filters["mask_password"] = mask_password

    # Middleware to modify the Server header
    @app.after_request
    def hide_server_header(response):
        response.headers["Server"] = "Hidden Server"
        return response

    @app.context_processor
    def utility_processor():
        return dict(is_active=is_active)

    # Register blueprints
    from .controllers.main_controller import main_bp
    from .controllers.users_controller import users_bp
    from .controllers.profile_controller import profile_bp
    from .controllers.roles_controller import roles_bp
    from .controllers.device_manager_controller import dm_bp
    from .controllers.template_manager_controller import tm_bp
    from .controllers.config_manager_controller import nm_bp
    from .utils.error_helper_utils import error_bp
    from .controllers.backup_controller import backup_bp
    from .controllers.ai_chatbot_controller import chatbot_bp
    from .controllers.config_file_manager_controller import config_file_bp
    from .controllers.restfull_api_controller import restapi_bp
    from .controllers.whatsapp_gateway_controller import whatsapp_bp
    from .controllers.analytic_controller import analytics_bp
    from .controllers.ai_analytic_controller_deepseek import ai_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(roles_bp)
    app.register_blueprint(dm_bp)
    app.register_blueprint(tm_bp)
    app.register_blueprint(nm_bp)
    app.register_blueprint(error_bp)
    app.register_blueprint(backup_bp)
    app.register_blueprint(chatbot_bp)
    app.register_blueprint(config_file_bp)
    app.register_blueprint(restapi_bp)
    app.register_blueprint(whatsapp_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(ai_bp)

    # Set up user loader
    from .models.app_models import User

    login_manager.login_view = "main.login"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.filter(User.id == user_id).first()

    return app
