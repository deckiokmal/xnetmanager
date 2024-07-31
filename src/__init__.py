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
from src.config import DevelopmentConfig, TestingConfig, ProductionConfig
from flask_mail import Mail

# Load .env file variable
load_dotenv()

# Initialize extensions
bcrypt = Bcrypt()
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
mail = Mail()


def create_app(config_class=None):
    app = Flask(__name__)

    # Membaca konfigurasi dari file .env
    config_name = decouple_config("CONFIG_NAME", default="Development")

    # Memilih konfigurasi berdasarkan nama
    if config_name == "Development":
        app.config.from_object(DevelopmentConfig)
    elif config_name == "Testing":
        app.config.from_object(TestingConfig)
    elif config_name == "Production":
        app.config.from_object(ProductionConfig)
    else:
        raise ValueError("Invalid CONFIG_NAME")

    # Initialize extensions
    bcrypt.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)

    # Konfigurasi logger
    handler = StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)

    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    # Register context processor
    app.jinja_env.filters["mask_password"] = mask_password

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

    app.register_blueprint(main_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(roles_bp)
    app.register_blueprint(dm_bp)
    app.register_blueprint(tm_bp)
    app.register_blueprint(nm_bp)
    app.register_blueprint(error_bp)

    # Set up user loader
    from .models.users_model import User

    login_manager.login_view = "main.login"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.filter(User.id == int(user_id)).first()

    return app
