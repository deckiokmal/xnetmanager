from decouple import config
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
from src.utils.is_active_utils import is_active
from src.utils.mask_password_utils import mask_password


# Load .env file variable
load_dotenv()


app = Flask(__name__)
app.config.from_object(config("APP_SETTINGS"))
app.jinja_env.filters['mask_password'] = mask_password


@app.context_processor
def utility_processor():
    return dict(is_active=is_active)


# Flask_Login LoginManager handler
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# Registrasi blueprint controller dibawah ini

# blueprint controllers main.py
from .controllers.main_controller import main_bp

app.register_blueprint(main_bp)

# blueprint controllers users.py
from .controllers.users_controller import users_bp

app.register_blueprint(users_bp)

# blueprint controllers users.py
from .controllers.roles_controller import roles_bp

app.register_blueprint(roles_bp)

# blueprint controllers device_manager.py
from .controllers.device_manager_controller import dm_bp

app.register_blueprint(dm_bp)

# blueprint controllers template_manager.py
from .controllers.template_manager_controller import tm_bp

app.register_blueprint(tm_bp)

# blueprint controllers network_manager.py
from .controllers.config_manager_controller import nm_bp

app.register_blueprint(nm_bp)

# Registrasi blueprint error handler
from .utils.error_helper_utils import error_bp

app.register_blueprint(error_bp)


# Registrasi blueprint End


# User Loader

# import User class dari model users.py
from .models.users_model import User

login_manager.login_view = "main.login"


# definisikan fungsi load_user yang digunakan oleh login_manager untuk memuat pengguna
@login_manager.user_loader
def load_user(user_id):
    # Load user by user_id
    return User.query.filter(User.id == int(user_id)).first()
