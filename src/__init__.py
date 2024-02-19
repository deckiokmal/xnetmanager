from decouple import config
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv


# Load .env file variable
load_dotenv()


app = Flask(__name__)
app.config.from_object(config("APP_SETTINGS"))

# Flask_Login LoginManager handler
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager.login_view = "main.login"


# Registrasi blueprint controller dibawah ini

# blueprint controllers main.py
from .controllers.main import main_bp

app.register_blueprint(main_bp)

# blueprint controllers users.py
from .controllers.users import users_bp

app.register_blueprint(users_bp)

# blueprint controllers device_manager.py
from .controllers.device_manager import dm_bp

app.register_blueprint(dm_bp)

# blueprint controllers template_manager.py
from .controllers.template_manager import tm_bp

app.register_blueprint(tm_bp)

# blueprint controllers network_manager.py
from .controllers.network_manager import nm_bp

app.register_blueprint(nm_bp)

# Registrasi blueprint error handler
from .utils.error_helper import error_bp

app.register_blueprint(error_bp)


# Registrasi blueprint End


# User Loader

# import User class dari model users.py
from .models.users import User


# definisikan fungsi load_user yang digunakan oleh login_manager untuk memuat pengguna
@login_manager.user_loader
def load_user(user_id):
    # Load user by user_id
    return User.query.filter(User.id == int(user_id)).first()
