import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
from flask_migrate import Migrate


# Load .env file variable
dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path)


# Inisialisasi app, secret_key untuk mengamankan sesi user.
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.static_folder = "static"


# # Definisi path untuk basis data SQLite
database_path = os.path.join(app.root_path, "data", "xnetmanager.db")

# # Konfigurasi SQLAlchemy dengan menonaktifkan fitur "track modifications" dan menentukan URI database.
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{database_path}"

# # Inisialisasi SQLAlchemy dan fungsi migrasi
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# Flask_Login LoginManager handler
login_manager = LoginManager(app)
login_manager.login_view = "main.login"


# Registrasi blueprint controller dibawah ini

# blueprint controllers main.py
from .controllers.main import main_bp

app.register_blueprint(main_bp)

# blueprint controllers users.py
from .controllers.users import users_bp

app.register_blueprint(users_bp)

# # blueprint controllers device_manager.py
from .controllers.device_manager import dm_bp

app.register_blueprint(dm_bp)

# blueprint controllers network_manager.py
# from .controllers.network_manager import nm_bp

# app.register_blueprint(nm_bp)

# Registrasi blueprint End


# Registrasi blueprint error handler
from .utils.error_helper import error_bp

app.register_blueprint(error_bp)


# User Loader

# import User class dari model users.py
from .models.users import User


# # definisikan fungsi load_user yang digunakan oleh login_manager untuk memuat pengguna
@login_manager.user_loader
def load_user(user_id):
    # Load user by user_id
    return User.query.get(int(user_id))


# # Buat basis data jika belum ada
if not os.path.exists(database_path):
    with app.app_context():
        db.create_all()
