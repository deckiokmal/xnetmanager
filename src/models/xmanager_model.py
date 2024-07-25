from src import db


class DeviceManager(db.Model):
    __tablename__ = "device_manager"

    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(100), unique=True, nullable=False)
    vendor = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    ssh = db.Column(db.String(5), nullable=False)
    status = db.Column(db.String(20), nullable=True, default="Unknown")
    is_active = db.Column(db.Boolean, default=True)


class ConfigTemplate(db.Model):
    __tablename__ = "config_templates"

    id = db.Column(db.Integer, primary_key=True)
    template_name = db.Column(db.String(100), unique=True, nullable=False)
    parameter_name = db.Column(db.String(100), unique=True, nullable=False)
    vendor = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(10), nullable=False)
    info = db.Column(db.Text, nullable=False)


class NetworkManager(db.Model):
    __tablename__ = "network_manager"

    id = db.Column(db.Integer, primary_key=True)
    template_name = db.Column(db.String(100), nullable=False, unique=True)
