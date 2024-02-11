from app import db


class Device_manager(db.Model):
    __tablename__ = "device_manager"

    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(100), unique=True, nullable=False)
    vendor = db.Column(db.String(100), unique=True, nullable=False)
    ip_address = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    ssh = db.Column(db.String(5), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
