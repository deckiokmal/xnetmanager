from app import db


class DeviceManager(db.Model):
    __tablename__ = "device_manager"

    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(100), unique=True, nullable=False)
    vendor = db.Column(db.String(100), unique=True, nullable=False)
    ip_address = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    ssh = db.Column(db.String(5), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    # Mengubah ForeignKey agar merujuk ke tabel NetworkManager
    template_id = db.Column(
        db.Integer, db.ForeignKey("network_manager.id"), nullable=False
    )

    # Mengubah back_populates ke "network_manager"
    network_manager = db.relationship("NetworkManager", back_populates="devices")
