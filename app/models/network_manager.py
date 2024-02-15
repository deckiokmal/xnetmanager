from app import db


class NetworkManager(db.Model):
    __tablename__ = "network_manager"

    id = db.Column(db.Integer, primary_key=True)
    template_name = db.Column(db.String(100), nullable=False, unique=True)

    # Mengubah back_populates ke "devices"
    devices = db.relationship(
        "DeviceManager", back_populates="network_manager", lazy=True
    )
