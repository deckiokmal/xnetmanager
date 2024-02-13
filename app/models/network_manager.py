from app import db


class configTemplates(db.Model):
    __tablename__ = "config_templates"

    id = db.Column(db.Integer, primary_key=True)
    template_name = db.Column(db.String(100), unique=True, nullable=False)
    parameter_name = db.Column(db.String(100), nullable=False)
    vendor = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(10), nullable=False)
    info = db.Column(db.Text, nullable=False)
