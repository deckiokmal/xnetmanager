from datetime import datetime
from flask_login import UserMixin
import pyotp
from src import bcrypt, db
from src.config import Config
from itsdangerous import URLSafeTimedSerializer as Serializer, SignatureExpired
from flask import current_app

# ------------------------------------------------------------------------
# User and Roles Management Section
# ------------------------------------------------------------------------


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True)
    company = db.Column(db.String(255), nullable=True)
    title = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(255), nullable=True)
    division = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    date_joined = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    time_zone = db.Column(db.String(50), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    secret_token = db.Column(db.String, unique=True, nullable=True)
    email_verification_token = db.Column(db.String, nullable=True)

    # Relasi ke Role dan Permission
    roles = db.relationship("Role", secondary="user_roles", back_populates="users")

    # Relasi ke DeviceManager
    devices = db.relationship("DeviceManager", backref="owner", lazy=True)

    # Relasi ke ConfigurationManager
    configurations = db.relationship("ConfigurationManager", backref="owner", lazy=True)

    # Relasi ke BackupData
    backups = db.relationship("BackupData", back_populates="user", lazy=True)

    # Relasi ke UserBackupShare untuk mengakses backup yang dibagikan
    backup_shares = db.relationship(
        "UserBackupShare",
        back_populates="user",
        lazy=True,
        overlaps="shared_user",
    )

    # Relasi ke ConfigurationManagerShare untuk sharing konfigurasi
    configuration_shares = db.relationship(
        "UserConfigurationShare",
        back_populates="user",
        lazy=True,
        overlaps="shared_user",
    )

    def __init__(self, first_name, last_name, email, password_hash):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password_hash = bcrypt.generate_password_hash(password_hash).decode(
            "utf-8"
        )
        self.date_joined = datetime.utcnow()
        self.secret_token = pyotp.random_base32()

    def get_authentication_setup_uri(self):
        return pyotp.totp.TOTP(self.secret_token).provisioning_uri(
            name=self.email, issuer_name=Config.APP_NAME
        )

    def is_otp_valid(self, user_otp):
        totp = pyotp.TOTP(self.secret_token)
        return totp.verify(
            user_otp, valid_window=1
        )  # valid_window=1 menambah toleransi waktu ±30 detik

    def generate_email_verification_token(self):
        s = Serializer(current_app.config["SECRET_KEY"], salt="email-confirm")
        return s.dumps(self.email, salt="email-confirm")

    def verify_email_verification_token(self, token, expiration=3600):
        s = Serializer(current_app.config["SECRET_KEY"], salt="email-confirm")
        try:
            email = s.loads(token, max_age=expiration)
        except SignatureExpired:
            return False
        return email == self.email

    def __repr__(self):
        return f"<User {self.email}>"

    def has_role(self, role):
        return (
            Role.query.join(Role.users)
            .filter(User.id == self.id, Role.name == role)
            .count()
            > 0
        )


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    users = db.relationship("User", secondary="user_roles", back_populates="roles")
    permissions = db.relationship(
        "Permission", secondary="role_permissions", back_populates="roles"
    )

    def has_permission(self, permission_name):
        return any(
            permission.name == permission_name for permission in self.permissions
        )

    def __repr__(self):
        return f"<Role {self.name}>"


class Permission(db.Model):
    __tablename__ = "permissions"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    roles = db.relationship(
        "Role", secondary="role_permissions", back_populates="permissions"
    )


class UserRoles(db.Model):
    __tablename__ = "user_roles"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id", ondelete="CASCADE"))


class RolePermissions(db.Model):
    __tablename__ = "role_permissions"
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id", ondelete="CASCADE"))
    permission_id = db.Column(
        db.Integer, db.ForeignKey("permissions.id", ondelete="CASCADE")
    )


# ------------------------------------------------------------------------
# Device and Configuration Management Section
# ------------------------------------------------------------------------


class DeviceManager(db.Model):
    __tablename__ = "device_manager"

    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(100), unique=True, nullable=False)
    vendor = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    ssh = db.Column(db.String(5), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=True, default="Unknown")
    is_active = db.Column(db.Boolean, default=True)

    # Relasi ke User
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    def __repr__(self):
        return f"<DeviceManager {self.device_name}>"


class TemplateManager(db.Model):
    __tablename__ = "template_manager"

    id = db.Column(db.Integer, primary_key=True)
    template_name = db.Column(db.String(100), unique=True, nullable=False)
    parameter_name = db.Column(db.String(100), unique=True, nullable=False)
    vendor = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(10), nullable=False)
    description = db.Column(db.String(100), nullable=True)
    created_by = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<TemplateManager {self.template_name}>"


class ConfigurationManager(db.Model):
    __tablename__ = "configuration_manager"

    id = db.Column(db.Integer, primary_key=True)
    config_name = db.Column(db.String(100), nullable=False, unique=True)
    vendor = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Text, nullable=True)

    # Relasi ke User
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Relasi ke UserConfigurationShare untuk sharing konfigurasi
    shared_with = db.relationship(
        "UserConfigurationShare", backref="configuration", lazy=True
    )

    def __repr__(self):
        return f"<ConfigurationManager {self.config_name}>"


class UserConfigurationShare(db.Model):
    __tablename__ = "user_configuration_share"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    configuration_id = db.Column(
        db.Integer, db.ForeignKey("configuration_manager.id"), nullable=False
    )

    user = db.relationship(
        "User",
        back_populates="configuration_shares",
        overlaps="configuration_shares,shared_user",
    )

    def __repr__(self):
        return f"<UserConfigurationShare User {self.user_id} -> Configuration {self.configuration_id}>"


# -----------------------------------------------------------------------
# Backup Management Section
# -----------------------------------------------------------------------


class BackupData(db.Model):
    __tablename__ = "backup_data"

    id = db.Column(db.Integer, primary_key=True)
    backup_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    user = db.relationship(
        "User", back_populates="backups", overlaps="shared_backups,backup_shares"
    )

    def __repr__(self):
        return f"<BackupData {self.backup_name} v{self.version}>"

    @staticmethod
    def create_backup(backup_name, backup_content_path, user_id):
        # Dapatkan versi terakhir dari backup dengan nama yang sama dan user yang sama
        last_backup = (
            BackupData.query.filter_by(backup_name=backup_name, user_id=user_id)
            .order_by(BackupData.version.desc())
            .first()
        )
        new_version = last_backup.version + 1 if last_backup else 1

        new_backup = BackupData(
            backup_name=backup_name,
            backup_content_path=backup_content_path,
            version=new_version,
            user_id=user_id,
        )
        db.session.add(new_backup)
        db.session.commit()
        return new_backup


class UserBackupShare(db.Model):
    __tablename__ = "user_backup_share"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    backup_id = db.Column(db.Integer, db.ForeignKey("backup_data.id"), nullable=False)

    user = db.relationship(
        "User",
        back_populates="backup_shares",
        overlaps="backup_shares,shared_user",
    )
    backup = db.relationship(
        "BackupData",
        backref=db.backref("shared_with", lazy=True),
        overlaps="shared_backups",
    )

    def __repr__(self):
        return f"<UserBackupShare User {self.user_id} -> Backup {self.backup_id}>"
