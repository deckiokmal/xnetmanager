from datetime import datetime
from flask_login import UserMixin
import pyotp
import pytz
from src import bcrypt, db
from src.config import Config
from itsdangerous import URLSafeTimedSerializer as Serializer, SignatureExpired
from flask import current_app
import uuid
from src import UUID_TYPE
from src.utils.backup_utilities import BackupUtils


# Set timezone Asia/Jakarta
DEFAULT_TZ = pytz.timezone("UTC")


# ------------------------------------------------------------------------
# User and Roles Management Section
# ------------------------------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    profile_picture = db.Column(
        db.String(255), nullable=False, default="img/undraw_profile.svg"
    )
    company = db.Column(db.String(255), nullable=True)
    title = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(255), nullable=True)
    biodata = db.Column(db.String(255), nullable=True)
    division = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    date_joined = db.Column(
        db.DateTime, nullable=False, default=datetime.now(DEFAULT_TZ)
    )
    last_login = db.Column(db.DateTime, nullable=True)
    time_zone = db.Column(
        db.String(50), nullable=True, default=datetime.now(DEFAULT_TZ)
    )
    is_2fa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    secret_token = db.Column(db.String, unique=True, nullable=True)
    email_verification_token = db.Column(db.String, nullable=True)
    force_logout = db.Column(db.Boolean, default=False)

    # Relasi ke Role dan Permission
    roles = db.relationship("Role", secondary="user_roles", back_populates="users")

    # Relasi ke DeviceManager
    devices = db.relationship("DeviceManager", backref="owner", lazy=True)

    # Relasi ke ConfigurationManager
    configurations = db.relationship("ConfigurationManager", backref="owner", lazy=True)

    # Relasi ke BackupData
    backups = db.relationship("BackupData", back_populates="user", lazy=True)

    # Relasi ke UserBackupShare untuk mengakses backup yang dibagikan
    backup_shares = db.relationship("UserBackupShare", back_populates="user", lazy=True)

    # Relasi ke AuditLog
    audit_logs = db.relationship(
        "AuditLog", back_populates="performed_by_user", lazy="dynamic"
    )

    # Relasi ke ConfigurationManagerShare untuk sharing konfigurasi
    configuration_shares = db.relationship(
        "UserConfigurationShare",
        back_populates="user",
        lazy=True,
        overlaps="shared_user",
    )

    # Relasi ke AIRecommendations
    applied_recommendations = db.relationship(
        "AIRecommendations",
        back_populates="applied_by_user",
        lazy="dynamic",
        foreign_keys="AIRecommendations.applied_by",
    )

    # Menghapus User Activity di level ORM jika user di delete
    activities = db.relationship(
        "Activity", backref="user", cascade="all, delete-orphan", lazy=True
    )

    def __init__(self, first_name, last_name, email, password_hash):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password_hash = bcrypt.generate_password_hash(password_hash).decode(
            "utf-8"
        )
        self.date_joined = datetime.now(DEFAULT_TZ)
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

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
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

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    roles = db.relationship(
        "Role", secondary="role_permissions", back_populates="permissions"
    )


class UserRoles(db.Model):
    __tablename__ = "user_roles"

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(
        UUID_TYPE, db.ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    role_id = db.Column(
        UUID_TYPE, db.ForeignKey("roles.id", ondelete="CASCADE"), index=True
    )


class RolePermissions(db.Model):
    __tablename__ = "role_permissions"

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    role_id = db.Column(
        UUID_TYPE, db.ForeignKey("roles.id", ondelete="CASCADE"), index=True
    )
    permission_id = db.Column(
        UUID_TYPE, db.ForeignKey("permissions.id", ondelete="CASCADE"), index=True
    )


class Activity(db.Model):
    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    user_id = db.Column(
        UUID_TYPE, db.ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    action = db.Column(db.String(255), nullable=False)  # Deskripsi aktivitas
    timestamp = db.Column(db.String(255), nullable=False)  # Waktu aktivitas
    details = db.Column(db.Text, nullable=True)  # Info tambahan (opsional)


# ------------------------------------------------------------------------
# Device and Configuration Management Section
# ------------------------------------------------------------------------
class DeviceManager(db.Model):
    __tablename__ = "device_manager"

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
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
    user_id = db.Column(UUID_TYPE, db.ForeignKey("users.id"), nullable=True, index=True)

    # Relasi ke BackupData (one-to-many)
    backups = db.relationship(
        "BackupData", back_populates="device", cascade="all, delete-orphan"
    )

    # Relasi ke AIRecommendations
    recommendations = db.relationship(
        "AIRecommendations", back_populates="device", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<DeviceManager {self.device_name}>"


class TemplateManager(db.Model):
    __tablename__ = "template_manager"

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
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

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    config_name = db.Column(db.String(100), nullable=False, unique=True)
    vendor = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Text, nullable=True)

    # Relasi ke User
    user_id = db.Column(UUID_TYPE, db.ForeignKey("users.id"), nullable=True, index=True)

    # Relasi ke UserConfigurationShare untuk sharing konfigurasi
    shared_with = db.relationship(
        "UserConfigurationShare", backref="configuration", lazy=True
    )

    def __repr__(self):
        return f"<ConfigurationManager {self.config_name}>"


class UserConfigurationShare(db.Model):
    __tablename__ = "user_configuration_share"

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(UUID_TYPE, db.ForeignKey("users.id"), nullable=True, index=True)
    configuration_id = db.Column(
        UUID_TYPE,
        db.ForeignKey("configuration_manager.id"),
        nullable=False,
        index=True,
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

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    backup_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(
        db.DateTime, nullable=False, default=datetime.now(DEFAULT_TZ)
    )
    backup_path = db.Column(db.String(255), nullable=False)  # Valid path required
    is_encrypted = db.Column(db.Boolean, default=False)
    is_compressed = db.Column(db.Boolean, default=False)
    integrity_check = db.Column(db.String(64), nullable=True)
    backup_type = db.Column(db.String(50), nullable=False, default="full")
    next_scheduled_backup = db.Column(db.DateTime, nullable=True)
    retention_period_days = db.Column(db.Integer, nullable=True)

    # Foreign Key for User
    user_id = db.Column(UUID_TYPE, db.ForeignKey("users.id"), nullable=True, index=True)
    user = db.relationship("User", back_populates="backups")

    # Foreign Key for DeviceManager
    device_id = db.Column(UUID_TYPE, db.ForeignKey("device_manager.id"), nullable=False)
    device = db.relationship("DeviceManager", back_populates="backups")

    # Relationships to other models (e.g., shared, versions, etc.)
    shared_with = db.relationship(
        "UserBackupShare", back_populates="backup", cascade="all, delete-orphan"
    )
    tags = db.relationship(
        "BackupTag", back_populates="backup", cascade="all, delete-orphan"
    )
    audit_logs = db.relationship(
        "AuditLog", back_populates="backup", cascade="all, delete-orphan"
    )

    @staticmethod
    def create_backup(
        backup_name,
        description,
        user_id,
        device_id,
        backup_type="full",
        retention_days=None,
        command=None,
    ):
        """
        Method to handle creating a new backup entry in the database and executing the backup.

        :param backup_name: Name of the backup.
        :param description: Description of the backup.
        :param user_id: ID of the user performing the backup.
        :param device_id: ID of the device being backed up.
        :param backup_type: Type of the backup (full, incremental, differential).
        :param retention_days: Retention period for the backup.
        :param command: The command to be executed for the backup.
        """
        try:
            if not backup_name or not backup_name.strip():
                raise ValueError("Backup name is required.")

            device = DeviceManager.query.get(device_id)
            if not device:
                raise ValueError("Device not found.")

            if not command:
                raise ValueError("Backup command is required.")

            # Get the latest version for this device's backups
            latest_backup = (
                BackupData.query.filter_by(device_id=device_id)
                .order_by(BackupData.version.desc())
                .first()
            )
            new_version = (latest_backup.version + 1) if latest_backup else 1

            # Perform the backup using BackupUtils
            backup_result = BackupUtils.perform_backup(
                backup_type,
                device,
                user_id=user_id,
                backup_name=backup_name,
                description=description,
                command=command,
                version=new_version,
            )

            # Ensure the backup was successful and has a valid backup_path
            if (
                backup_result.get("status") != "success"
                or "backup_path" not in backup_result
            ):
                error_message = backup_result.get(
                    "message", "Unknown error occurred during backup."
                )
                raise RuntimeError(f"Backup failed: {error_message}")

            # Create the new backup record
            new_backup = BackupData(
                backup_name=backup_name,
                description=description,
                version=new_version,
                backup_path=backup_result["backup_path"],
                backup_type=backup_type,
                user_id=user_id,
                device_id=device_id,
                retention_period_days=retention_days,
                integrity_check=backup_result.get("integrity_hash"),
            )

            db.session.add(new_backup)
            db.session.commit()

            return new_backup
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating backup: {e}")
            raise RuntimeError(f"Unexpected error occurred: {e}")


class UserBackupShare(db.Model):
    __tablename__ = "user_backup_share"

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(UUID_TYPE, db.ForeignKey("users.id"), nullable=True, index=True)
    backup_id = db.Column(
        UUID_TYPE, db.ForeignKey("backup_data.id"), nullable=False, index=True
    )

    # Permissions for sharing (read-only, edit, or ownership transfer)
    permission_level = db.Column(
        db.String(50), default="read-only"
    )  # read-only, edit, transfer

    # Relationship to the user with whom the backup is shared
    user = db.relationship("User", back_populates="backup_shares")

    # Relationship to the backup being shared
    backup = db.relationship("BackupData", back_populates="shared_with")

    def __repr__(self):
        return f"<UserBackupShare User {self.user_id} -> Backup {self.backup_id} with {self.permission_level} access>"


class BackupTag(db.Model):
    __tablename__ = "backup_tags"

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    backup_id = db.Column(
        UUID_TYPE, db.ForeignKey("backup_data.id"), nullable=False, index=True
    )
    tag = db.Column(db.String(50), nullable=False)

    # Relationship to the backup this tag belongs to
    backup = db.relationship("BackupData", back_populates="tags")

    def __repr__(self):
        return f"<BackupTag {self.tag} for Backup {self.backup_id}>"


# -----------------------------------------------------------------------
# Backup Audit Logging Section
# -----------------------------------------------------------------------
class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    device_id = db.Column(
        UUID_TYPE,
        db.ForeignKey("device_manager.id", ondelete="CASCADE"),
        nullable=False,
    )
    backup_id = db.Column(
        UUID_TYPE, db.ForeignKey("backup_data.id"), nullable=False, index=True
    )
    action = db.Column(db.String(50), nullable=False, default="created", index=True)
    performed_by = db.Column(UUID_TYPE, db.ForeignKey("users.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(DEFAULT_TZ))
    description = db.Column(db.String(1000), nullable=True)

    # Relationship to the backup this log belongs to
    backup = db.relationship("BackupData", back_populates="audit_logs")
    performed_by_user = db.relationship("User", back_populates="audit_logs")

    def __repr__(self):
        return f"<AuditLog {self.action} on Backup {self.backup_id}>"


# -----------------------------------------------------------------------
# AI Recommendation Data
# -----------------------------------------------------------------------
class AIRecommendations(db.Model):
    __tablename__ = "ai_recommendations"
    __table_args__ = (
        db.Index("idx_recommendation_device", "device_id", "created_at"),
        db.Index("idx_recommendation_priority", "priority", "created_at"),
        db.Index("idx_duplicate_status", "is_duplicate"),
        {"comment": "Stores AI-generated recommendations for network devices"},
    )

    id = db.Column(UUID_TYPE, primary_key=True, default=lambda: uuid.uuid4())
    device_id = db.Column(
        UUID_TYPE,
        db.ForeignKey("device_manager.id", ondelete="CASCADE"),
        nullable=False,
        comment="Foreign key referencing the device this recommendation applies to",
    )
    title = db.Column(
        db.String(255),
        nullable=False,
        comment="Short title describing the recommendation",
    )
    description = db.Column(
        db.Text, nullable=True, comment="Detailed description of the recommendation"
    )
    command = db.Column(  # Diubah dari commands ke command
        db.Text,
        nullable=False,
        comment="CLI commands to implement the recommendation",
    )
    risk_level = db.Column(
        db.String(50),
        nullable=False,
        default="low",
        comment="Risk level (low, medium, high)",
    )
    impact_area = db.Column(
        db.String(255),
        nullable=False,
        default="security",
        comment="Impact area (security, availability, performance)",
    )
    is_duplicate = db.Column(  # Kolom baru untuk deduplikasi
        db.Boolean,
        default=False,
        index=True,
        comment="Flag marking duplicate recommendations",
    )
    embedding = db.Column(  # Kolom baru untuk vector embeddings
        db.JSON,
        nullable=True,
        comment="Embedding vector for similarity checking",
    )
    created_at = db.Column(
        db.DateTime,
        default=datetime.now,
        nullable=False,  # Diperbaiki: menghapus ()
        comment="Timestamp when the recommendation was generated",
    )
    is_applied = db.Column(
        db.Boolean,
        default=False,
        index=True,
        comment="Flag indicating whether the recommendation has been applied",
    )
    applied_at = db.Column(
        db.DateTime,
        nullable=True,
        comment="Timestamp when the recommendation was applied",
    )
    priority = db.Column(
        db.Integer,
        default=1,
        nullable=False,
        comment="Priority level (1: Low, 2: Medium, 3: High)",
    )
    status = db.Column(
        db.String(50),
        default="generated",
        nullable=False,
        comment="Status (generated, applied, failed)",
    )
    applied_by = db.Column(
        UUID_TYPE,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who applied the recommendation",
    )
    error_message = db.Column(
        db.Text,
        nullable=True,
        comment="Error message if the recommendation application failed",
    )

    # Relationships
    device = db.relationship("DeviceManager", back_populates="recommendations")
    applied_by_user = db.relationship(
        "User", back_populates="applied_recommendations", foreign_keys=[applied_by]
    )

    def __repr__(self):
        return f"<AIRecommendation {self.id[:8]} {self.title} ({self.risk_level})>"

    def to_dict(self):
        """Serialize recommendation for API responses"""
        return {
            "id": str(self.id),
            "device_id": str(self.device_id),
            "title": self.title,
            "description": self.description,
            "command": self.command,
            "risk_level": self.risk_level,
            "impact_area": self.impact_area,
            "is_duplicate": self.is_duplicate,
            "embedding": self.embedding,
            "created_at": self.created_at.isoformat(),
            "is_applied": self.is_applied,
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
            "priority": self.priority,
            "status": self.status,
            "applied_by": str(self.applied_by) if self.applied_by else None,
            "error_message": self.error_message,
        }
