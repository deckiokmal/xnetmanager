from datetime import datetime
from flask_login import UserMixin
import pyotp
from src import bcrypt, db
from config import Config


class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    is_two_factor_authentication_enabled = db.Column(
        db.Boolean, nullable=False, default=False
    )
    secret_token = db.Column(db.String, unique=True)

    roles = db.relationship("Role", secondary="user_roles", back_populates="users")

    def __init__(self, username, password):
        self.username = username
        self.password = bcrypt.generate_password_hash(password)
        self.created_at = datetime.now()
        self.secret_token = pyotp.random_base32()

    def get_authentication_setup_uri(self):
        return pyotp.totp.TOTP(self.secret_token).provisioning_uri(
            name=self.username, issuer_name=Config.APP_NAME
        )

    def is_otp_valid(self, user_otp):
        totp = pyotp.parse_uri(self.get_authentication_setup_uri())
        return totp.verify(user_otp)

    def __repr__(self):
        return f"<user {self.username}>"

    def has_role(self, role):
        return bool(
            Role.query.join(Role.users)
            .filter(User.id == self.id)
            .filter(Role.name == role)
            .count()
            > 0
        )


class Role(db.Model):

    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship("User", secondary="user_roles", back_populates="roles")
    permissions = db.relationship(
        "Permission", secondary="role_permissions", back_populates="roles"
    )

    def has_permission(self, permission):
        if self.permissions:
            return permission in self.permissions.split(",")
        return False

    def __repr__(self):
        return "<Role {}>".format(self.name)


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
