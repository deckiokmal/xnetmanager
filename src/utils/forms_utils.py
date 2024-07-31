from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField, FileField, SelectField
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
    ValidationError,
    Optional,
)
from src.models.users_model import User


class RegisterForm(FlaskForm):
    """
    Formulir untuk registrasi pengguna.

    Field:
    - first_name: StringField untuk nama depan dengan validator untuk data yang diperlukan.
    - last_name: StringField untuk nama belakang dengan validator untuk data yang diperlukan.
    - email: EmailField untuk alamat email dengan validator untuk data yang diperlukan dan format email.
    - password: PasswordField untuk kata sandi dengan validator untuk data yang diperlukan dan panjang.
    - confirm_password: PasswordField untuk mengkonfirmasi kata sandi, harus cocok dengan kata sandi.

    Metode:
    - validate_email: Metode validasi kustom untuk memeriksa apakah email sudah terdaftar.
    """

    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Password", validators=[DataRequired(), Length(min=8, max=25)]
    )
    confirm_password = PasswordField(
        "Repeat Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords harus match."),
        ],
    )

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("Email sudah terdaftar.")


class LoginForm(FlaskForm):
    """
    Formulir untuk login pengguna.

    Field:
    - email: EmailField untuk alamat email dengan validator untuk data yang diperlukan dan format email.
    - password: PasswordField untuk kata sandi dengan validator untuk data yang diperlukan.
    """

    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])


class TwoFactorForm(FlaskForm):
    """
    Formulir untuk otentikasi dua faktor.

    Field:
    - otp: StringField untuk memasukkan OTP (One-Time Password) dengan validator untuk input yang diperlukan dan panjang.
    """

    otp = StringField("Enter OTP", validators=[DataRequired(), Length(min=6, max=6)])


class UserUpdateForm(FlaskForm):
    """
    Formulir untuk memperbarui data pengguna oleh Role Admin.
    """

    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("New Password", validators=[Optional()])
    phone_number = StringField("Phone Number")
    profile_picture = StringField("Profile Picture URL")
    company = StringField("Company")
    title = StringField("Title")
    city = StringField("City")
    division = StringField("Division")
    is_verified = SelectField(
        "Email Verified", choices=[("True", "True"), ("False", "False")], coerce=str
    )
    is_2fa_enabled = SelectField(
        "2FA Enabled", choices=[("True", "True"), ("False", "False")], coerce=str
    )
    is_active = SelectField(
        "Active", choices=[("True", "True"), ("False", "False")], coerce=str
    )
    time_zone = StringField("Time Zone")


class ProfileUpdateForm(FlaskForm):
    """
    Formulir untuk memperbarui data profile pengguna.
    """

    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("New Password", validators=[Optional()])
    phone_number = StringField("Phone Number")
    profile_picture = StringField("Profile Picture URL")
    company = StringField("Company")
    title = StringField("Title")
    city = StringField("City")
    division = StringField("Division")
    time_zone = StringField("Time Zone")


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField("Old Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired()])
    repeat_password = PasswordField(
        "Repeat New Password",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="Passwords must match."),
        ],
    )


class ProfilePictureForm(FlaskForm):
    profile_picture = FileField("Profile Picture", validators=[DataRequired()])


class User2FAEnableForm(FlaskForm):
    """
    Formulir untuk mengaktifkan/nonaktifkan 2FA.
    """

    is_2fa_enabled = SelectField(
        "2FA Enabled", choices=[("True", "True"), ("False", "False")], coerce=str
    )
