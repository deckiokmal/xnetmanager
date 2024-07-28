from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from src.models.users_model import User
from flask_login import current_user


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


class UserUpdateForm(FlaskForm):
    """
    Formulir untuk memperbarui data pengguna.

    Field:
    - first_name: StringField untuk nama depan dengan validator untuk data yang diperlukan.
    - last_name: StringField untuk nama belakang dengan validator untuk data yang diperlukan.
    - phone_number: StringField untuk nomor telepon.
    - profile_picture: StringField untuk URL gambar profil.
    - company: StringField untuk nama perusahaan.
    - title: StringField untuk jabatan.
    - city: StringField untuk kota.
    - division: StringField untuk divisi.
    - time_zone: StringField untuk zona waktu.
    """

    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    phone_number = StringField("Phone Number")
    profile_picture = StringField("Profile Picture URL")
    company = StringField("Company")
    title = StringField("Title")
    city = StringField("City")
    division = StringField("Division")
    time_zone = StringField("Time Zone")


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
