from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, Length, InputRequired
from src.models.users_model import User


class RegisterForm(FlaskForm):
    """
    Formulir untuk registrasi pengguna.

    Field:
    - username: StringField untuk nama pengguna dengan validator untuk data yang diperlukan dan panjang.
    - password: PasswordField untuk kata sandi dengan validator untuk data yang diperlukan dan panjang.
    - confirm: PasswordField untuk mengkonfirmasi kata sandi, harus cocok dengan kata sandi.

    Metode:
    - validate: Metode validasi kustom untuk memeriksa apakah nama pengguna sudah terdaftar dan apakah kata sandi cocok.
    """
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=6, max=40)]
    )
    password = PasswordField(
        "Password", validators=[DataRequired(), Length(min=6, max=25)]
    )
    confirm = PasswordField(
        "Repeat password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )

    def validate(self, extra_validators):
        initial_validation = super(RegisterForm, self).validate(extra_validators)
        if not initial_validation:
            return False
        user = User.query.filter_by(username=self.username.data).first()
        if user:
            self.username.errors.append("Username already registered")
            return False
        if self.password.data != self.confirm.data:
            self.password.errors.append("Passwords must match")
            return False
        return True


class LoginForm(FlaskForm):
    """
    Formulir untuk login pengguna.

    Field:
    - username: StringField untuk nama pengguna dengan validator untuk data yang diperlukan.
    - password: PasswordField untuk kata sandi dengan validator untuk data yang diperlukan.
    """
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


class TwoFactorForm(FlaskForm):
    """
    Formulir untuk otentikasi dua faktor.

    Field:
    - otp: StringField untuk memasukkan OTP (One-Time Password) dengan validator untuk input yang diperlukan dan panjang.
    """
    otp = StringField("Enter OTP", validators=[InputRequired(), Length(min=6, max=6)])
