from src import mail
from flask_mail import Message
from flask import url_for, current_app
from itsdangerous import URLSafeTimedSerializer as Serializer, SignatureExpired


def send_verification_email(user):
    token = user.generate_email_verification_token()
    msg = Message(
        "Email Verification",
        sender=current_app.config["MAIL_USERNAME"],
        recipients=[user.email],
    )
    link = url_for("profile.verify_email", token=token, _external=True)
    msg.body = f"Please click the link to verify your email address: {link}"
    mail.send(msg)


def generate_verification_token(email):
    """Hasilkan token verifikasi email untuk alamat email tertentu."""
    s = Serializer(current_app.config["SECRET_KEY"], salt="email-confirm")
    return s.dumps(email, salt="email-confirm")


def verify_token(token, expiration=3600):
    """Verifikasi token dan kembalikan email jika token valid dan belum kadaluarsa."""
    s = Serializer(current_app.config["SECRET_KEY"], salt="email-confirm")
    try:
        email = s.loads(token, max_age=expiration)
    except SignatureExpired:
        return False
    return email
