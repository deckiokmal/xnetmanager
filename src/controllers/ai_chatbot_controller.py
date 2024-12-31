from flask import (
    Blueprint,
    request,
    jsonify,
    current_app,
    render_template,
    flash,
    redirect,
    url_for,
)
from flask_login import (
    login_required,
    current_user,
)
from .decorators import (
    required_2fa,
)
from flask_login import logout_user
from src.utils.talita_ai_utils import talita_chatbot
import logging
from src import db

# Buat Blueprint untuk endpoint chatbot
chatbot_bp = Blueprint("chatbot", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging untuk aplikasi
logging.basicConfig(level=logging.INFO)


@chatbot_bp.before_app_request
def setup_logging():
    """
    Mengatur level logging untuk aplikasi.
    """
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


@error_bp.app_errorhandler(404)
def page_not_found(error):
    """
    Menangani error 404 dan menampilkan halaman 404.
    """
    current_app.logger.error(f"Error 404: {error}")
    return render_template("main/404.html"), 404


@chatbot_bp.before_request
def before_request_func():
    """
    Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan.
    Jika pengguna harus logout paksa, lakukan logout dan arahkan ke halaman login.
    Jika tidak terotentikasi, kembalikan pesan 'Unauthorized access'.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return render_template("main/404.html"), 404

    # Jika pengguna terotentikasi dan memiliki flag force_logout, lakukan logout
    if current_user.force_logout:
        current_user.force_logout = False  # Reset the flag
        db.session.commit()
        logout_user()
        flash("Your password has been updated. Please log in again.", "info")
        return redirect(url_for("main.login"))


# --------------------------------------------------------------------------------
# Chatbot Section
# --------------------------------------------------------------------------------


@chatbot_bp.route("/chatbot/chat", methods=["POST"])
@login_required
@required_2fa
def chat_with_talita():
    # Ambil pesan dari body permintaan
    data = request.get_json()
    question = data.get("message", "").strip()

    if not question:
        return jsonify({"success": False, "message": "Please enter a question."}), 400

    # Ambil ID pengguna saat ini (dari Flask-Login)
    user_id = str(current_user.id) if current_user.is_authenticated else "anonymous"

    # Gunakan fungsi utilitas untuk mengirim pertanyaan ke TALITA
    response = talita_chatbot(question, user_id)

    if response["success"]:
        return jsonify(response), 200
    else:
        return jsonify(response), 500
