from flask import Blueprint, request, jsonify, current_app
from src.utils.talita_ai_utils import talita_chatbot
from flask_login import current_user

# Buat Blueprint untuk endpoint API
api_bp = Blueprint("api", __name__)


@api_bp.route("/api/chat", methods=["POST"])
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
