from flask import (
    Blueprint,
    request,
    jsonify,
)
import requests
from requests.auth import HTTPBasicAuth

# Buat Blueprint untuk endpoint whatsapp
whatsapp_bp = Blueprint("whatsapp", __name__)


# --------------------------------------------------------------------------------
# whatsapp Section
# --------------------------------------------------------------------------------


@whatsapp_bp.route("/send-message", methods=["GET"])
def send_message_via_gateway():
    try:
        # Ambil parameter dari URL
        phone = request.args.get("phone")
        message = request.args.get("message")

        # Validasi parameter
        if not phone or not message:
            return (
                jsonify(
                    {"error": "Both 'phone' and 'message' parameters are required"}
                ),
                400,
            )

        # Data yang akan dikirim ke WhatsApp Gateway
        data = {
            "phone": f"{phone}@s.whatsapp.net",  # Format nomor telepon 62
            "message": message,
        }

        # URL WhatsApp Gateway
        gateway_url = "http://10.0.201.1:8442/send/message"

        # Basic Authentication credentials
        username = "deckiokmal"
        password = "N4sional"

        # Mengirim request POST ke WhatsApp Gateway dengan Basic Auth
        response = requests.post(
            gateway_url,
            json=data,
            headers={"Content-Type": "application/json"},
            auth=HTTPBasicAuth(username, password),  # Tambahkan autentikasi Basic
        )

        # Periksa respons dari WhatsApp Gateway
        if response.status_code != 200:
            return (
                jsonify(
                    {"error": "Failed to send message", "details": response.json()}
                ),
                response.status_code,
            )

        # Respons sukses
        return jsonify({"status": "success", "details": response.json()}), 200

    except Exception as e:
        # Penanganan error
        return jsonify({"error": str(e)}), 500
