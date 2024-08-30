import requests
from flask import flash, current_app



def talita_chat_completion(question, user_id):
    """
    Mengirimkan permintaan POST ke API TALITA untuk mendapatkan jawaban dari chat completion.

    Parameters:
    url (str): URL endpoint API TALITA.
    apikey (str): API key yang digunakan untuk otentikasi.
    question (str): Pertanyaan yang ingin diajukan kepada TALITA.
    user_id (str): ID pengguna yang mengajukan pertanyaan.

    Returns:
    str: Jawaban dari TALITA jika permintaan berhasil, atau None jika gagal.
    """

    talita_api_key = current_app.config.get('TALITA_API_KEY')
    talita_url = current_app.config.get('TALITA_URL')

    # Header yang ingin ditambahkan
    headers = {
        "Content-Type": "application/json",
        "apikey": talita_api_key,
    }

    # Data yang akan dikirim dalam body request, dalam format JSON
    data = {
        "question": question,
        "user_id": user_id,
    }

    try:
        # Mengirimkan permintaan POST
        response = requests.post(talita_url, headers=headers, json=data)

        # Mengecek status kode dari respon
        if response.status_code == 200:
            return response.json().get("TALITA", "No valid response received.")
        elif response.status_code == 401:
            flash("Unauthorized access. Please check your API key.", "danger")
        elif response.status_code == 404:
            flash("The requested resource was not found.", "warning")
        elif response.status_code == 500:
            flash("Server error on the TALITA API. Please try again later.", "danger")
        else:
            flash(
                f"Failed to get a response from TALITA: {response.status_code}, {response.text}",
                "danger",
            )

    except requests.exceptions.ConnectionError:
        flash(
            "Failed to connect to the TALITA API. Please check your network connection.",
            "danger",
        )
    except requests.exceptions.Timeout:
        flash("The request to TALITA API timed out. Please try again later.", "warning")
    except requests.exceptions.RequestException as e:
        flash(f"An error occurred while making the request: {str(e)}", "danger")

    return None


def talita_chatbot(question, user_id):
    """
    Mengirimkan permintaan POST ke API TALITA untuk mendapatkan jawaban dari chat completion.

    Parameters:
    question (str): Pertanyaan yang ingin diajukan kepada TALITA.
    user_id (str): ID pengguna yang mengajukan pertanyaan.

    Returns:
    dict: Hasil dalam format JSON, termasuk 'success' sebagai boolean dan 'message' sebagai string.
    """

    talita_api_key = current_app.config.get('TALITA_API_KEY')
    talita_url = current_app.config.get('TALITA_URL')

    # Header yang ingin ditambahkan
    headers = {
        "Content-Type": "application/json",
        "apikey": talita_api_key,
    }

    # Data yang akan dikirim dalam body request, dalam format JSON
    data = {
        "question": question,
        "user_id": user_id,
    }

    try:
        # Mengirimkan permintaan POST
        response = requests.post(talita_url, headers=headers, json=data)

        # Mengecek status kode dari respon
        if response.status_code == 200:
            answer = response.json().get("TALITA", "No valid response received.")
            return {"success": True, "message": answer}
        else:
            # Menangani berbagai status kesalahan
            error_message = f"Error {response.status_code}: {response.text}"
            if response.status_code == 401:
                error_message = "Unauthorized access. Please check your API key."
            elif response.status_code == 404:
                error_message = "The requested resource was not found."
            elif response.status_code == 500:
                error_message = "Server error on the TALITA API. Please try again later."

            return {"success": False, "message": error_message}

    except requests.exceptions.ConnectionError:
        return {"success": False, "message": "Failed to connect to the TALITA API. Please check your network connection."}
    except requests.exceptions.Timeout:
        return {"success": False, "message": "The request to TALITA API timed out. Please try again later."}
    except requests.exceptions.RequestException as e:
        return {"success": False, "message": f"An error occurred: {str(e)}"}