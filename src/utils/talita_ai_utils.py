import requests


def talita_chat_completion(url, apikey, question, user_id):
    """
    Mengirimkan permintaan POST ke API TALITA untuk mendapatkan jawaban dari chat completion.

    Parameters:
    url (str): URL endpoint API TALITA.
    apikey (str): API key yang digunakan untuk otentikasi.
    question (str): Pertanyaan yang ingin diajukan kepada TALITA.
    user_id (str): ID pengguna yang mengajukan pertanyaan.

    Returns:
    str: Jawaban dari TALITA jika permintaan berhasil, atau pesan error jika gagal.
    """

    # Header yang ingin ditambahkan
    headers = {
        "Content-Type": "application/json",
        "apikey": apikey,
    }

    # Data yang akan dikirim dalam body request, dalam format JSON
    data = {
        "question": question,
        "user_id": user_id,
    }

    # Mengirimkan permintaan POST
    response = requests.post(url, headers=headers, json=data)

    # Mengecek status kode dari respon
    if response.status_code == 200:
        return response.json()["TALITA"]
    else:
        return f"Gagal melakukan permintaan: {response.status_code, response.text}"
