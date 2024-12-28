import openai
import re


def validate_generated_template_with_openai(config, vendor):
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": f"You are an expert in network device configuration and syntax validation, specializing in {vendor} devices.",
            },
            {
                "role": "user",
                "content": f"Please validate the following configuration for a {vendor} network device:\n\n{config}\n\n"
                "If the configuration is completely correct and valid, respond with exactly 'VALID'. "
                "If there are any errors or incomplete syntax, respond with exactly 'ERROR' and provide a detailed explanation of the issues.",
            },
        ],
    )

    # Extract the validation result from the response
    validation_result = response["choices"][0]["message"]["content"].strip()

    # Use exact matching to avoid confusion
    if validation_result.upper() == "VALID":
        return {"is_valid": True, "result_message": validation_result}
    elif validation_result.startswith("ERROR"):
        # Extract the error message
        error_message = re.sub(
            r"^ERROR\s*:\s*", "", validation_result, flags=re.IGNORECASE
        ).strip()
        return {"is_valid": False, "error_message": error_message}
    else:
        return {
            "is_valid": False,
            "error_message": "The validation result was unclear. Please check manually.",
        }


def create_configuration_with_openai(question, vendor):
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": f"You are an expert in network device configuration and syntax validation, specializing in {vendor} devices. Your responses should only include the configuration without any additional text, explanation, or formatting.",
            },
            {
                "role": "user",
                "content": f"Please generate the configuration for a {vendor} network device based on the following requirements:\n\n{question}\n\n"
                "Your response must only contain the configuration commands. Do not include any explanations or additional text."
                "If there are any errors or unclear question, respond with exactly 'ERROR' and provide a detailed explanation of the issues.",
            },
        ],
    )

    # Extract the validation result from the response
    configuration_result = response["choices"][0]["message"]["content"].strip()

    # Check for ambiguity or unclear responses
    unclear_indicators = [
        "unclear",
        "not sure",
        "please clarify",
        "error",
        "?",
        "I am not sure",
        "ambiguous",
        "confusing",
        "ERROR",
    ]
    if any(
        indicator.lower() in configuration_result.lower()
        for indicator in unclear_indicators
    ):
        error_message = (
            "ERROR: The response indicates ambiguity or unclear instructions."
        )
        detailed_error_message = configuration_result
        return error_message, detailed_error_message

    return configuration_result, None


def summarize_error_with_openai(error_log, vendor):
    """
    Menggunakan OpenAI API untuk menyederhanakan pesan error atau mengonfirmasi sukses.
    Jika `error_log` kosong, return status sukses dengan pesan "Configuration successfully applied".
    Jika terdapat error, ringkas pesan error dalam bahasa Indonesia.
    """
    if not error_log.strip():
        # Jika error_log kosong, anggap konfigurasi berhasil
        return {"status": "success", "message": "Configuration successfully applied."}

    # Jika ada pesan error, gunakan OpenAI untuk menyederhanakan pesan
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": f"You are an expert in network device configuration for {vendor} devices. Respond in Indonesian. If the configuration is error-free, reply exactly 'Configuration successfully applied.' If there is an error, provide a simplified summary of the error message.",
            },
            {
                "role": "user",
                "content": f"Here is the error log for a {vendor} device configuration attempt:\n\n{error_log}\n\n"
                "Please summarize this error log into a simple, user-friendly message in Indonesia.",
            },
        ],
    )

    summary_result = response["choices"][0]["message"]["content"].strip()

    # Periksa hasil dari OpenAI, dan tentukan statusnya
    if summary_result == "Configuration successfully applied.":
        return {"status": "success", "message": summary_result}
    else:
        return {"status": "error", "message": summary_result}


def analyze_device_with_openai(backup_content, max_tokens=8000, overlap=100):
    """
    Menggunakan OpenAI API untuk menganalisis konfigurasi MikroTik, dengan penanganan kesalahan token.

    Args:
        backup_content (str): Isi file backup konfigurasi Mikrotik.
        max_tokens (int): Batas maksimum token untuk setiap permintaan ke OpenAI.

    Returns:
        tuple: Tuple berisi (ringkasan analisis, daftar rekomendasi dengan syntax).
    """

    def split_content_with_overlap(content, max_tokens=8000, overlap=100):
        # Fungsi untuk membagi konten menjadi bagian-bagian dengan panjang maksimum
        tokens = len(content.split())  # Estimasi jumlah token (tidak akurat)
        parts = []
        start = 0
        while start < len(content):
            end = min(start + max_tokens, len(content))
            parts.append(content[start:end])
            start = end
        return parts

    # Bagi backup menjadi bagian-bagian
    parts = split_content_with_overlap(backup_content, max_tokens)

    # Inisialisasi variabel untuk menyimpan hasil
    overall_analysis = []
    all_recommendations = []

    for part in parts:
        # Buat prompt dengan bagian backup yang lebih kecil
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": f"Anda adalah seorang ahli konfigurasi jaringan MikroTik. Tugas Anda adalah menganalisis konfigurasi yang diberikan dan memberikan rekomendasi praktik terbaik. Jawaban Anda harus dalam bahasa Indonesia dan mencakup:\n1. Ringkasan singkat konfigurasi yang ada.\n2. Daftar rekomendasi praktik terbaik, termasuk:\n   - Deskripsi singkat rekomendasi.\n   - Contoh syntax konfigurasi MikroTik yang relevan untuk menerapkan rekomendasi tersebut.",
                },
                {
                    "role": "user",
                    "content": f"Berikut adalah konfigurasi MikroTik yang ingin saya analisis:\n\n`\n{backup_content}\n`\n\nMohon berikan analisis mendalam dan rekomendasi untuk meningkatkan keamanan, kinerja, dan stabilitas konfigurasi ini.",
                },
            ],
        )

        # Parsing respons dan tambahkan ke hasil keseluruhan
        analysis = response["choices"][0]["message"]["content"]
        overall_analysis.append(analysis)

        recommendations = []
    for part in analysis.split("\n\n"):
        if "Rekomendasi" in part:
            recommendation = part.split(":")
            if len(recommendation) == 2:
                recommendations.append(
                    (recommendation[0].strip(), recommendation[1].strip())
                )

        all_recommendations.extend(recommendations)

    # Gabungkan hasil dari semua bagian
    return "\n".join(overall_analysis), all_recommendations
