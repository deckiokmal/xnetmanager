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
