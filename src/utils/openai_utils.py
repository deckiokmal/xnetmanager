import re
from openai import OpenAI


class ConfigurationFileManagement:
    def __init__(self):
        self.client = OpenAI()
        self.model = "gpt-4o"

    def validated_configuration(
        self, configuration: str, device_vendor: str
    ):
        """
        Validasi konfigurasi berdasarkan script device configuration yang diinput oleh user.
        """

        response = self.client.chat.completions.create(
            model=self.model,
            response_format="json",
            messages=[
                {
                    "role": "system",
                    "content": f"You are an expert in network device configuration and syntax validation, specializing in {device_vendor} devices.",
                },
                {
                    "role": "user",
                    "content": f"""
                    Validate the following configuration for a network device.

                    - Device Vendor: {device_vendor}
                    - Configuration:
                    ```
                    {configuration}
                    ```

                    Return a JSON object with the following structure:
                    {{
                        "is_valid": <true/false>,
                        "errors": [
                            {{
                                "line": <line_number>,
                                "error_code": <short_error_code>,
                                "message": <detailed_error_message>
                            }},
                            ...
                        ],
                        "suggestions": <list of suggested fixes if errors exist>
                    }}
                    """,
                },
            ],
        )

        # Parsing JSON response
        validation_result = response.choices[0].message.content

        return validation_result  # Sudah dalam format JSON

    def create_configuration_with_openai(self, question, vendor):
        response = self.client.chat.completions.create(
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
