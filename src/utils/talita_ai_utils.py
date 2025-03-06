from flask import current_app
import json
import requests
from openai import OpenAI
from pydantic import BaseModel, Field
from .config_manager_utils import ConfigurationManagerUtils
import logging

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------
# Talita API: Generate Configuration File
# ----------------------------------------------------------


def generate_configfile_talita(question, user_id):
    """
    Mengirimkan permintaan POST ke API TALITA untuk mendapatkan jawaban dari chat completion.

    Parameters:
    question (str): Pertanyaan yang ingin diajukan kepada TALITA.
    user_id (str): ID pengguna yang mengajukan pertanyaan.

    Returns:
    dict: Hasil dalam format JSON, termasuk 'success' sebagai boolean dan 'message' sebagai string.
    """

    talita_url = current_app.config["TALITA_URL"]
    talita_api_key = current_app.config["TALITA_API_KEY"]

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
        response = requests.post(talita_url, headers=headers, json=data, verify=False)

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
                error_message = (
                    "Server error on the TALITA API. Please try again later."
                )

            return {"success": False, "message": error_message}

    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "message": "Failed to connect to the TALITA API. Please check your network connection.",
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "message": "The request to TALITA API timed out. Please try again later.",
        }
    except requests.exceptions.RequestException as e:
        return {"success": False, "message": f"An error occurred: {str(e)}"}


def talita_chatbot(question, user_id):
    """
    Mengirimkan permintaan POST ke API TALITA untuk mendapatkan jawaban dari chat completion.

    Parameters:
    question (str): Pertanyaan yang ingin diajukan kepada TALITA.
    user_id (str): ID pengguna yang mengajukan pertanyaan.

    Returns:
    dict: Hasil dalam format JSON, termasuk 'success' sebagai boolean dan 'message' sebagai string.
    """

    talita_url = current_app.config["TALITA_URL"]
    talita_api_key = current_app.config["TALITA_API_KEY"]

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
        response = requests.post(talita_url, headers=headers, json=data, verify=False)

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
                error_message = (
                    "Server error on the TALITA API. Please try again later."
                )

            return {"success": False, "message": error_message}

    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "message": "Failed to connect to the TALITA API. Please check your network connection.",
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "message": "The request to TALITA API timed out. Please try again later.",
        }
    except requests.exceptions.RequestException as e:
        return {"success": False, "message": f"An error occurred: {str(e)}"}


# ----------------------------------------------------------
# OpenAI API: Generate Configuration File
# ----------------------------------------------------------
class NetworkAutomationUtility:
    def __init__(self):
        self.client = OpenAI()
        self.model = "gpt-4o"
        self.tools = [
            {
                "type": "function",
                "function": {
                    "name": "send_configuration",
                    "description": "Send network configuration to a device using SSH",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ip_address": {
                                "type": "string",
                                "description": "Device IP address",
                            },
                            "username": {
                                "type": "string",
                                "description": "SSH username",
                            },
                            "password": {
                                "type": "string",
                                "description": "SSH password",
                            },
                            "ssh": {"type": "number", "description": "SSH Port"},
                            "command": {
                                "type": "string",
                                "description": "Configuration command",
                            },
                        },
                        "required": [
                            "ip_address",
                            "username",
                            "password",
                            "ssh",
                            "command",
                        ],
                        "additionalProperties": False,
                    },
                    "strict": True,
                },
            }
        ]

    def extract_configuration_info(self, user_input: str):
        """First LLM call to determine if input is a configuration intent"""
        logger.info("Starting configuration extraction analysis")
        logger.debug(f"Input text: {user_input}")

        completion = self.client.beta.chat.completions.parse(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are 'Talita', an AI assistant specialized in network automation and configuration. "
                        "Your task is to analyze the user's request and determine if it is related to **Intent-Based Networking (IBN)**.\n\n"
                        "1️ **If the request is IBN-related:**\n"
                        "- Extract:\n"
                        "  - The **target device's IP address** (if provided).\n"
                        "  - The **vendor** of the device (e.g., Mikrotik, Cisco, Fortigate).\n"
                        "  - Whether the request is a valid configuration command.\n"
                        "  - Identify any **missing parameters** required for the configuration.\n"
                        "  - If essential parameters are missing, respond by stating what is missing.\n\n"
                        "2️ **If the request is NOT related to Intent-Based Networking:**\n"
                        "- Provide a human-readable response in **Bahasa Indonesia** informing the user that their request is not related to IBN "
                        "and guide them on how to structure a valid intent-based request."
                    ),
                },
                {"role": "user", "content": user_input},
            ],
            response_format=ConfigurationExtraction,
        )

        result = completion.choices[0].message.parsed if completion.choices else None
        if not result:
            logger.error("LLM failed to parse the request")
            return None

        logger.info(
            f"Extraction complete - Intent: {result.is_configuration_intent}, Confidence: {result.confidence_score:.2f}, "
            f"IP: {result.description}"
        )
        return result

    def parse_configuration_details(self, description: str):
        """Second LLM call to extract specific configuration details"""
        logger.info("Starting configuration details parsing")

        completion = self.client.beta.chat.completions.parse(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": "Extract detailed configuration information, ensuring vendor-specific syntax is included.",
                },
                {"role": "user", "content": description},
            ],
            response_format=ConfigurationDetails,
        )

        result = completion.choices[0].message.parsed if completion.choices else None
        if not result:
            logger.error("LLM failed to parse configuration details")
            return None

        logger.info(
            f"Parsed configuration - IP: {result.ip_address}, Vendor: {result.vendor}, Command: {result.command}"
        )
        return result

    def generate_configuration(self, username, password, ssh, configuration_details):
        """Third LLM call: Provide the configuration response"""
        logger.info("Generating device configuration")

        system_prompt = """
        You are a network automation expert. Generate configuration commands based on the user's intent.
        Ensure that the generated command is specific to the vendor's CLI syntax.
        """

        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"username: {username}, password: {password}, ssh: {ssh}, {str(configuration_details.model_dump())}",
            },
        ]

        completion = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=self.tools,
        )

        if not completion.choices:
            logger.error("LLM failed to generate configuration")
            return None

        for tool_call in completion.choices[0].message.tool_calls:
            name = tool_call.function.name
            args = json.loads(tool_call.function.arguments)
            messages.append(completion.choices[0].message)
            result = self.call_function(name, args)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result),
                }
            )

        completion_2 = self.client.beta.chat.completions.parse(
            model=self.model,
            messages=messages,
            tools=self.tools,
            response_format=ConfigurationResponse,
        )

        if not completion_2.choices:
            logger.error("LLM failed to generate final configuration response")
            return None

        logger.info(
            f"Generated configuration: {completion_2.choices[0].message.parsed.command}"
        )
        return completion_2.choices[0].message.parsed

    def process_configuration_request(self, user_input: str, username, password, ssh):
        """Main function implementing the prompt chain"""
        logger.info(f"Processing configuration request: {user_input}")

        initial_extraction = self.extract_configuration_info(user_input)
        # Gate check: Verify if it's a configuration event with sufficient confidence
        if (
            not initial_extraction.is_configuration_intent
            or initial_extraction.confidence_score < 0.7
        ):
            logger.warning(
                f"Gate check failed - is_configuration_intent: {initial_extraction.is_configuration_intent}, result: {initial_extraction.description}"
            )
            return initial_extraction.description

        logger.info("Gate check passed, proceeding with event processing")

        # Second LLM call: Extract detailed configuration info
        configuration_details = self.parse_configuration_details(
            initial_extraction.description
        )
        if not configuration_details:
            logger.warning("Failed to extract configuration details")
            return None

        # Third LLM call: Generate configuration
        confirmation = self.generate_configuration(
            username, password, ssh, configuration_details
        )
        if not confirmation:
            logger.warning("Failed to generate configuration")
            return None

        logger.info("Configuration request processed successfully")
        return confirmation.response

    def send_configuration(self, ip_address, username, password, ssh, command):
        configuration = ConfigurationManagerUtils(ip_address, username, password, ssh)
        send_command = configuration.configure_device(command)
        status = send_command.split(" ")[0]
        return {"success": status == "success", "message": send_command}

    def call_function(self, name, args):
        if name == "send_configuration":
            return self.send_configuration(**args)
        raise ValueError(f"Unknown function: {name}")


class ConfigurationExtraction(BaseModel):
    """First LLM call: Extract basic prompt configuration information"""

    description: str = Field(
        description="Configuration request details, including target device IP and vendor. Provide a human-readable response in **Bahasa Indonesia** informing the user that their request is not related"
    )
    is_configuration_intent: bool = Field(
        description="True if this is a valid network configuration request."
    )
    confidence_score: float = Field(description="Confidence score between 0 and 1")


class ConfigurationDetails(BaseModel):
    """Second LLM call: Parse specific configuration details"""

    ip_address: str = Field(description="IP Address of target device")
    vendor: str = Field(description="Device vendor (e.g., Mikrotik, Cisco)")
    command: str = Field(description="Configuration command to be executed")


class ConfigurationResponse(BaseModel):
    """Third LLM call: Provide the configuration response"""

    command: str = Field(description="Configuration command to be executed.")
    response: str = Field(
        description="Provide a human-readable response in Indonesian. If the command fails or does not align with the Intent-Based Networking concept, return a clear error message. Explain that the request is not suitable for Intent-Based Networking, then provide an example of a correct prompt."
    )
