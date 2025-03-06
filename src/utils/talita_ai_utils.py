from flask import current_app
import json
import requests
from openai import OpenAI
from pydantic import BaseModel, Field
from .config_manager_utils import ConfigurationManagerUtils
import logging
from src.models.app_models import DeviceManager
from typing import Optional, Literal
import re

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
client = OpenAI()
model = "gpt-4o"


# --------------------------------------------------------------
# Step 1: Define Function logic for application
# --------------------------------------------------------------
class NetworkManager:

    @staticmethod
    def get_credentials(ip_address: str):
        """
        Mengambil kredensial jaringan dari database berdasarkan ip_address.
        Jika tidak ditemukan, gunakan nilai default dari environment variable.
        """
        credential = DeviceManager.query.filter_by(ip_address=ip_address).first()

        if credential:
            return credential.username, credential.password, credential.ssh
        else:
            return False

    @staticmethod
    def send_configuration(ip_address: str, command: str) -> dict:
        """Send configuration commands to network device"""
        username, password, ssh_port = NetworkManager.get_credentials(ip_address)
        config_manager = ConfigurationManagerUtils(
            ip_address, username, password, ssh_port
        )
        result = config_manager.configure_device(command)
        return {"success": "success" in result.lower(), "response": result}

    @staticmethod
    def send_monitoring_command(ip_address: str, command: str) -> dict:
        """Send monitoring command to network device"""
        logger.debug(f"Executing monitoring command: {command} on {ip_address}")
        username, password, ssh_port = NetworkManager.get_credentials(ip_address)
        config_manager = ConfigurationManagerUtils(
            ip_address, username, password, ssh_port
        )
        result = config_manager.configure_device(
            command
        )  # Pastikan ini sesuai dengan library yang digunakan
        return {"success": "success" in result.lower(), "response": result}


# --------------------------------------------------------------
# Step 2: Define the data models for routing and responses
# --------------------------------------------------------------
class NetworkingIntentType(BaseModel):
    """Router LLM call: Determine the type of networking intent"""

    intent: Literal["configure", "monitor", "other"] = Field(
        description="Type of networking intent being made"
    )
    confidence_score: float = Field(description="Confidence score between 0 and 1")
    description: str = Field(
        description="Cleaned description of the intent with device target ip address and vendor. Always verify the configuration by executing the appropriate command and presenting the results to the user for confirmation"
    )


class ConfigurationDetails(BaseModel):
    """Details for configuring a network device"""

    ip_address: str = Field(description="IP address of the target device to configure")
    vendor: str = Field(description="Vendor of the network device")
    command: str = Field(
        description="This command configures the device per vendor syntax without text formatting."
    )


class MonitoringDetails(BaseModel):
    """Details for monitoring a network device"""

    ip_address: str = Field(description="IP address of the target device to monitor")
    vendor: str = Field(description="Vendor of the network device")
    command: str = Field(
        description="Command to monitor the device. If a 'ping' command needs to be executed, it must always be set to an interval of four pings only to prevent continuous output, ensuring controlled execution and optimized system performance."
    )


class NetworkResponse(BaseModel):
    """Response from network operations"""

    response: str = Field(description="Result of the operation")
    success: bool = Field(
        description="Indicates whether the operation was successful. Always verify the configuration by executing the appropriate command and presenting the results to the user for confirmation."
    )


# --------------------------------------------------------------
# Step 3: Define the routing and processing functions
# --------------------------------------------------------------
def route_network_intent(user_input: str) -> NetworkingIntentType:
    """Router LLM call to determine the type of user intent request"""
    logger.info("Routing user intent request")

    completion = client.beta.chat.completions.parse(
        model=model,
        messages=[
            {
                "role": "system",
                "content": "Determine if this is a request to configure or monitor network devices.",
            },
            {"role": "user", "content": user_input},
        ],
        response_format=NetworkingIntentType,
    )

    result = completion.choices[0].message.parsed
    logger.info(
        f"Request routed as: {result.intent} with confidence: {result.confidence_score}"
    )
    return result


def handle_configure_intent(description: str) -> ConfigurationDetails:
    """Process a configure request and parsed command"""
    logger.info("Processing configure request")

    # Get configure details
    completion = client.beta.chat.completions.parse(
        model=model,
        messages=[
            {
                "role": "system",
                "content": "Extract details for creating a new configuration intent. With added command to check configuration results.",
            },
            {
                "role": "user",
                "content": description,
            },
        ],
        response_format=ConfigurationDetails,
    )

    details = completion.choices[0].message.parsed

    logger.info(f"New configure: {details.model_dump_json(indent=2)}")

    # Generate configuration details
    return details


def handle_monitor_intent(description: str) -> MonitoringDetails:
    """Process a monitor request and parsed command"""
    logger.info("Processing monitor request")

    # Get configure details
    completion = client.beta.chat.completions.parse(
        model=model,
        messages=[
            {
                "role": "system",
                "content": "Extract details for creating a new monitor intent.",
            },
            {
                "role": "user",
                "content": description,
            },
        ],
        response_format=MonitoringDetails,
    )

    details = completion.choices[0].message.parsed

    logger.info(f"New configure: {details.model_dump_json(indent=2)}")

    # Generate configuration details
    return details


def process_intent_request(user_input: str) -> Optional[NetworkResponse]:
    """Main function implementing the routing workflow"""
    logger.info("Processing intent request")

    # Route the request
    route_result = route_network_intent(user_input)

    # Check confidence threshold
    if route_result.confidence_score < 0.7:
        logger.warning(f"Low confidence score: {route_result.confidence_score}")
        return None

    # Route to appropriate handler
    if route_result.intent == "other":
        return f"other"

    # Periksa IP Address ke database sebelum LLM Call
    pattern = r"target\s+ip\s+(\d+\.\d+\.\d+\.\d+)"
    match = re.search(pattern, str(user_input), re.IGNORECASE)
    if match:
        ip_address = match.group(1)
        credentials = NetworkManager.get_credentials(ip_address)
        if credentials:

            # Route to appropriate handler
            if route_result.intent == "configure":
                configure_details = handle_configure_intent(route_result.description)
                result = execute_command(configure_details)
                return result.response
            elif route_result.intent == "monitor":
                monitor_details = handle_monitor_intent(route_result.description)
                result = execute_command(monitor_details)
                return result.response
            else:
                logger.warning("Request type not supported")
                return f"request gagal"
        else:
            return f"The target IP address is not found in the Device Management system"
    else:
        return f"No information available for the target IP <ip_address>. Please verify the IP address and try again"


# --------------------------------------------------------------
# Step 4: Define Function Calling OpenAI
# --------------------------------------------------------------
def execute_command(configuration_details):
    """
    Executes a network configuration command via OpenAI API and SSH.
    """
    # Step 1: Generate completion with OpenAI API
    tools = [
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
                        "command": {
                            "type": "string",
                            "description": "Configuration command With added command to check configuration results",
                        },
                    },
                    "required": [
                        "ip_address",
                        "command",
                    ],
                    "additionalProperties": False,
                },
                "strict": True,
            },
        },
        {
            "type": "function",
            "function": {
                "name": "send_monitoring_command",
                "description": "Send monitoring command to a device using SSH",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string"},
                        "command": {"type": "string"},
                    },
                    "required": ["ip_address", "command"],
                    "additionalProperties": False,
                },
                "strict": True,
            },
        },
    ]

    system_prompt = """
    You are a network automation expert. Validate command with spesific vendor syntax.
    - Use send_configuration for configuration changes
    - Use send_monitoring_command for read-only monitoring commands
    """
    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": f"Configuration detail: {str(configuration_details.model_dump())}",
        },
    ]

    completion = client.chat.completions.create(
        model=model,
        messages=messages,
        tools=tools,
    )

    # Step 2: Extract function calls
    tool_calls = completion.choices[0].message.tool_calls

    if not tool_calls:  # <-- Tambahkan ini
        logger.error("No tool calls found in OpenAI response")
        return (
            f"There is an issue with the system at the moment. Please try again later."
        )

    # Step 3: Execute the corresponding function
    def call_function(name, args):
        if name == "send_configuration":
            return NetworkManager.send_configuration(**args)
        elif name == "send_monitoring_command":
            return NetworkManager.send_monitoring_command(**args)
        raise ValueError(f"Unknown function: {name}")

    for tool_call in tool_calls:
        name = tool_call.function.name
        args = json.loads(tool_call.function.arguments)
        messages.append(completion.choices[0].message)
        result = call_function(name, args)
        messages.append(
            {
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(result),
            }
        )

    # Step 4: Process the response
    completion_2 = client.beta.chat.completions.parse(
        model=model,
        messages=messages,
        tools=tools,
        response_format=NetworkResponse,
    )
    # logger.info(f"Final OpenAI Response: {completion_2}")

    if completion_2 is None or not completion_2.choices:
        logger.error("OpenAI API response is None or empty")
        return (
            f"There is an issue with the system at the moment. Please try again later."
        )

    return completion_2.choices[0].message.parsed
