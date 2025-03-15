import re
import json
import logging
import requests
import numpy as np
from openai import OpenAI
from flask import current_app, jsonify
from typing import Optional, Literal
from pydantic import BaseModel, Field
from sklearn.metrics.pairwise import cosine_similarity
from src import db
from src.models.app_models import DeviceManager, AIRecommendations
from sqlalchemy.orm import Session
from sqlalchemy import select, delete
from .backup_utilities import BackupUtils
from .network_configurator_utilities import ConfigurationManagerUtils

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ----------------------------------------------------------
# Talita API: Chatbot with RAG Knowledge Based
# ----------------------------------------------------------
def talita_llm(user_input, user_id):
    """
    Mengirimkan permintaan POST ke API TALITA untuk mendapatkan jawaban dari chat completion.

    Parameters:
    user_input (str): Pertanyaan yang ingin diajukan kepada TALITA.
    user_id (str): ID pengguna yang mengajukan pertanyaan.

    Returns:
    dict: Hasil dalam format JSON, termasuk 'success' sebagai boolean dan 'message' sebagai string.
    """
    # current_app.logger.info(f"Permintaan TALITA dimulai.")

    talita_url = current_app.config["TALITA_URL"]
    talita_api_key = current_app.config["TALITA_API_KEY"]

    # Header yang ingin ditambahkan
    headers = {
        "Content-Type": "application/json",
        "apikey": talita_api_key,
    }

    # Data yang akan dikirim dalam body request, dalam format JSON
    data = {
        "question": user_input,
        "user_id": str(user_id),
    }

    try:
        # Mengirimkan permintaan POST
        response = requests.post(talita_url, headers=headers, json=data, verify=False)
        # current_app.logger.info(f"hasil raw jawaban TALITA: {response}")

        # Mengecek status kode dari respon
        if response.status_code == 200:
            answer = response.json().get("TALITA", "No valid response received.")
            # current_app.logger.info(f"Jawaban dari TALITA yang diparsing: {answer}")
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
# OpenAI API: Agentic Workflow for Intent Based Networking
# ----------------------------------------------------------
class AgenticNetworkIntent:
    def __init__(self, user_input: str):
        self.client = OpenAI()
        self.model = "gpt-4o"
        self.user_input = user_input

    # --------------------------------------------------------------
    # Step 1: Define the data models for routing and responses
    # --------------------------------------------------------------
    class NetworkingIntentType(BaseModel):
        """Router LLM call: Determine the type of networking intent"""

        intent: Literal["configure", "monitor", "other"] = Field(
            description="Type of networking intent being made"
        )
        confidence_score: float = Field(description="Confidence score between 0 and 1")
        description: str = Field(
            description="Cleaned description of the intent based networking with device target ip address and vendor."
        )

    class ConfigurationDetails(BaseModel):
        """Details for configuring a network device"""

        ip_address: str = Field(
            description="IP address of the target device to configure"
        )
        vendor: str = Field(description="Vendor of the network device")
        command: str = Field(
            description="Generate valid network configurations for the specified vendor (e,g.. mikrotik, fortinet, cisco) and additional verification syntax to display the results of the applied configuration. Make sure 'commands' without additional text formatting, without explanation and without additional escape characters."
        )

    class MonitoringDetails(BaseModel):
        """Details for monitoring a network device"""

        ip_address: str = Field(
            description="IP address of the target device to monitor"
        )
        vendor: str = Field(description="Vendor of the network device")
        command: str = Field(
            description="Commands to monitor the device (e,g.. mikrotik, fortinet, cisco). If any commands are indicated to cause continuous output to be executed (e,g.. ping,monitor traffic), they should always be set to an interval once or four count to prevent continuous output, ensuring controlled execution and optimal system performance."
        )

    class NetworkResponse(BaseModel):
        """Response from network operations"""

        response: str = Field(description="Result of the operation")
        success: bool = Field(
            description="Indicates whether the operation was successful. Always verify the configuration by running the appropriate commands and present the results in good text formatting to the user for confirmation. If there are any missing parameters that cause errors in the configuration, ask the user to provide the missing parameters and display the configuration syntax."
        )

    # --------------------------------------------------------------
    # Step 2: Define Function logic for application
    # --------------------------------------------------------------
    def get_credentials(self, ip_address: str):
        """
        Mengambil kredensial jaringan dari database berdasarkan ip_address.
        Jika tidak ditemukan, gunakan nilai default dari environment variable.
        """
        credential = DeviceManager.query.filter_by(ip_address=ip_address).first()

        if credential:
            return credential.username, credential.password, credential.ssh
        else:
            return False

    def send_configuration(self, ip_address: str, command: str) -> dict:
        """Send configuration commands to network device"""
        username, password, ssh = self.get_credentials(ip_address)
        config_manager = ConfigurationManagerUtils(ip_address, username, password, ssh)
        result = config_manager.configure_device(command)
        return {"success": "success" in result.lower(), "response": result}

    # --------------------------------------------------------------
    # Step 3: Define the routing and processing functions
    # --------------------------------------------------------------
    def route_network_intent(self, user_input: str) -> NetworkingIntentType:
        """Router LLM call to determine the type of user intent request"""
        # logger.info("Routing user intent request")

        completion = self.client.beta.chat.completions.parse(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": "Determine if this is a request to 'configure', 'monitor' network devices. If user mention about talita or ask a queston about some knowledge without specify target ip this mean request to 'other'.",
                },
                {"role": "user", "content": user_input},
            ],
            response_format=self.NetworkingIntentType,
        )

        result = completion.choices[0].message.parsed
        # logger.info(
        #     f"Request routed as: {result.intent} with confidence: {result.confidence_score}"
        # )
        return result

    def handle_configure_intent(self, description: str) -> ConfigurationDetails:
        """Process a configure request and parsed command"""
        # logger.info("Processing configure request")

        # Get configure details
        completion = self.client.beta.chat.completions.parse(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": "Extract details for creating a new configuration intent. Configuration and checking of configuration results in valid syntax without additional text formatting and without additional escape caracters.",
                },
                {
                    "role": "user",
                    "content": description,
                },
            ],
            response_format=self.ConfigurationDetails,
        )

        details = completion.choices[0].message.parsed

        # logger.info(f"New configure: {details.model_dump_json(indent=2)}")

        # Generate configuration details
        return details

    def handle_monitor_intent(self, description: str) -> MonitoringDetails:
        """Process a monitor request and parsed command"""
        # logger.info("Processing monitor request")

        # Get configure details
        completion = self.client.beta.chat.completions.parse(
            model=self.model,
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
            response_format=self.MonitoringDetails,
        )

        details = completion.choices[0].message.parsed

        # logger.info(f"New configure: {details.model_dump_json(indent=2)}")

        # Generate configuration details
        return details

    def process_intent_request(self) -> Optional[NetworkResponse]:
        """Main function implementing the routing workflow"""
        # logger.info("Processing intent request")

        # Route the request
        route_result = self.route_network_intent(self.user_input)

        # Check confidence threshold
        if route_result.confidence_score < 0.7:
            # logger.warning(f"Low confidence score: {route_result.confidence_score}")
            return f"Please provide clear input."

        # Route to appropriate handler
        if route_result.intent == "other":
            # current_app.logger.info(f"other talita di trigger")
            return f"other"

        # Periksa IP Address ke database sebelum LLM Call
        pattern = r"target\s+ip\s+(\d+\.\d+\.\d+\.\d+)"
        match = re.search(pattern, str(self.user_input), re.IGNORECASE)
        if match:
            ip_address = match.group(1)
            credentials = self.get_credentials(ip_address)
            if credentials:

                # Route to appropriate handler
                if route_result.intent == "configure":
                    configure_details = self.handle_configure_intent(
                        route_result.description
                    )
                    # current_app.logger.info(
                    #     f"hasil parsing configure: {configure_details}"
                    # )
                    result = self.execute_command(configure_details)
                    return result.response
                elif route_result.intent == "monitor":
                    monitor_details = self.handle_monitor_intent(
                        route_result.description
                    )
                    result = self.execute_command(monitor_details)
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
    def execute_command(self, configuration_details):
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
                                "description": "Valid network configuration syntax for the specified vendor and provide the corresponding verification commands to confirm that the configuration has been applied correctly",
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
        ]

        system_prompt = """
        You are a highly skilled and expert network engineer. Your job is to create, validate and optimize network configuration syntax based on 'commands' with specific 'vendors' in Detail configuration. Make sure 'commands' without additional text formatting, without explanation and without additional escape characters. Then add configuration result checks.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"Configuration detail: {str(configuration_details.model_dump())}",
            },
        ]

        completion = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools,
            tool_choice={
                "type": "function",
                "function": {"name": "send_configuration"},
            },
        )

        # Step 2: Extract function calls
        tool_calls = completion.choices[0].message.tool_calls

        # current_app.logger.info(f"tool calls 1 result: {tool_calls}")

        if not tool_calls:  # <-- Tambahkan ini
            # logger.error("No tool calls found in OpenAI response")
            return f"There is an issue with the system at the moment. Please try again later."

        # Step 3: Execute the corresponding function
        def call_function(name, args):
            if name == "send_configuration":
                return self.send_configuration(**args)
            # elif name == "send_monitoring_command":
            #     return self.send_monitoring_command(**args)
            raise ValueError(f"Unknown function: {name}")

        for tool_call in tool_calls:
            name = tool_call.function.name
            args = json.loads(tool_call.function.arguments)
            # Perbaiki formatting command agar tidak ada escape karakter
            # args["command"] = args["command"].encode().decode("unicode_escape")

            # current_app.logger.info(f"hasil parsing escape karakter: {args}")
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
        completion_2 = self.client.beta.chat.completions.parse(
            model=self.model,
            messages=messages,
            tools=tools,
            response_format=self.NetworkResponse,
        )
        # logger.info(f"Final OpenAI Response: {completion_2}")

        if completion_2 is None or not completion_2.choices:
            # logger.error("OpenAI API response is None or empty")
            return f"There is an issue with the system at the moment. Please try again later."

        return completion_2.choices[0].message.parsed


# --------------------------------------------------------------
# AI Recommendation Configuration Utility
# --------------------------------------------------------------
client = OpenAI()
model = "gpt-4o"


class AIAnalyticsUtils:
    @staticmethod
    def get_configuration_data(device):
        """Mengambil data konfigurasi live dan backup"""
        try:
            # Ambil live config menggunakan command sesuai device type
            command_map = {
                "cisco_ios": "show running-config",
                "cisco": "show running-config",
                "juniper": "show configuration | display set",
                "huawei": "display current-configuration",
                "mikrotik": "export compact",
                "fortinet": "show full-configuration",
            }
            vendor = device.vendor.lower()
            command = command_map.get(
                vendor, command_map["mikrotik"]
            )  # Default lebih aman

            live_config = BackupUtils.get_device_config(device, command)
            if live_config["status"] == "success":
                live_data = live_config["message"]
            else:
                live_data = "No data available"

            # lanjutkan dengan pengecekan backup data
            latest_backup = BackupUtils.determine_previous_backup(device, "full")

            backup_config = (
                BackupUtils.read_backup_file(latest_backup.backup_path)
                if latest_backup
                else "No data available"
            )
            backup_data = backup_config

            return {
                "live": live_data,
                "backup": backup_data,
                "combined": f"LIVE CONFIGURATION:\n{live_config}\n\nBACKUP CONFIGURATION:\n{backup_data}",
            }

        except Exception as e:
            logging.error(f"Error getting configuration data: {str(e)}")
            raise

    @staticmethod
    def generate_recommendations(config_data):
        """Generate AI recommendations menggunakan OpenAI API"""
        try:
            system_prompt = """Anda adalah network engineer expert dan security analis expert. Berikan rekomendasi dengan format:
            {
                "recommendations": [
                    {
                        "title": "Judul",
                        "description": "Penjelasan teknis",
                        "commands": ["list","commands"],
                        "risk_level": "low/medium/high",
                        "impact_area": "security/availability"
                    }
                ]
            }"""

            response = client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": config_data["combined"]},
                ],
                temperature=0.3,
                max_tokens=1000,
            )

            return AIAnalyticsUtils._parse_ai_response(
                response.choices[0].message.content
            )

        except Exception as e:
            logging.error(f"AI API Error: {str(e)}")
            return []

    @staticmethod
    def _parse_ai_response(response_text):
        """Parse dan validasi response dari OpenAI"""
        try:
            response_data = json.loads(response_text)
            recommendations = response_data.get("recommendations", [])

            if not isinstance(recommendations, list):
                raise ValueError("Invalid recommendations format")

            valid_recommendations = []
            valid_risk_levels = {"low", "medium", "high"}
            valid_impact_areas = {"security", "availability"}

            for rec in recommendations:
                try:
                    # Validasi field wajib
                    required_fields = [
                        "title",
                        "commands",
                        "risk_level",
                        "description",
                        "impact_area",
                    ]
                    if not all(field in rec for field in required_fields):
                        continue

                    # Validasi nilai enum
                    if (
                        rec["risk_level"].lower() not in valid_risk_levels
                        or rec["impact_area"].lower() not in valid_impact_areas
                    ):
                        continue

                    # Konversi commands list ke string
                    rec["command"] = "\n".join(rec.pop("commands"))
                    valid_recommendations.append(rec)

                except (KeyError, TypeError) as e:
                    logging.warning(f"Invalid recommendation structure: {str(e)}")
                    continue

            return valid_recommendations

        except (json.JSONDecodeError, ValueError) as e:
            logging.error(f"Invalid AI Response: {str(e)}")
            return []


class RecommendationDeduplicator:
    def __init__(self):
        self.similarity_threshold = 0.50
        self.embedding_model = "text-embedding-3-small"
        self.client = OpenAI()  # Inisialisasi client OpenAI SDK terbaru

    def _preprocess_text(self, text: str) -> str:
        """Preprocessing teks untuk embedding"""
        # Case folding dan normalisasi whitespace
        text = text.lower().strip()

        # Hapus karakter khusus dan multiple whitespace
        text = " ".join(text.split())
        text = "".join([c if c.isalnum() or c.isspace() else " " for c in text])

        return text

    def _generate_embedding(self, text: str) -> list:
        """Generate text embedding menggunakan OpenAI API versi terbaru"""
        try:
            text = self._preprocess_text(text)
            response = self.client.embeddings.create(
                input=[text], model=self.embedding_model
            )
            return response.data[0].embedding
        except Exception as e:
            logging.error(f"Embedding generation failed: {str(e)}")
            raise

    def _get_existing_embeddings(self, session: Session, device_id: int) -> list:
        """Retrieve existing embeddings dengan ID"""
        stmt = select(AIRecommendations.id, AIRecommendations.embedding).where(
            AIRecommendations.device_id == device_id,
            AIRecommendations.is_duplicate == False,
        )
        return session.execute(stmt).fetchall()

    def _get_combined_text(self, config_data: dict) -> str:
        """Gabungkan data rekomendasi menjadi teks untuk embedding"""
        return (
            f"{config_data['title']} "
            f"{config_data['risk_level']} "
            f"{config_data['impact_area']} "
            f"{config_data['command']}"
        )

    def handle_recommendation(self, config_data: dict) -> dict:
        """Main function dengan optimasi deduplikasi dan penghapusan"""
        session = Session(db.engine)
        try:
            combined_text = self._get_combined_text(config_data)
            new_embedding = self._generate_embedding(combined_text)

            # Ambil data existing dengan ID
            existing_records = self._get_existing_embeddings(
                session, config_data["device_id"]
            )
            existing_ids = [rec[0] for rec in existing_records]
            existing_embeddings = [np.array(rec[1]) for rec in existing_records]

            duplicate_ids = []
            if existing_embeddings:
                # Hitung similarity dan temukan duplikat
                similarities = cosine_similarity([new_embedding], existing_embeddings)[
                    0
                ]
                duplicate_indices = np.where(similarities >= self.similarity_threshold)[
                    0
                ]
                duplicate_ids = [existing_ids[i] for i in duplicate_indices]

                # Hapus duplikat existing
                if duplicate_ids:
                    delete_stmt = delete(AIRecommendations).where(
                        AIRecommendations.id.in_(duplicate_ids)
                    )  # **Perbaikan: Menutup kurung di sini**
                    session.execute(delete_stmt)
                    session.commit()

            # Cek kembali apakah masih ada duplikat setelah penghapusan
            existing_after_deletion = self._get_existing_embeddings(
                session, config_data["device_id"]
            )
            if existing_after_deletion:
                new_similarities = cosine_similarity(
                    [new_embedding], [np.array(e[1]) for e in existing_after_deletion]
                )[0]
                if np.max(new_similarities) >= self.similarity_threshold:
                    return {"status": "duplicate"}

            # Tambahkan rekomendasi baru
            new_rec = AIRecommendations(
                device_id=config_data["device_id"],
                title=config_data["title"],
                description=config_data["description"],
                command=config_data["command"],
                risk_level=config_data["risk_level"],
                impact_area=config_data["impact_area"],
                embedding=new_embedding,
                is_duplicate=False,
            )
            session.add(new_rec)
            session.commit()

            return {"status": "unique", "new_id": new_rec.id}

        except Exception as e:
            session.rollback()
            logging.error(f"Deduplication error: {str(e)}")
            return {"error": str(e)}
        finally:
            session.close()


# --------------------------------------------------------------
# AI Configuration File Management & Templating
# --------------------------------------------------------------
class ConfigurationFileManagement:
    def __init__(self):
        self.client = OpenAI()
        self.model = "gpt-4o"

    def json_parse(self, text_json_data: str):
        pattern = r"```json\s*\n(.*?)\n?```"
        match = re.search(pattern, text_json_data, re.DOTALL)

        if match:
            json_content = match.group(1)
            try:
                parsed_json = json.loads(json_content)
                return parsed_json  # Mengembalikan dictionary dari JSON
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON: {e}")
                return None
        else:
            print("No JSON block found.")
            return None

    def validated_configuration(self, configuration: str, device_vendor: str):
        """
        Validasi konfigurasi berdasarkan script device configuration yang diinput oleh user.
        """

        system_prompt = """
                        you are a very helpful assistant in verifying the device configuration.

                        RESPONSE INSTRUCTIONS
                        ---------------------
                        when responding to me use bahasa indonesia, you must follow the following format:
                        {{
                            "is_valid": <true/false>,
                            "errors": [
                                        {{
                                            "line": <line_number>,
                                            "error_code": <short_error_code>,
                                            "message": <detailed_error_message>
                                        }},
                                    ],
                            "suggestions": <list of suggested fixes if errors exist>
                        }}
                        """
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
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
                    """,
                },
            ],
        )

        # Parsing JSON response
        validation_result = completion.choices[0].message.content

        # Convert str to dictionary
        return validation_result

    def process_validated(self, configuration: str, device_vendor: str):

        response_text = self.validated_configuration(configuration, device_vendor)
        parsing_json = self.json_parse(response_text)

        return parsing_json
