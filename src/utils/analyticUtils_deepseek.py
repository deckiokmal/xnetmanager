import openai
import json
import logging
from .backupUtils import BackupUtils
import uuid


class AIAnalyticsUtils:
    @staticmethod
    def get_configuration_data(device):
        """Mengambil data konfigurasi live dan backup"""
        try:
            # Ambil live config menggunakan command sesuai device type
            command_map = {
                "cisco_ios": "show running-config",
                "juniper": "show configuration | display set",
                "huawei": "display current-configuration",
                "mikrotik": "export compact",
                "fortinet": "show full-configuration",
            }
            command = command_map.get(device.vendor.lower(), "show running-config")

            live_config = BackupUtils.get_device_config(device, command)

            # Ambil backup terakhir
            latest_backup = BackupUtils.determine_previous_backup(device, "full")
            backup_config = (
                BackupUtils.read_backup_file(latest_backup.backup_path)
                if latest_backup
                else ""
            )

            return {
                "live": live_config,
                "backup": backup_config,
                "combined": f"LIVE CONFIGURATION:\n{live_config}\n\nBACKUP CONFIGURATION:\n{backup_config}",
            }

        except Exception as e:
            logging.error(f"Error getting configuration data: {str(e)}")
            raise

    @staticmethod
    def generate_recommendations(config_data):
        """Generate AI recommendations menggunakan OpenAI API"""
        try:
            system_prompt = """Anda adalah network engineer expert dengan spesialisasi security dan high availability. 
            Berikan rekomendasi untuk meningkatkan konfigurasi dengan format:
            {
                "recommendations": [
                    {
                        "title": "Judul Rekomendasi",
                        "description": "Penjelasan teknis",
                        "commands": ["list","commands"],
                        "risk_level": "low/medium/high",
                        "impact_area": "security/availability"
                    }
                ]
            }"""

            response = openai.ChatCompletion.create(
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
            if not isinstance(response_data.get("recommendations", []), list):
                raise ValueError("Invalid recommendations format")

            # Validasi setiap rekomendasi
            valid_recommendations = []
            for rec in response_data["recommendations"]:
                if all(key in rec for key in ["title", "commands", "risk_level"]):
                    valid_recommendations.append(rec)

            return valid_recommendations

        except (json.JSONDecodeError, ValueError) as e:
            logging.error(f"Invalid AI Response: {str(e)}")
            return []
