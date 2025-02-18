import openai
import json
import logging
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from sqlalchemy.orm import Session
from sqlalchemy import select, insert, update, delete
from src.models.app_models import AIRecommendations
from .backupUtils import BackupUtils
from src import db


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
            vendor = device.vendor.lower()
            command = command_map.get(
                vendor, command_map["cisco_ios"]
            )  # Default lebih aman

            live_config = BackupUtils.get_device_config(device, command)
            latest_backup = BackupUtils.determine_previous_backup(device, "full")

            backup_config = (
                BackupUtils.read_backup_file(latest_backup.backup_path)
                if latest_backup
                else "No backup available"
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
        self.similarity_threshold = 0.85
        self.embedding_model = "text-embedding-3-small"
        self.client = openai  # Inisialisasi client OpenAI SDK terbaru

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
            response = self.client.Embedding.create(
                input=[text], model=self.embedding_model
            )
            return response["data"][0]["embedding"]
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
