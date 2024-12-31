import os
import paramiko
import openai
from datetime import datetime
from flask import jsonify
from src import db
from src.models.app_models import AIRecommendations, DeviceManager, BackupData


# 1. Tarik Konfigurasi (Backup atau Perangkat Langsung)
def fetch_device_configuration(device_id):
    """Fetch configuration from the latest backup of a device."""
    backup = (
        BackupData.query.filter_by(device_id=device_id)
        .order_by(BackupData.created_at.desc())
        .first()
    )
    if not backup:
        raise ValueError("No backup found for the specified device.")
    with open(backup.backup_path, "r") as file:
        config_data = file.read()
    return config_data


def fetch_live_configuration(device_ip, username, password):
    """Fetch live configuration from the device using SSH."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(device_ip, username=username, password=password)
    stdin, stdout, stderr = ssh.exec_command("show running-config")
    config_data = stdout.read().decode()
    ssh.close()
    return config_data


# 2. Parsing dan Validasi
def parse_and_validate_configuration(config_data):
    """Parse and validate configuration data."""
    if "interface" not in config_data:
        raise ValueError("Invalid configuration: Missing interface data.")
    parsed_data = {"interfaces": []}
    for line in config_data.split("\n"):
        if line.startswith("interface"):
            parsed_data["interfaces"].append(line.strip())
    return parsed_data


# 3. Analitik AI
def analyze_configuration_with_ai(config_data):
    """Send configuration data to OpenAI API for analysis and recommendations."""
    response = openai.Completion.create(
        model="text-davinci-003",
        prompt=f"Analyze this configuration and provide optimization suggestions:\n{config_data}",
        max_tokens=500,
    )
    return response.choices[0].text.strip()


# 4. Simpan Rekomendasi
def save_analytics_result(device_id, recommendation_text):
    """Save AI recommendation to the database."""
    analytics_result = AIRecommendations(
        device_id=device_id,
        recommendation_text=recommendation_text,
        created_at=datetime.utcnow(),
    )
    db.session.add(analytics_result)
    db.session.commit()
    return analytics_result


# 5. Terapkan Rekomendasi
def apply_configuration(device_ip, username, password, command):
    """Apply recommended configuration to the device."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(device_ip, username=username, password=password)
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode()
    ssh.close()
    return output


# 6. Monitoring Perangkat
def monitor_device_status(device_ip):
    """Monitor device status with ping."""
    response = os.system(f"ping -c 1 {device_ip}")
    return "Online" if response == 0 else "Offline"


# 7. Laporkan Aktivitas
def generate_report():
    """Generate a report of analytics and recommendations."""
    reports = AIRecommendations.query.all()
    return [
        {
            "id": r.id,
            "device_id": r.device_id,
            "recommendation": r.recommendation_text,
            "is_applied": r.is_applied,
            "created_at": r.created_at,
        }
        for r in reports
    ]
