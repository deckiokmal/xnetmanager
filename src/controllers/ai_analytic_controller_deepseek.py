from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from src.utils.analyticUtils_deepseek import (
    AIAnalyticsUtils,
    RecommendationDeduplicator,
)
from src.utils.backupUtils import BackupUtils
from src.models.app_models import DeviceManager, AIRecommendations
from src import db
from src.utils.network_topology_visualization import NetworkTopologyVisualizer
import json
from flask_login import current_user
import uuid
from src.utils.config_manager_utils import ConfigurationManagerUtils
import logging
from src.models.app_models import BackupData

ai_bp = Blueprint("ai", __name__, url_prefix="/ai")


@ai_bp.route("/analyze/<device_id>")
def analyze_device(device_id):
    deduplicator = RecommendationDeduplicator()
    session = db.session

    try:
        device = session.get(DeviceManager, device_id)
        if not device:
            flash("Device tidak ditemukan", "danger")
            return redirect(url_for("dm.index"))

        # Cek status device
        utils = ConfigurationManagerUtils(ip_address=device.ip_address)
        if json.loads(utils.check_device_status()).get("status") != "success":
            flash("Device offline", "warning")
            return redirect(url_for("dm.index"))

        # Proses analisis
        config_data = AIAnalyticsUtils.get_configuration_data(device)
        recommendations = AIAnalyticsUtils.generate_recommendations(config_data)

        valid_recommendations = []
        duplicate_count = 0

        for rec in recommendations:
            recommendation_data = {
                "device_id": device_id,
                "title": rec["title"],
                "description": rec.get("description", ""),
                "command": rec["command"],
                "risk_level": rec["risk_level"],
                "impact_area": rec.get("impact_area", "security"),
            }

            dedup_result = deduplicator.handle_recommendation(recommendation_data)

            if dedup_result.get("status") == "duplicate":
                duplicate_count += 1
            elif "new_id" in dedup_result:
                valid_recommendations.append(
                    {
                        "id": dedup_result["new_id"],
                        **recommendation_data,
                        "status": "generated",
                    }
                )

        # Hapus semua duplikat yang terdeteksi
        session.query(AIRecommendations).filter(
            AIRecommendations.is_duplicate == True
        ).delete()
        session.commit()

        # Tampilkan hasil
        recommendations_data = (
            session.query(AIRecommendations)
            .filter_by(device_id=device_id, is_duplicate=False)
            .order_by(AIRecommendations.risk_level.desc())
            .all()
        )

        flash(f"Berhasil memproses {len(valid_recommendations)} rekomendasi", "success")
        if duplicate_count > 0:
            flash(f"Ditemukan {duplicate_count} duplikat", "info")

        return render_template(
            "/analytic_templates/analytics_deepseek.html",
            device=device,
            live_config=config_data["live"],
            recommendations=recommendations_data,
            status_device="success",
        )

    except Exception as e:
        session.rollback()
        logging.error(f"Error analisis: {str(e)}")
        flash("Proses analisis gagal", "danger")
        return redirect(url_for("dm.index"))


@ai_bp.route("/visualize_topology")
def visualize_topology():
    try:
        visualizer = NetworkTopologyVisualizer()

        # Contoh penambahan perangkat dan koneksi
        visualizer.add_device("1", "Router A")
        visualizer.add_device("2", "Switch B")
        visualizer.add_connection("1", "2")

        visualizer.visualize()
        return jsonify({"status": "success"}), 200

    except Exception as e:
        logging.error(f"Error visualizing topology: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@ai_bp.route("/apply", methods=["POST"])
def apply_recommendation():
    data = request.get_json()
    try:
        recommendation = AIRecommendations.query.get_or_404(data["rec_id"])
        device = DeviceManager.query.get(recommendation.device_id)

        # Koneksi ke device
        utils = ConfigurationManagerUtils(
            ip_address=device.ip_address,
            username=device.username,
            password=device.password,
            ssh=device.ssh,
        )

        # Eksekusi perintah
        commands = recommendation.command
        utils.configure_device(commands)

        # Update status
        recommendation.status = "applied"
        db.session.commit()

        # Cek apakah backup sudah ada
        backup_exists = BackupUtils.check_backup_exists(device_id=device.id)

        # Buat backup setelah perubahan
        # Ambil live config menggunakan command sesuai device type
        command_map = {
            "cisco_ios": "show running-config",
            "juniper": "show configuration | display set",
            "huawei": "display current-configuration",
            "mikrotik": "export compact",
            "fortinet": "show full-configuration",
        }
        vendor = device.vendor.lower()
        command = command_map.get(vendor, command_map["cisco_ios"])

        backup_type = "differential" if backup_exists else "full"
        # Create a new backup for this device using the static method
        new_backup = BackupData.create_backup(
            backup_name=f"post-ai-{recommendation.title}",
            description=f"After applying AI recommendation {recommendation.description}",
            user_id=current_user.id,
            device_id=device.id,
            backup_type=backup_type,
            retention_days=7,
            command=command,
        )

        return (
            jsonify(
                {
                    "success": True,
                    "message": "Backup created successfully.",
                    "backup_id": new_backup.id,
                    "backup_path": new_backup.backup_path,
                }
            ),
            201,
        )

    except Exception as e:
        recommendation.status = f"failed: {str(e)}"
        logging.error(f"Error applying recommendation: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500
