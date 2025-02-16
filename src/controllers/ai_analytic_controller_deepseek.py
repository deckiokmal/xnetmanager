from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from src.utils.analyticUtils_deepseek import AIAnalyticsUtils
from src.utils.backupUtils import BackupUtils
from src.models.app_models import DeviceManager, AIRecommendations
import paramiko
from src import db
import json
from flask_login import current_user
import uuid
from src.utils.config_manager_utils import ConfigurationManagerUtils

ai_bp = Blueprint("ai", __name__, url_prefix="/ai")


@ai_bp.route("/analyze/<device_id>")
def analyze_device(device_id):
    try:
        device = DeviceManager.query.get_or_404(device_id)

        # check status perangkat sebelum analyze
        utils = ConfigurationManagerUtils(ip_address=device.ip_address)
        status_json = utils.check_device_status()
        status_dict = json.loads(status_json)
        status_device = status_dict["status"]

        if status_device == "success":

            # Dapatkan data konfigurasi
            config_data = AIAnalyticsUtils.get_configuration_data(device)

            # Dapatkan rekomendasi AI
            recommendations = AIAnalyticsUtils.generate_recommendations(config_data)

            # Simpan ke database
            for recommendation_data in recommendations:
                new_rec = AIRecommendations(
                    id=str(uuid.uuid4()),
                    device_id=device_id,
                    title=recommendation_data["title"],
                    description=recommendation_data.get("description", ""),
                    commands=recommendation_data["commands"],
                    risk_level=recommendation_data["risk_level"],
                    impact_area=recommendation_data.get("impact_area", "security"),
                    priority=recommendation_data.get("priority", 1),
                    status="generated",
                )
                db.session.add(new_rec)
            db.session.commit()

            recommendations_data = AIRecommendations.query.filter_by(
                device_id=device_id
            ).all()

            return render_template(
                "/analytic_templates/analytics_deepseek.html",
                device=device,
                live_config=config_data["live"],
                recommendations=recommendations_data,
                status_device=status_device,
            )
        else:
            flash("Device Offline!", "warning")
            return redirect(url_for("dm.index"))

    except Exception as e:
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
        commands = recommendation.commands
        for cmd in commands:
            utils.configure_device(cmd)

        # Update status
        recommendation.status = "applied"
        db.session.commit()

        # Buat backup setelah perubahan
        BackupUtils.perform_backup(
            backup_type="incremental",
            device=device,
            user_id=current_user.id,
            backup_name=f"post-ai-{recommendation.id}",
            description=f"After applying AI recommendation {recommendation.title}",
            command="auto",
            version=1.0,
        )

        return jsonify({"status": "success"})

    except Exception as e:
        recommendation.status = f"failed: {str(e)}"
        db.session.commit()
        return jsonify({"status": "error", "message": str(e)}), 500
