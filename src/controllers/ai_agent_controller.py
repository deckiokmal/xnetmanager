import logging
from werkzeug.exceptions import BadRequest
from flask import (
    Blueprint,
    request,
    jsonify,
    current_app,
    render_template,
    flash,
    redirect,
    url_for,
)
from flask_login import login_required, current_user, logout_user
from .decorators import (
    required_2fa,
)
from src.models.app_models import DeviceManager, AIRecommendations, BackupData
from src.utils.ai_agent_utilities import (
    talita_llm,
    AIAnalyticsUtils,
    RecommendationDeduplicator,
    AgenticNetworkIntent,
)
from src.utils.backup_utilities import BackupUtils
from src.utils.network_configurator_utilities import ConfigurationManagerUtils
from src import db
from src.utils.activity_feed_utils import log_activity


# ----------------------------------------------------------------------------------------
# Buat Blueprint untuk endpoint ai_agent_bp
# ----------------------------------------------------------------------------------------
ai_agent_bp = Blueprint("ai_agent_bp", __name__, url_prefix="/ai")
error_bp = Blueprint("error", __name__)


# ----------------------------------------------------------------------------------------
# Middleware and Endpoint security
# ----------------------------------------------------------------------------------------
@ai_agent_bp.before_app_request
def setup_logging():
    """
    Mengatur level logging untuk aplikasi.
    """
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]
    current_app.logger.addHandler(handler)


@error_bp.app_errorhandler(404)
def page_not_found(error):
    """
    Menangani error 404 dan menampilkan halaman 404.
    """
    current_app.logger.error(f"Error 404: {error}")
    return render_template("main/404.html"), 404


@ai_agent_bp.before_request
def before_request_func():
    """
    Memeriksa apakah pengguna telah terotentikasi sebelum setiap permintaan.
    Jika pengguna harus logout paksa, lakukan logout dan arahkan ke halaman login.
    Jika tidak terotentikasi, kembalikan pesan 'Unauthorized access'.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"
        )
        return render_template("main/404.html"), 404

    # Jika pengguna terotentikasi dan memiliki flag force_logout, lakukan logout
    if current_user.force_logout:
        current_user.force_logout = False  # Reset the flag
        db.session.commit()
        logout_user()
        flash("Your password has been updated. Please log in again.", "info")
        return redirect(url_for("main.login"))


# --------------------------------------------------------------------------------
# Agentic AI Section
# --------------------------------------------------------------------------------
@ai_agent_bp.route("/chatbot", methods=["POST"])
@login_required
@required_2fa
def chatbot():
    # Ambil pesan dari body permintaan
    data = request.get_json()
    user_input = data.get("message", "").strip()

    if not user_input:
        return jsonify({"success": False, "message": "Please enter a question."}), 400

    try:
        chat_intent = AgenticNetworkIntent(user_input).process_intent_request()

        if chat_intent == "other":
            # Ambil ID pengguna saat ini (dari Flask-Login)
            user_id = current_user.id if current_user.is_authenticated else "anonymous"
            response = talita_llm(user_input, user_id)
            return jsonify(response), 200

        return jsonify({"success": True, "message": chat_intent}), 200
    except BadRequest as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "message": "An unexpected error occurred. Please try again later.",
                }
            ),
            500,
        )


# --------------------------------------------------------------------------------
# AI Device Configuration Recommendation Section
# --------------------------------------------------------------------------------
@ai_agent_bp.route("/view/analyze/<device_id>", methods=["GET"])
def analyze_view(device_id):
    device = DeviceManager.query.get_or_404(device_id)
    if not device:
        flash("Device tidak ditemukan", "danger")
        return redirect(url_for("dm.index"))

    # Proses analisis
    config_data = AIAnalyticsUtils.get_configuration_data(device)
    # current_app.logger.info(f"config_data: {config_data}")

    if config_data["live"] is not None:
        show_config_data = config_data["live"]
    elif config_data["backup"] is not None:
        show_config_data = config_data["backup"]
    else:
        flash("No available data, check your device connection.", "warning")
        return redirect(url_for("dm.index"))

    # handle jika data live config dan backup tidak ada
    if show_config_data == "No data available":
        current_app.logger.info("Live config & Backup data not available - AI Agent.")
        flash("No data available, please check your device connection.", "warning")
        return redirect(url_for("dm.index"))

    # Ambil hasil rekomendasi
    recommendations_data = (
        AIRecommendations.query.filter_by(device_id=device_id, is_duplicate=False)
        .order_by(AIRecommendations.risk_level.desc())
        .all()
    )

    return render_template(
        "/analytic_templates/analytics_recommendations.html",
        device=device,
        live_config=show_config_data,
        recommendations=recommendations_data,
        status_device="success",
    )


@ai_agent_bp.route("/analyze/<device_id>")
def analyze_device(device_id):
    deduplicator = RecommendationDeduplicator()
    session = db.session

    try:
        device = DeviceManager.query.get_or_404(device_id)
        if not device:
            flash("Device tidak ditemukan", "danger")
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
        AIRecommendations.query.filter_by(is_duplicate=True).delete()
        session.commit()

        flash(f"Berhasil memproses {len(valid_recommendations)} rekomendasi", "success")

        log_activity(
            current_user.id,
            "User analyze device current configuration with AI successfully.",
            details=f"User {current_user.email} successfully analyze device current configuration with AI for device {device.device_name}",
        )
        if duplicate_count > 0:
            flash(f"Ditemukan {duplicate_count} duplikat", "info")

        return redirect(url_for("ai_agent_bp.analyze_view", device_id=device.id))

    except Exception as e:
        session.rollback()
        logging.error(f"Error analisis: {str(e)}")
        flash("Proses analisis gagal", "danger")
        return redirect(url_for("ai_agent_bp.analyze_view"))


@ai_agent_bp.route("/edit_recommendations/<rec_id>", methods=["PUT"])
def edit_recommendation(rec_id):
    data = request.get_json()
    new_command = data.get("command")

    if not new_command:
        return jsonify({"error": "Command field is required"}), 400

    recommendation = AIRecommendations.query.get(rec_id)
    if not recommendation:
        return jsonify({"error": "Recommendation not found"}), 404

    recommendation.command = new_command
    db.session.commit()

    return jsonify(
        {
            "message": "Recommendation updated successfully",
            "id": str(rec_id),
            "command": new_command,
        }
    )


@ai_agent_bp.route("/apply", methods=["POST"])
def apply_recommendation():
    data = request.get_json()
    try:
        recommendation = AIRecommendations.query.get_or_404(data["rec_id"])
        device = DeviceManager.query.get_or_404(recommendation.device_id)

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
            "cisco": "show running-config",
            "juniper": "show configuration | display set",
            "huawei": "display current-configuration",
            "mikrotik": "export compact",
            "fortinet": "show full-configuration",
        }
        vendor = device.vendor.lower()
        command = command_map.get(vendor, command_map["mikrotik"])

        backup_type = "differential" if backup_exists else "full"
        # Create a new backup for this device using the static method
        BackupData.create_backup(
            backup_name=f"post-ai-{recommendation.title}",
            description=f"After applying AI recommendation {recommendation.title}",
            user_id=current_user.id,
            device_id=device.id,
            backup_type=backup_type,
            retention_days=7,
            command=command,
        )

        log_activity(
            current_user.id,
            "User apply AI recommendation successfully.",
            details=f"User {current_user.email} successfully apply AI recommendation {recommendation.title}",
        )
        return (
            jsonify(
                {
                    "success": True,
                    "message": "Configuration applied successfully!",
                    "status": recommendation.status,
                }
            ),
            201,
        )

    except Exception as e:
        recommendation.status = f"failed: {str(e)}"
        logging.error(f"Error applying recommendation: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500
