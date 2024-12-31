from flask import (
    Blueprint,
    jsonify,
    request,
    current_app,
    redirect,
    url_for,
    flash,
)
from src import db
from flask_login import login_required, current_user, logout_user
from src.models.app_models import (
    DeviceManager,
    AIRecommendations,
)
from src.utils.analytics_utils import (
    fetch_device_configuration,
    parse_and_validate_configuration,
    analyze_configuration_with_ai,
    save_analytics_result,
    apply_configuration,
    monitor_device_status,
    generate_report,
)
from datetime import datetime
import uuid

# Blueprint untuk analytics
analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/api/start_analysis", methods=["POST"])
def start_analysis():
    """Start analysis for a device configuration."""
    try:
        # Validasi input
        device_id = request.json.get("device_id")
        if not device_id or not uuid.UUID(device_id, version=4):
            return jsonify({"error": "Invalid device_id format"}), 400

        # Fetch perangkat dari database
        device = DeviceManager.query.get(device_id)
        if not device:
            return jsonify({"error": "Device not found"}), 404

        # Fetch konfigurasi perangkat
        config_data = fetch_device_configuration(device_id)

        # Parsing dan validasi konfigurasi
        parsed_config = parse_and_validate_configuration(config_data)

        # Analisis konfigurasi dengan AI
        recommendation = analyze_configuration_with_ai(config_data)

        # Simpan rekomendasi ke database
        save_analytics_result(device_id, recommendation)

        return jsonify({
            "message": "Analysis completed.",
            "recommendation": recommendation,
            "parsed_config": parsed_config
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error in start_analysis: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/get_recommendations", methods=["GET"])
def get_recommendations():
    """Get recommendations for a specific device."""
    try:
        # Validasi input
        device_id = request.args.get("device_id")
        if not device_id or not uuid.UUID(device_id, version=4):
            return jsonify({"error": "Invalid device_id format"}), 400

        # Fetch perangkat dan rekomendasi terkait
        device = DeviceManager.query.get(device_id)
        if not device:
            return jsonify({"error": "Device not found"}), 404

        recommendations = device.recommendations.filter_by(is_applied=False).all()

        return jsonify([
            {
                "id": r.id,
                "recommendation": r.recommendation_text,
                "created_at": r.created_at
            } for r in recommendations
        ]), 200
    except Exception as e:
        current_app.logger.error(f"Error in get_recommendations: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/apply_recommendation", methods=["POST"])
def apply_recommendation():
    """Apply a specific recommendation to a device."""
    try:
        # Validasi input
        recommendation_id = request.json.get("recommendation_id")
        if not recommendation_id or not uuid.UUID(recommendation_id, version=4):
            return jsonify({"error": "Invalid recommendation_id format"}), 400

        # Fetch rekomendasi dari database
        recommendation = AIRecommendations.query.get(recommendation_id)
        if not recommendation:
            return jsonify({"error": "Recommendation not found"}), 404

        # Fetch perangkat terkait
        device = recommendation.device
        if not device:
            return jsonify({"error": "Device not found"}), 404

        # Terapkan konfigurasi ke perangkat
        output = apply_configuration(
            device.ip_address,
            device.username,
            device.password,
            recommendation.recommendation_text
        )

        # Perbarui status rekomendasi
        recommendation.is_applied = True
        recommendation.applied_at = datetime.utcnow()
        db.session.commit()

        return jsonify({"message": "Configuration applied successfully.", "output": output}), 200
    except Exception as e:
        current_app.logger.error(f"Error in apply_recommendation: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/device_status", methods=["GET"])
def device_status():
    """Check the status of a specific device."""
    try:
        # Validasi input
        device_id = request.args.get("device_id")
        if not device_id or not uuid.UUID(device_id, version=4):
            return jsonify({"error": "Invalid device_id format"}), 400

        # Fetch perangkat dari database
        device = DeviceManager.query.get(device_id)
        if not device:
            return jsonify({"error": "Device not found"}), 404

        # Pantau status perangkat
        status = monitor_device_status(device.ip_address)

        return jsonify({"device_id": device_id, "status": status}), 200
    except Exception as e:
        current_app.logger.error(f"Error in device_status: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/report", methods=["GET"])
def get_report():
    """Generate a report of all analytics."""
    try:
        # Buat laporan analitik
        reports = generate_report()
        return jsonify(reports), 200
    except Exception as e:
        current_app.logger.error(f"Error in get_report: {e}")
        return jsonify({"error": str(e)}), 500
