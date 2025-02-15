from flask import (
    Blueprint,
    jsonify,
    request,
    current_app,
    redirect,
    url_for,
    flash,
    render_template,
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
    parse_mikrotik_config,
    save_parsing_results,
    analyze_configuration_with_ai,
    save_analytics_results,
    apply_configuration,
    monitor_device_status,
    generate_report,
)
from datetime import datetime
import uuid
from flask_paginate import Pagination, get_page_args
from sqlalchemy.exc import SQLAlchemyError

# Blueprint untuk analytics
analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/analytics", methods=["GET"])
@login_required
def render_analytics_dashboard():
    """
    Render the Analytics Dashboard.
    """
    search_query = request.args.get("search", "").lower()
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )
    if page < 1 or per_page < 1:
        flash("Invalid pagination values.", "danger")

    try:
        # Query untuk DeviceManager
        if current_user.has_role("Admin"):
            devices_query = DeviceManager.query
        else:
            devices_query = DeviceManager.query.filter_by(user_id=current_user.id)

        # Jika ada pencarian, tambahkan filter pencarian
        if search_query:
            devices_query = devices_query.filter(
                DeviceManager.device_name.ilike(f"%{search_query}%")
                | DeviceManager.ip_address.ilike(f"%{search_query}%")
                | DeviceManager.vendor.ilike(f"%{search_query}%")
            )

        # Pagination dan device query
        total_devices = devices_query.count()
        devices = devices_query.limit(per_page).offset(offset).all()
        pagination = Pagination(page=page, per_page=per_page, total=total_devices)

        if total_devices == 0:
            flash("Tidak ada data apapun di halaman ini.", "info")

        return render_template(
            "analytic_templates/index.html",
            devices=devices,
            page=page,
            per_page=per_page,
            pagination=pagination,
            search_query=search_query,
            total_devices=total_devices,
        )
    except SQLAlchemyError as e:
        # Specific database error handling
        current_app.logger.error(
            f"Database error while accessing Push Configuration page by user {current_user.email}: {str(e)}"
        )
        flash(
            "A database error occurred while accessing the Push Configuration. Please try again later.",
            "danger",
        )
        return redirect(url_for("users.dashboard"))
    except Exception as e:
        current_app.logger.error(
            f"Error accessing Push Configuration page by user {current_user.email}: {str(e)}"
        )
        flash(
            "An error occurred while accessing the Push Configuration. Please try again later.",
            "danger",
        )
        return redirect(url_for("users.dashboard"))


@analytics_bp.route("/api/start_analysis", methods=["POST"])
def start_analysis():
    current_app.logger.info(f"Headers: {request.headers}")
    current_app.logger.info(f"Request Data: {request.get_data()}")
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    try:
        data = request.get_json()
        current_app.logger.info(f"Parsed JSON: {data}")
        device_id = data.get("device_id")
        if not device_id:
            return jsonify({"error": "device_id is required"}), 400

        # Proses analisis
        config_data = fetch_device_configuration(device_id)

        # Parsing BackupData dan Simpan ke Database
        parsed_config = parse_mikrotik_config(config_data)
        save_parsing_results(device_id, parsed_config)
        user_prompt = "optimize"
        recommendation = analyze_configuration_with_ai(config_data, user_prompt)
        save_analytics_results(device_id, recommendation)

        result = {
            "message": "Analysis completed.",
            "recommendation": recommendation,
            "parsed_config": parsed_config,
        }
        current_app.logger.info(f"Response Data: {result}")
        return jsonify(result), 200
    except Exception as e:
        current_app.logger.error(f"Error in start_analysis: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/get_recommendations", methods=["GET"])
def get_recommendations():
    """Get recommendations for a specific device."""
    device_id = request.args.get("device_id")
    current_app.logger.info(f"Received device_id: {device_id}")

    try:
        recommendations = AIRecommendations.query.filter_by(
            device_id=device_id, is_applied=False
        ).all()
        current_app.logger.info(f"Recommendations found: {len(recommendations)}")
        return (
            jsonify(
                [
                    {
                        "id": r.id,
                        "recommendation": r.recommendation_text,
                        "created_at": r.created_at,
                    }
                    for r in recommendations
                ]
            ),
            200,
        )
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
            recommendation.recommendation_text,
        )

        # Perbarui status rekomendasi
        recommendation.is_applied = True
        recommendation.applied_at = datetime.utcnow()
        db.session.commit()

        return (
            jsonify(
                {"message": "Configuration applied successfully.", "output": output}
            ),
            200,
        )
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
