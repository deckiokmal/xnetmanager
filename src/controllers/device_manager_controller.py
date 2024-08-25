from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    current_app,
)
from flask_login import login_required, current_user
from src import db
from src.models.app_models import DeviceManager
from .decorators import login_required, role_required, required_2fa
from src.utils.forms_utils import DeviceForm, DeviceUpdateForm
from flask_paginate import Pagination, get_page_args
import logging

# Create blueprints for the device manager (dm_bp) and error handling (error_bp)
dm_bp = Blueprint("dm", __name__)
error_bp = Blueprint("error", __name__)

# Setup logging configuration for the application
logging.basicConfig(level=logging.INFO)


@dm_bp.before_app_request
def setup_logging():
    """
    Configure logging for the application.
    This function ensures that all logs are captured at the INFO level,
    making it easier to track the flow of the application and debug issues.
    """
    current_app.logger.setLevel(logging.INFO)
    handler = current_app.logger.handlers[0]  # Use the first handler
    current_app.logger.addHandler(handler)


@error_bp.app_errorhandler(404)
def page_not_found(error):
    """
    Handle 404 errors and display a custom 404 error page.
    Logs the occurrence of a 404 error, which indicates a page was not found.
    """
    current_app.logger.error(f"Error 404: {error}")  # Log the error for debugging
    return render_template("main/404.html"), 404  # Render the custom 404 page


@dm_bp.before_request
def before_request_func():
    """
    Ensure that the user is authenticated before processing any requests.
    If the user is not authenticated, log the attempt and return a 404 error page.
    This helps secure the application by preventing unauthorized access.
    """
    if not current_user.is_authenticated:
        current_app.logger.warning(
            f"Unauthorized access attempt by {request.remote_addr}"  # Log the IP address of the unauthorized attempt
        )
        return (
            render_template("main/404.html"),
            404,
        )  # Render the 404 page to obscure the existence of the resource


@dm_bp.context_processor
def inject_user():
    """
    Provide the authenticated user's first name and last name to the template context.
    This allows templates to access user information for personalized greetings or other user-specific content.
    """
    if current_user.is_authenticated:
        return dict(
            first_name=current_user.first_name, last_name=current_user.last_name
        )
    return dict(
        first_name="", last_name=""
    )  # Return empty strings if the user is not authenticated


# -----------------------------------------------------------
# Devices Manager Section
# -----------------------------------------------------------


@dm_bp.route("/devices-management", methods=["GET"])
@login_required  # Ensure the user is logged in
@required_2fa  # Require two-factor authentication for added security
@role_required(
    roles=["Admin", "User", "View"],  # Restrict access based on user roles
    permissions=[
        "Manage Devices",
        "View Devices",
    ],  # Further restrict access based on permissions
    page="Devices Management",  # Indicate the page for role management
)
def index():
    """
    Display the main page of the Device Manager.
    This page includes a list of devices and supports pagination and searching.
    """
    form = DeviceForm(request.form)
    search_query = request.args.get("search", "").lower()
    page, per_page, offset = get_page_args(
        page_parameter="page", per_page_parameter="per_page", per_page=10
    )

    try:
        # Determine the user's role and adjust the query accordingly
        if current_user.has_role("Admin"):
            if search_query:
                devices_query = DeviceManager.query.filter(
                    DeviceManager.device_name.ilike(f"%{search_query}%")
                    | DeviceManager.ip_address.ilike(f"%{search_query}%")
                    | DeviceManager.vendor.ilike(f"%{search_query}%")
                    | DeviceManager.description.ilike(f"%{search_query}%")
                    | DeviceManager.created_by.ilike(f"%{search_query}%")
                )
            else:
                devices_query = DeviceManager.query
        else:
            if search_query:
                devices_query = DeviceManager.query.filter(
                    DeviceManager.user_id == current_user.id,
                    (
                        DeviceManager.device_name.ilike(f"%{search_query}%")
                        | DeviceManager.ip_address.ilike(f"%{search_query}%")
                        | DeviceManager.vendor.ilike(f"%{search_query}%")
                        | DeviceManager.description.ilike(f"%{search_query}%")
                        | DeviceManager.created_by.ilike(f"%{search_query}%")
                    ),
                )
            else:
                devices_query = DeviceManager.query.filter_by(user_id=current_user.id)

        total_devices = devices_query.count()
        devices = devices_query.limit(per_page).offset(offset).all()
        pagination = Pagination(page=page, per_page=per_page, total=total_devices)

        current_app.logger.info(
            f"User {current_user.email} accessed Device Manager page."
        )

        return render_template(
            "/device_managers/index.html",
            devices=devices,
            page=page,
            per_page=per_page,
            pagination=pagination,
            search_query=search_query,
            total_devices=total_devices,
            form=form,
        )

    except Exception as e:
        # Handle exceptions and log the error
        current_app.logger.error(
            f"Error accessing Device Manager page by user {current_user.email}: {str(e)}"
        )
        flash(
            "An error occurred while accessing the Device Manager. Please try again later.",
            "danger",
        )
        return redirect(
            url_for("users.dashboard")
        )  # Redirect to a safe page like dashboard


@dm_bp.route("/create-device", methods=["GET", "POST"])
@login_required  # Ensure the user is logged in
@required_2fa  # Require two-factor authentication for added security
@role_required(
    roles=["Admin", "User"],  # Restrict access to Admin and User roles
    permissions=["Manage Devices"],  # Require 'Manage Devices' permission
    page="Devices Management",  # Indicate the page for role management
)
def create_device():
    """Add a new device to the database"""
    form = DeviceForm(request.form)  # Initialize the device form with request data

    if request.method == "POST":
        if form.validate_on_submit():
            try:
                # Check if a device with the same IP address or device name already exists
                exist_address = DeviceManager.query.filter_by(
                    ip_address=form.ip_address.data
                ).first()
                exist_device = DeviceManager.query.filter_by(
                    device_name=form.device_name.data
                ).first()

                if exist_device or exist_address:
                    # Provide feedback to the user if the device already exists
                    flash("Perangkat sudah terdaftar!", "info")
                    current_app.logger.info(
                        f"Duplicate device attempt: {form.device_name.data} or {form.ip_address.data} by {current_user.email}"
                    )
                else:
                    # Create a new device with the provided form data
                    new_device = DeviceManager(
                        device_name=form.device_name.data.strip(),
                        vendor=form.vendor.data.strip(),
                        ip_address=form.ip_address.data.strip(),
                        username=form.username.data.strip(),
                        password=form.password.data.strip(),
                        ssh=form.ssh.data.strip(),
                        description=form.description.data.strip(),
                        created_by=current_user.email,
                        user_id=current_user.id,
                    )
                    db.session.add(new_device)  # Add the new device to the session
                    db.session.commit()  # Commit the transaction to the database

                    # Provide success feedback to the user
                    flash("Perangkat berhasil ditambahkan!", "success")
                    current_app.logger.info(
                        f"Device created: {form.device_name.data.strip()} with IP {form.ip_address.data.strip()} by {current_user.email}"
                    )
                    return redirect(
                        url_for("dm.index")
                    )  # Redirect to the device management page
            except Exception as e:
                # Log the error and provide error feedback to the user
                current_app.logger.error(
                    f"Error creating device {form.device_name.data.strip()}: {str(e)}"
                )
                flash(
                    "Terjadi kesalahan saat membuat perangkat. Silakan coba lagi.",
                    "danger",
                )
                db.session.rollback()  # Rollback the transaction in case of error
        else:
            # Log each validation error and provide feedback to the user
            for field, errors in form.errors.items():
                for error in errors:
                    flash(
                        f"Kesalahan pada {getattr(form, field).label.text}: {error}",
                        "danger",
                    )
            current_app.logger.warning("Form validation failed during device creation.")

    return redirect(
        url_for("dm.index")
    )  # Redirect to the device management page if not a POST request


@dm_bp.route("/update-device/<device_id>", methods=["GET", "POST"])
@login_required  # Ensure the user is logged in
@required_2fa  # Require two-factor authentication for security
@role_required(
    roles=["Admin", "User"],  # Restrict access to Admin and User roles
    permissions=["Manage Devices"],  # Require 'Manage Devices' permission
    page="Devices Management",  # Indicate the page for role management
)
def update_device(device_id):
    """Update device information in the database"""

    # Query the device by ID; return 404 if not found
    device = DeviceManager.query.get_or_404(device_id)

    # Check the user's role for ownership logic
    if not current_user.has_role("Admin") and device.user_id != current_user.id:
        # If the user is not Admin and does not own the device, restrict access
        flash("Anda tidak memiliki izin untuk memperbarui perangkat ini.", "danger")
        current_app.logger.warning(
            f"Unauthorized update attempt on Device ID {device_id} by {current_user.email}"
        )
        return redirect(url_for("dm.index"))

    # Initialize the form with the current device data
    form = DeviceUpdateForm(obj=device)

    if request.method == "POST":
        if form.validate_on_submit():  # Check if the form is valid
            try:
                # Check for device name uniqueness
                existing_device = DeviceManager.query.filter(
                    DeviceManager.device_name == form.device_name.data.strip(),
                    DeviceManager.id != device_id,
                ).first()

                if existing_device:
                    flash(
                        "Nama perangkat sudah ada. Silakan pilih nama lain.", "warning"
                    )
                    current_app.logger.warning(
                        f"Duplicate device name attempt for Device ID {device_id} by {current_user.email}"
                    )
                    return render_template(
                        "/device_managers/update_device.html", form=form, device=device
                    )

                # Update password only if a new one is provided
                if form.password.data:
                    device.password = form.password.data.strip()
                    current_app.logger.info(
                        f"Password updated for Device ID {device_id} by {current_user.email}"
                    )
                else:
                    current_app.logger.info(
                        f"No password change for Device ID {device_id} updated by {current_user.email}"
                    )

                # Update other device fields
                device.device_name = form.device_name.data.strip()
                device.vendor = form.vendor.data.strip()
                device.ip_address = form.ip_address.data.strip()
                device.username = form.username.data.strip()
                device.ssh = form.ssh.data.strip()
                device.description = form.description.data.strip()

                # Save changes to the database
                db.session.commit()
                flash("Perangkat berhasil diperbarui!", "success")
                current_app.logger.info(
                    f"Device ID {device_id} updated successfully by {current_user.email}"
                )
                return redirect(
                    url_for("dm.index")
                )  # Redirect to the device management page
            except Exception as e:
                # Log the error and flash a danger message to the user
                current_app.logger.error(
                    f"Error updating device ID {device_id}: {str(e)}"
                )
                flash(
                    "Terjadi kesalahan saat memperbarui perangkat. Silakan coba lagi.",
                    "danger",
                )
                db.session.rollback()  # Rollback the transaction in case of error
        else:
            # Handle form validation errors
            for field, errors in form.errors.items():
                for error in errors:
                    flash(
                        f"Kesalahan pada {getattr(form, field).label.text}: {error}",
                        "danger",
                    )
            current_app.logger.warning(
                f"Form validation failed during device update for device ID {device_id} by {current_user.email}."
            )

    # Provide a placeholder for the password field to guide the user
    form.password.render_kw = {
        "placeholder": "Enter new password if you want to change it"
    }

    # Render the device update page with the form
    return render_template(
        "/device_managers/update_device.html", form=form, device=device
    )


@dm_bp.route("/delete-device/<device_id>", methods=["POST"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def delete_device(device_id):
    """Menghapus perangkat dari database"""
    device = DeviceManager.query.get_or_404(
        device_id
    )  # Retrieve the device by ID, 404 if not found

    # Check the user's role for ownership logic
    if not current_user.has_role("Admin") and device.user_id != current_user.id:
        # If the user is not an Admin and does not own the device, restrict access
        flash("Anda tidak memiliki izin untuk menghapus perangkat ini.", "danger")
        current_app.logger.warning(
            f"Unauthorized delete attempt on Device ID {device_id} by {current_user.email}"
        )
        return redirect(url_for("dm.index"))

    try:
        # Attempt to delete the device from the database
        db.session.delete(device)
        db.session.commit()
        flash(
            "Device telah dihapus!", "success"
        )  # Inform the user of successful deletion
        current_app.logger.info(
            f"Device ID {device_id} deleted by {current_user.email}"  # Log the successful deletion
        )
    except Exception as e:
        # Handle any exceptions that occur during deletion
        current_app.logger.error(f"Error deleting device ID {device_id}: {str(e)}")
        flash(
            "Terjadi kesalahan saat menghapus perangkat.",
            "danger",
        )  # Inform the user of the error

    # Redirect to the device management index page after deletion
    return redirect(url_for("dm.index"))


# -----------------------------------------------------------
# API Devices Section
# -----------------------------------------------------------


@dm_bp.route("/api/get-devices", methods=["GET"])
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def get_devices():
    """Mendapatkan data semua perangkat dalam format JSON yang dimiliki oleh pengguna saat ini"""
    devices = DeviceManager.query.filter(DeviceManager.user_id == current_user.id).all()

    device_list = [
        {
            "id": device.id,
            "device_name": device.device_name,
            "vendor": device.vendor,
            "ip_address": device.ip_address,
            "username": device.username,
            "password": device.password,
            "ssh": device.ssh,
            "description": device.description,
        }
        for device in devices
    ]

    current_app.logger.info(f"User {current_user.email} retrieved their devices data.")
    return jsonify({"devices": device_list})


@dm_bp.route("/api/get-device-data/<device_id>")
@login_required
@required_2fa
@role_required(
    roles=["Admin", "User"], permissions=["Manage Devices"], page="Devices Management"
)
def get_device_data(device_id):
    """Mendapatkan data perangkat berdasarkan ID dalam format JSON jika perangkat tersebut dimiliki oleh pengguna saat ini"""
    try:
        device = DeviceManager.query.get_or_404(device_id)

        # Ensure the current user is the owner of the device
        if device.user_id != current_user.id:
            current_app.logger.warning(
                f"User {current_user.email} attempted to access a device they do not own."
            )
            return (
                jsonify({"error": "You do not have permission to access this device."}),
                403,
            )

        current_app.logger.info(
            f"User {current_user.email} accessed data for device ID {device_id}"
        )
        return jsonify(
            {
                "ip_address": device.ip_address,
                "username": device.username,
                "password": device.password,
                "ssh": device.ssh,
                "device_name": device.device_name,
                "vendor": device.vendor,
                "description": device.description,
            }
        )
    except Exception as e:
        current_app.logger.error(f"Error retrieving device ID {device_id}: {str(e)}")
        return jsonify({"error": "Data tidak ditemukan"}), 404
