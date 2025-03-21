from flask_wtf import FlaskForm
from wtforms import (
    EmailField,
    PasswordField,
    StringField,
    FileField,
    SelectField,
    TextAreaField,
    SubmitField,
    BooleanField,
    IntegerField,
    SelectMultipleField,
    HiddenField,
)
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
    ValidationError,
    Optional,
    IPAddress,
    Regexp,
    NumberRange,
)
from wtforms_sqlalchemy.fields import QuerySelectMultipleField
from src.models.app_models import User, Permission


class RegisterForm(FlaskForm):
    """
    Formulir untuk registrasi pengguna.

    Field:
    - first_name: StringField untuk nama depan dengan validator untuk data yang diperlukan.
    - last_name: StringField untuk nama belakang dengan validator untuk data yang diperlukan.
    - email: EmailField untuk alamat email dengan validator untuk data yang diperlukan dan format email.
    - password: PasswordField untuk kata sandi dengan validator untuk data yang diperlukan dan panjang.
    - confirm_password: PasswordField untuk mengkonfirmasi kata sandi, harus cocok dengan kata sandi.

    Metode:
    - validate_email: Metode validasi kustom untuk memeriksa apakah email sudah terdaftar.
    """

    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, max=25),
            Regexp(
                r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
                message="Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.",
            ),
        ],
    )
    confirm_password = PasswordField(
        "Repeat Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords harus match."),
        ],
    )

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.strip()).first()
        if user:
            raise ValidationError("Email sudah terdaftar.")


class LoginForm(FlaskForm):
    """
    Formulir untuk login pengguna.

    Field:
    - email: EmailField untuk alamat email dengan validator untuk data yang diperlukan dan format email.
    - password: PasswordField untuk kata sandi dengan validator untuk data yang diperlukan.
    """

    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])


class TwoFactorForm(FlaskForm):
    """
    Formulir untuk otentikasi dua faktor.

    Field:
    - otp: StringField untuk memasukkan OTP (One-Time Password) dengan validator untuk input yang diperlukan dan panjang.
    """

    otp = StringField("Enter OTP", validators=[DataRequired(), Length(min=6, max=6)])


class UserUpdateForm(FlaskForm):
    """
    Formulir untuk memperbarui data pengguna oleh Role Admin dengan pesan error yang relevan.
    """

    first_name = StringField(
        "First Name",
        validators=[DataRequired(message="Nama depan harus diisi.")],
    )
    last_name = StringField(
        "Last Name",
        validators=[DataRequired(message="Nama belakang harus diisi.")],
    )
    email = StringField(
        "Email",
        validators=[
            DataRequired(message="Email harus diisi."),
            Email(message="Format email tidak valid."),
        ],
    )
    password = PasswordField(
        "New Password",
        validators=[
            Optional(),
            Length(min=8, message="Password minimal harus 8 karakter."),
        ],
    )
    phone_number = StringField(
        "Phone Number",
        validators=[
            Optional(),
            Regexp(
                r"^\+?[1-9]\d{1,14}$",
                message="Nomor telepon harus valid dengan format internasional.",
            ),
        ],
    )
    profile_picture = StringField(
        "Profile Picture URL",
        validators=[Optional()],
    )
    company = StringField(
        "Company",
        validators=[Optional()],
    )
    title = StringField(
        "Title",
        validators=[Optional()],
    )
    city = StringField(
        "City",
        validators=[Optional()],
    )
    division = StringField(
        "Division",
        validators=[Optional()],
    )
    is_verified = SelectField(
        "Email Verified",
        choices=[("True", "True"), ("False", "False")],
        coerce=str,
        validators=[DataRequired(message="Status verifikasi email harus dipilih.")],
    )
    is_2fa_enabled = SelectField(
        "2FA Enabled",
        choices=[("True", "True"), ("False", "False")],
        coerce=str,
        validators=[DataRequired(message="Status 2FA harus dipilih.")],
    )
    is_active = SelectField(
        "Active",
        choices=[("True", "True"), ("False", "False")],
        coerce=str,
        validators=[DataRequired(message="Status aktif pengguna harus dipilih.")],
    )
    time_zone = SelectField(
        "Time Zone",
        choices=[
            ("UTC", "UTC (Coordinated Universal Time)"),
            ("America/New_York", "New York (GMT-5)"),
            ("America/Los_Angeles", "Los Angeles (GMT-8)"),
            ("Europe/London", "London (GMT+0)"),
            ("Europe/Berlin", "Berlin (GMT+1)"),
            ("Asia/Dubai", "Dubai (GMT+4)"),
            ("Asia/Kolkata", "India (GMT+5:30)"),
            ("Asia/Jakarta", "Jakarta (GMT+7)"),
            ("Asia/Tokyo", "Tokyo (GMT+9)"),
            ("Australia/Sydney", "Sydney (GMT+11)"),
        ],
    )


class ProfileUpdateForm(FlaskForm):
    """
    Formulir untuk memperbarui data profile pengguna.
    """

    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("New Password", validators=[Optional()])
    phone_number = StringField("Phone Number")
    profile_picture = StringField("Profile Picture URL")
    company = StringField("Company")
    title = StringField("Title")
    city = StringField("City")
    division = StringField("Division")
    time_zone = SelectField(
        "Time Zone",
        choices=[
            ("UTC", "UTC (Coordinated Universal Time)"),
            ("America/New_York", "New York (GMT-5)"),
            ("America/Los_Angeles", "Los Angeles (GMT-8)"),
            ("Europe/London", "London (GMT+0)"),
            ("Europe/Berlin", "Berlin (GMT+1)"),
            ("Asia/Dubai", "Dubai (GMT+4)"),
            ("Asia/Kolkata", "India (GMT+5:30)"),
            ("Asia/Jakarta", "Jakarta (GMT+7)"),
            ("Asia/Tokyo", "Tokyo (GMT+9)"),
            ("Australia/Sydney", "Sydney (GMT+11)"),
        ],
    )
    biodata = TextAreaField(
        "Biodata",
        validators=[Optional()],
    )


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField("Old Password", validators=[DataRequired()])
    new_password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=8, max=25),
            Regexp(
                r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
                message="Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.",
            ),
        ],
    )
    repeat_password = PasswordField(
        "Repeat New Password",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="Passwords must match."),
        ],
    )


class ProfilePictureForm(FlaskForm):
    profile_picture = FileField("Profile Picture", validators=[DataRequired()])


class User2FAEnableForm(FlaskForm):
    """
    Formulir untuk mengaktifkan/nonaktifkan 2FA.
    """

    is_2fa_enabled = SelectField(
        "2FA Enabled", choices=[("True", "True"), ("False", "False")], coerce=str
    )


class RolesForm(FlaskForm):
    name = StringField(
        "Role Name",
        validators=[DataRequired(), Length(max=64)],
        render_kw={"placeholder": "Enter role name"},
    )

    permissions = QuerySelectMultipleField(
        "Permissions", query_factory=lambda: Permission.query.all(), get_label="name"
    )

    submit = SubmitField("Save Role")


class RoleUpdateForm(FlaskForm):
    name = StringField(
        "Role Name",
        validators=[DataRequired(), Length(max=64)],
        render_kw={"placeholder": "Enter role name"},
    )

    users = SelectMultipleField("Users", coerce=str)  # Menyimpan ID user sebagai string

    permissions = SelectMultipleField(
        "Permissions",
        coerce=str,  # Menyimpan ID permission sebagai string
    )

    submit = SubmitField("Save Changes")


class RoleDeleteForm(FlaskForm):
    pass


class RoleAssignUserForm(FlaskForm):
    pass


class PermissionCreateForm(FlaskForm):
    pass


class PermissionUpdateForm(FlaskForm):
    pass


class PermissionDeleteForm(FlaskForm):
    pass


class DeviceForm(FlaskForm):
    device_name = StringField(
        "Device Name",
        validators=[
            DataRequired(message="Please enter the device name."),
            Length(min=1, max=50),
        ],
    )
    vendor = SelectField(
        "Select Device Vendor",
        choices=[
            ("mikrotik", "Mikrotik"),
            ("cisco", "Cisco"),
            ("fortinet", "Fortinet"),
        ],
        validators=[DataRequired()],
    )
    ip_address = StringField(
        "IP Address",
        validators=[
            DataRequired(message="Please enter the IP Address."),
            IPAddress(message="IP Address not valid."),
        ],
    )
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Please enter the username."),
            Length(min=1, max=50),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Please enter the password."),
        ],
    )
    ssh = StringField(
        "SSH Port",
        validators=[
            DataRequired(),
            Regexp(r"^\d+$", message="SSH port must be a number"),
        ],
    )
    description = StringField("Description", validators=[Optional(), Length(max=200)])


class DeviceUpdateForm(FlaskForm):
    device_name = StringField(
        "Device Name",
        validators=[
            DataRequired(message="Please enter the device name."),
            Length(min=1, max=50),
        ],
    )
    vendor = SelectField(
        "Select Device Vendor",
        choices=[
            ("mikrotik", "Mikrotik"),
            ("cisco", "Cisco"),
            ("fortinet", "Fortinet"),
        ],
        validators=[DataRequired()],
    )
    ip_address = StringField(
        "IP Address",
        validators=[
            DataRequired(message="Please enter the IP Address."),
            IPAddress(message="IP Address not valid."),
        ],
    )
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Please enter the username."),
            Length(min=1, max=50),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[Optional()],
    )
    ssh = StringField(
        "SSH Port",
        validators=[
            DataRequired(),
            Regexp(r"^\d+$", message="SSH port must be a number"),
        ],
    )
    description = StringField("Description", validators=[Optional(), Length(max=200)])


class TemplateForm(FlaskForm):
    vendor = SelectField(
        "Select Device Vendor",
        choices=[
            ("mikrotik", "Mikrotik"),
            ("cisco", "Cisco"),
            ("fortinet", "Fortinet"),
        ],
        validators=[DataRequired()],
    )
    version = StringField(
        "Version",
        validators=[
            DataRequired(message="Version is required."),
            Length(max=10, message="Version must be less than 10 characters."),
        ],
    )
    description = TextAreaField(
        "Description",
        validators=[
            Length(max=100, message="Description must be less than 100 characters.")
        ],
    )


class TemplateUpdateForm(FlaskForm):
    template_name = StringField(
        "Nama Template",
        validators=[
            DataRequired(message="Nama template harus diisi."),
            Length(
                max=100, message="Nama template tidak boleh lebih dari 100 karakter."
            ),
        ],
    )
    parameter_name = StringField(
        "Nama Parameter",
        validators=[
            DataRequired(message="Nama parameter harus diisi."),
            Length(
                max=100, message="Nama parameter tidak boleh lebih dari 100 karakter."
            ),
        ],
    )
    vendor = SelectField(
        "Select Device Vendor",
        choices=[
            ("mikrotik", "Mikrotik"),
            ("cisco", "Cisco"),
            ("fortinet", "Fortinet"),
        ],
        validators=[DataRequired()],
    )
    version = StringField(
        "Versi",
        validators=[
            DataRequired(message="Versi harus diisi."),
            Length(max=20, message="Versi tidak boleh lebih dari 20 karakter."),
        ],
    )
    description = TextAreaField(
        "Deskripsi",
        validators=[
            Length(max=500, message="Deskripsi tidak boleh lebih dari 500 karakter.")
        ],
    )
    template_content = TextAreaField(
        "Konten Template",
        validators=[DataRequired(message="Konten template harus diisi.")],
    )
    parameter_content = TextAreaField(
        "Konten Parameter",
        validators=[DataRequired(message="Konten parameter harus diisi.")],
    )


class ManualTemplateForm(FlaskForm):
    vendor = SelectField(
        "Select Device Vendor",
        choices=[
            ("mikrotik", "Mikrotik"),
            ("cisco", "Cisco"),
            ("fortinet", "Fortinet"),
        ],
        validators=[DataRequired()],
    )
    version = StringField(
        "Version",
        validators=[DataRequired(message="Versi tidak boleh kosong."), Length(max=10)],
    )
    description = StringField("Description", validators=[Length(max=100)])
    template_content = TextAreaField(
        "Template Content",
        validators=[DataRequired(message="Konten template tidak boleh kosong.")],
    )
    parameter_content = TextAreaField(
        "Parameter Content",
        validators=[DataRequired(message="Konten parameter tidak boleh kosong.")],
    )


class TemplateDeleteForm(FlaskForm):
    pass


class ManualConfigurationForm(FlaskForm):
    filename = StringField(
        "Filename",
        validators=[
            DataRequired(message="Filename is required."),
            Length(
                min=1, max=100, message="Filename must be between 1 and 100 characters."
            ),
        ],
    )
    vendor = SelectField(
        "Select Device Vendor",
        choices=[
            ("mikrotik", "Mikrotik"),
            ("cisco", "Cisco"),
            ("fortinet", "Fortinet"),
        ],
        validators=[DataRequired()],
    )
    configuration_description = TextAreaField(
        "Configuration Description",
        validators=[
            Length(max=500, message="Description must be less than 500 characters.")
        ],
    )
    configuration_content = TextAreaField(
        "Configuration Content",
        validators=[
            DataRequired(message="Configuration content is required."),
            Length(
                min=1,
                max=10000,
                message="Configuration content must be between 1 and 10,000 characters.",
            ),
        ],
    )
    submit = SubmitField("Create Configuration")


class AIConfigurationForm(FlaskForm):
    filename = StringField(
        "Filename",
        validators=[
            DataRequired(message="Filename is required."),
            Length(
                min=1, max=100, message="Filename must be between 1 and 100 characters."
            ),
        ],
    )
    vendor = SelectField(
        "Select Device Vendor",
        choices=[
            ("mikrotik", "Mikrotik"),
            ("cisco", "Cisco"),
            ("fortinet", "Fortinet"),
        ],
        validators=[DataRequired()],
    )
    description = TextAreaField(
        "Description",
        validators=[
            Length(max=500, message="Description must be less than 500 characters.")
        ],
    )
    ask_configuration = TextAreaField(
        "Configuration Requirements",
        validators=[
            DataRequired(message="Configuration requirements are required."),
            Length(
                min=10,
                max=5000,
                message="Configuration requirements must be between 10 and 5000 characters.",
            ),
        ],
    )
    submit = SubmitField("Create Configuration")


class UpdateConfigurationForm(FlaskForm):
    config_name = StringField(
        "Config Name",
        validators=[
            DataRequired(message="Config name is required."),
            Length(
                min=1,
                max=100,
                message="Config name must be between 1 and 100 characters.",
            ),
        ],
    )
    vendor = SelectField(
        "Select Device Vendor",
        choices=[
            ("mikrotik", "Mikrotik"),
            ("cisco", "Cisco"),
            ("fortinet", "Fortinet"),
        ],
        validators=[DataRequired()],
    )
    description = TextAreaField(
        "Description",
        validators=[
            Length(max=500, message="Description must be less than 500 characters.")
        ],
    )
    config_content = TextAreaField(
        "Config Content",
        validators=[
            DataRequired(message="Config content is required."),
            Length(min=1, message="Config content cannot be empty."),
        ],
    )
    submit = SubmitField("Update Configuration")


class TalitaQuestionForm(FlaskForm):
    config_name = StringField(
        "Configuration Name",
        validators=[
            DataRequired(message="Configuration name is required."),
            Length(max=100, message="Configuration name cannot exceed 100 characters."),
        ],
    )
    vendor = SelectField(
        "Select Device Vendor",
        choices=[
            ("mikrotik", "Mikrotik"),
            ("cisco", "Cisco"),
            ("fortinet", "Fortinet"),
        ],
        validators=[DataRequired()],
    )
    description = TextAreaField(
        "Description",
        validators=[
            Length(max=500, message="Description cannot exceed 500 characters.")
        ],
    )
    question = TextAreaField(
        "Pertanyaan",
        validators=[
            DataRequired(message="Pertanyaan tidak boleh kosong."),
            Length(min=10, message="Pertanyaan harus berisi setidaknya 10 karakter."),
        ],
    )
    submit = SubmitField("Submit")


class BackupForm(FlaskForm):
    backup_name = StringField("Backup Name", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[Optional()])
    backup_type = SelectField(
        "Backup Type",
        choices=[
            ("full", "Full Backup"),
            ("incremental", "Incremental Backup"),
            ("differential", "Differential Backup"),
        ],
        validators=[DataRequired()],
    )
    retention_days = IntegerField(
        "Retention Days", validators=[Optional(), NumberRange(min=1)]
    )
    devices = HiddenField("Devices")
    submit = SubmitField("Create Backup")


class UpdateBackupForm(FlaskForm):
    backup_name = StringField("Backup Name", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[Optional()])
    retention_days = IntegerField("Retention Period (Days)", validators=[Optional()])
    is_encrypted = BooleanField("Encrypt Backup", default=False)
    is_compressed = BooleanField("Compress Backup", default=False)
    tags = StringField(
        "Tags (comma-separated)", validators=[Optional()]
    )  # String field for tags
