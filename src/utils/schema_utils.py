from src import ma


#########################################################################
# Form API Section with Flask-Marshmallow
#########################################################################


class UserSchema(ma.Schema):
    class Meta:
        fields = (
            "id",
            "first_name",
            "last_name",
            "email",
            "password_hash",
            "phone_number",
            "profile_picture",
            "company",
            "title",
            "city",
            "division",
            "is_active",
            "is_verified",
            "date_joined",
            "last_login",
            "time_zone",
            "is_2fa_enabled",
            "secret_token",
            "email_verification_token",
            "force_logout",
        )


user_schema = UserSchema()
users_schema = UserSchema(many=True)


class DeviceSchema(ma.Schema):
    class Meta:
        fields = (
            "id",
            "device_name",
            "vendor",
            "ip_address",
            "username",
            "password",
            "ssh",
            "description",
            "created_by",
            "status",
            "is_active",
        )


device_schema = DeviceSchema()
devices_schema = DeviceSchema(many=True)


class TemplateSchema(ma.Schema):
    class Meta:
        fields = (
            "id",
            "template_name",
            "parameter_name",
            "vendor",
            "version",
            "description",
            "template_content",
            "parameter_content",
            "created_by",
        )


template_schema = TemplateSchema()
templates_schema = TemplateSchema(many=True)


class ConfigfileSchema(ma.Schema):
    class Meta:
        fields = (
            "id",
            "config_name",
            "vendor",
            "description",
            "created_by",
            "user_id",
            "shared_with",
            "config_content",
        )


configfile_schema = ConfigfileSchema()
configfiles_schema = ConfigfileSchema(many=True)


class BackupSchema(ma.Schema):

    class Meta:
        fields = (
            "id",
            "backup_name",
            "description",
            "version",
            "created_at",
            "backup_path",
            "is_encrypted",
            "is_compressed",
            "integrity_check",
            "backup_type",
            "next_scheduled_backup",
            "retention_period,days",
            "user_id",
            "device_id",
        )

backup_schema = BackupSchema()
backups_schema = BackupSchema(many=True)
