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
