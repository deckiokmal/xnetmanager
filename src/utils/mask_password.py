def mask_password(password):
    if not password:
        return ""
    return "*" * 5
