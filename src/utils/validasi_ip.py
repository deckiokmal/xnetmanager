import re


# Validasi format IP address
def is_valid_ip(ip_address):
    # Regex untuk validasi IP address v4
    pattern = re.compile(
        r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        + r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        + r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        + r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    return pattern.match(ip_address) is not None
