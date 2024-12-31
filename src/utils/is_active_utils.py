# utils.py
from flask import request


def is_active(url):
    return "active" if request.path == url else ""
