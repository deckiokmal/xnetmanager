from src.models.app_models import Activity
from src import db


def log_activity(user_id, action, details=None):
    new_activity = Activity(user_id=user_id, action=action, details=details)
    db.session.add(new_activity)
    db.session.commit()
