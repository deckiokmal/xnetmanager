import yaml
from jinja2 import Environment, meta
from flask import current_app

def validate_jinja2(template_content):
    try:
        env = Environment()
        parsed_content = env.parse(template_content)
        meta.find_undeclared_variables(parsed_content)
        return True
    except Exception as e:
        current_app.logger.error(f"Jinja2 validation error: {e}")
        return False

def validate_yaml(yaml_content):
    try:
        yaml.safe_load(yaml_content)
        return True
    except yaml.YAMLError as e:
        current_app.logger.error(f"YAML validation error: {e}")
        return False