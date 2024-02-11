import paramiko
import subprocess
from jinja2 import Template
import yaml


class netAuto:
    def __init__(self, ip_address, username, password, jinja_template, yaml_params):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.jinja_template = jinja_template
        self.yaml_params = yaml_params

    def send_command(self, command):
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=self.ip_address, username=self.username, password=self.password
            )
            ssh_client.exec_command(command)
            ssh_client.close()
            return True
        except Exception as e:
            print("Error:", e)
            return False

    def check_device_status(self):
        try:
            response = subprocess.run(
                ["ping", "-c", "1", self.ip_address], capture_output=True, text=True
            )
            if response.returncode == 0:
                return True
            else:
                return False
        except Exception as e:
            print("Error:", e)
            return False

    def render_template(self):
        try:
            # Membaca isi file Jinja2 dari database atau dari file langsung
            jinja_template_content = self.jinja_template.content

            # Membaca parameter YAML dari database atau dari file langsung
            yaml_params_content = self.yaml_params.content

            # Parsing parameter YAML
            yaml_params_dict = yaml.safe_load(yaml_params_content)

            # Membuat objek Template Jinja2
            template = Template(jinja_template_content)

            # Menggabungkan parameter YAML ke dalam template Jinja2
            rendered_config = template.render(yaml_params_dict)

            return rendered_config
        except Exception as e:
            print("Error:", e)
            return None
