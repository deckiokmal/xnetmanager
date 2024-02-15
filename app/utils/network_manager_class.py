import threading
import subprocess
import paramiko
import os
import webbrowser
import platform
from jinja2 import Template
import yaml


class NetworkManagerUtils:
    def __init__(
        self, ip_address="0.0.0.0", username="admin", password="admin", ssh=22
    ):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.ssh = ssh
        self.device_status = None

    def configure_device(self, command):
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=self.ip_address,
                username=self.username,
                password=self.password,
                port=self.ssh,
            )
            ssh_client.exec_command(command)
            ssh_client.close()
            return True
        except Exception as e:
            print("Error:", e)
            return False

    def check_device_status(self):
        try:
            # Tentukan perintah ping berdasarkan sistem operasi
            if platform.system() == "Windows":
                command = ["ping", "-n", "1", self.ip_address]
            elif platform.system() == "Linux":
                command = ["ping", "-c", "1", self.ip_address]
            else:
                print("Unsupported operating system.")
                return False

            # Jalankan ping
            response = subprocess.run(command, capture_output=True, text=True)
            if response.returncode == 0:
                self.device_status = True
            else:
                self.device_status = False
        except Exception as e:
            print("Error:", e)
            self.device_status = False

    def check_device_status_threaded(self):
        thread = threading.Thread(target=self.check_device_status)
        thread.start()
        thread.join()

    def open_console(self):
        try:
            # Periksa platform sistem operasi
            if platform.system() == "Windows":
                # Jalankan PuTTY di Windows
                subprocess.Popen(
                    [
                        "putty.exe",
                        "-ssh",
                        f"{self.username}@{self.ip_address}",
                        "-pw",
                        self.password,
                    ]
                )
            elif platform.system() == "Linux":
                # Jalankan PuTTY di Linux
                subprocess.Popen(
                    [
                        "putty",
                        "-ssh",
                        f"{self.username}@{self.ip_address}",
                        "-pw",
                        self.password,
                    ]
                )
            else:
                print("Unsupported operating system.")
                return False
            return True
        except Exception as e:
            print("Error:", e)
            return False

    def open_webconsole(self):
        try:
            url = f"http://{self.ip_address}"
            webbrowser.open_new_tab(url)
            return True
        except Exception as e:
            print("Error:", e)
            return False

    def render_template_config(self, jinja_template, yaml_params):
        """
        Merender template Jinja2 dengan parameter YAML.
        """
        try:
            # Parsing parameter YAML
            yaml_params_dict = yaml.safe_load(yaml_params)

            # Membuat objek Template Jinja2
            template = Template(jinja_template)

            # Menggabungkan parameter YAML ke dalam template Jinja2
            rendered_config = template.render(yaml_params_dict)

            return rendered_config
        except Exception as e:
            print("Error:", e)
            return None

    def backup_config(self, command):
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=self.ip_address,
                username=self.username,
                password=self.password,
                port=self.ssh,
            )
            stdin, stdout, stderr = ssh_client.exec_command(command)
            backup_data = stdout.read().decode("utf-8")
            ssh_client.close()

            return backup_data

        except Exception as e:
            print("Error:", e)
            return False


# Examples
list = [
    "192.168.1.1",
    "192.168.2.1",
    "192.168.100.300",
    "192.168.100.254",
    "192.168.100.100",
]

for ip in list:
    myob = NetworkManagerUtils(ip_address=ip)
    myob.check_device_status_threaded()
    print(myob.device_status)
