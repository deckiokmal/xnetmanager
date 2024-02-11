import paramiko
import subprocess
from jinja2 import Template
import yaml
import sqlite3

class netAuto:
    def __init__(self, ip_address, username, password, ssh):
        """
        Inisialisasi objek netAuto dengan informasi dasar perangkat.
        """
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.ssh = ssh

    def send_command(self, command):
        """
        Mengirimkan perintah SSH ke perangkat.
        """
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=self.ip_address,
                username=self.username,
                password=self.password,
                port=self.ssh
            )
            ssh_client.exec_command(command)
            ssh_client.close()
            return True
        except Exception as e:
            print("Error:", e)
            return False

    def check_device_status(self):
        """
        Memeriksa status perangkat dengan melakukan ping.
        """
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

    @staticmethod
    def get_device_list_from_database():
        """
        Mendapatkan daftar perangkat dari database.
        """
        try:
            conn = sqlite3.connect('device_manager.db')
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address, username, password, ssh FROM device_manager")
            device_list = cursor.fetchall()
            conn.close()
            return device_list
        except Exception as e:
            print("Error:", e)
            return []

    def send_command_by_id(self, device_id, command):
        """
        Mengirimkan perintah ke perangkat berdasarkan ID perangkat.
        """
        try:
            conn = sqlite3.connect('device_manager.db')
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address, username, password, ssh FROM device_manager WHERE id=?", (device_id,))
            device_info = cursor.fetchone()
            conn.close()
            if device_info:
                ip_address, username, password, ssh_port = device_info
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(
                    hostname=ip_address,
                    username=username,
                    password=password,
                    port=ssh_port
                )
                ssh_client.exec_command(command)
                ssh_client.close()
                return True
            else:
                print("Device not found.")
                return False
        except Exception as e:
            print("Error:", e)
            return False
