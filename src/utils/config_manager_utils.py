import threading
import paramiko
import subprocess
from jinja2 import Template
import yaml


class ConfigurationManagerUtils:
    def __init__(
        self, ip_address="0.0.0.0", username="admin", password="admin", ssh=22
    ):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.ssh = ssh
        self.device_status = None

    def configure_device(self, command):
        """
        Konfigurasi perangkat melalui SSH dengan perintah yang diberikan.
        Mengembalikan pesan sukses atau kesalahan.
        """
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=self.ip_address,
                username=self.username,
                password=self.password,
                port=self.ssh,
                timeout=5,
            )
            stdin, stdout, stderr = ssh_client.exec_command(command)

            # Menunggu hingga perintah selesai dieksekusi
            stdout.channel.recv_exit_status()
            response = stdout.read().decode()
            ssh_client.close()

            # Jika sukses, kembalikan pesan sukses
            return "Push konfigurasi sukses!", "success"
        except paramiko.AuthenticationException:
            error_message = "Authentication failed, please verify your credentials."
            print(error_message)
            return error_message, "danger"
        except paramiko.SSHException as sshException:
            error_message = f"Unable to establish SSH connection: {sshException}"
            print(error_message)
            return error_message, "danger"
        except Exception as e:
            error_message = f"Error: {e}"
            print(error_message)
            return error_message, "danger"

    def ping_device(self, ip_address):
        """
        Mengecek apakah perangkat dapat dijangkau menggunakan ping.
        """
        try:
            output = subprocess.check_output(
                ["ping", "-c", "1", ip_address], stderr=subprocess.STDOUT
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def check_device_status(self):
        """
        Memeriksa status perangkat.
        """
        status = self.ping_device(self.ip_address)
        self.device_status = {"ip_address": self.ip_address, "reachable": status}
        print(
            f"Device {self.ip_address} is {'reachable' if status else 'not reachable'}."
        )

    def check_device_status_threaded(self):
        """
        Memeriksa status perangkat dalam thread terpisah.
        """

        def target():
            self.check_device_status()

        thread = threading.Thread(target=target)
        thread.start()
        thread.join()

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
