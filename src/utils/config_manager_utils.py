import threading
import subprocess
import paramiko
import webbrowser
import platform
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
                timeout=10,
            )
            stdin, stdout, stderr = ssh_client.exec_command(command)

            # Menunggu hingga perintah selesai dieksekusi
            stdout.channel.recv_exit_status()
            response = stdout.read().decode()
            ssh_client.close()

            # Jika sukses, kembalikan pesan sukses
            return "Push konfigurasi sukses!", "success"
        except paramiko.AuthenticationException:
            # Jika gagal otentikasi
            error_message = "Authentication failed, please verify your credentials."
            print(error_message)
            return error_message, "danger"
        except paramiko.SSHException as sshException:
            # Jika gagal membuat koneksi SSH
            error_message = f"Unable to establish SSH connection: {sshException}"
            print(error_message)
            return error_message, "danger"
        except Exception as e:
            # Jika terjadi kesalahan lain
            error_message = f"Error: {e}"
            print(error_message)
            return error_message, "danger"

    def check_device_status(self):
        """
        Memeriksa status perangkat dengan menggunakan ping.
        """
        try:
            # Tentukan perintah ping berdasarkan sistem operasi
            if platform.system() == "Windows":
                command = ["ping", "-n", "1", self.ip_address]
            elif platform.system() == "Linux":
                command = ["ping", "-c", "1", self.ip_address]
            else:
                error_message = "Unsupported operating system."
                print(error_message)
                self.device_status = False
                return error_message

            # Jalankan ping
            response = subprocess.run(command, capture_output=True, text=True)
            if response.returncode == 0:
                self.device_status = True
                return "Device is reachable", "success"
            else:
                self.device_status = False
                return "Device is not reachable", "danger"
        except Exception as e:
            # Jika terjadi kesalahan saat memeriksa status perangkat
            error_message = f"Error: {e}"
            print(error_message)
            self.device_status = False
            return error_message, "danger"

    def check_device_status_threaded(self):
        """
        Memeriksa status perangkat dalam thread terpisah.
        """
        thread = threading.Thread(target=self.check_device_status)
        thread.start()
        thread.join()

    def open_console(self):
        """
        Membuka konsol SSH atau web berdasarkan sistem operasi.
        """
        try:
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
        """
        Membuka konsol web dengan URL perangkat.
        """
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
        """
        Membuat backup konfigurasi perangkat melalui SSH.
        """
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
            return None
