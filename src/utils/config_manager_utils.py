import threading
import paramiko
import subprocess
from jinja2 import Template
import yaml
import platform


class ConfigurationManagerUtils:
    def __init__(
        self, ip_address="0.0.0.0", username="admin", password="admin", ssh=22
    ):
        """
        Inisialisasi objek ConfigurationManagerUtils dengan detail koneksi perangkat.
        """
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
            # Membuat koneksi SSH ke perangkat
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

    def check_device_status(self):
        """
        Mengecek status perangkat dengan melakukan ping ke alamat IP.
        Jika ada balasan (reply), maka status perangkat online; jika tidak, offline.
        """
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
            if "Reply from" in response.stdout or "reply from" in response.stdout:
                self.device_status = True
            else:
                self.device_status = False
        except Exception as e:
            print("Error:", e)
            self.device_status = False

    def check_device_status_threaded(self):
        """
        Mengecek status perangkat dengan menggunakan threading.
        Memulai thread untuk memanggil fungsi check_device_status.
        """
        thread = threading.Thread(target=self.check_device_status)
        thread.start()
        thread.join()

    def render_template_config(self, jinja_template, yaml_params):
        """
        Merender template Jinja2 dengan parameter YAML.
        Mengembalikan konfigurasi yang telah dirender atau None jika terjadi kesalahan.
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

    def backup_config(self, device, command_backup):
        """
        Kirim perintah backup ke perangkat berdasarkan vendor dan simpan STDOUT ke dalam file baru.
        """
        try:
            # Membuat koneksi SSH ke perangkat
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=self.ip_address,
                username=self.username,
                password=self.password,
                port=self.ssh,
                timeout=5,
            )
            stdin, stdout, stderr = ssh_client.exec_command(command_backup)

            # Menunggu hingga perintah selesai dieksekusi
            stdout.channel.recv_exit_status()
            response = stdout.read().decode()
            ssh_client.close()

            return response

        except paramiko.AuthenticationException:
            error_message = "Authentication failed, please verify your credentials."
            return error_message, "danger"
        except paramiko.SSHException as sshException:
            error_message = f"Unable to establish SSH connection: {sshException}"
            return error_message, "danger"
        except Exception as e:
            error_message = f"Error: {e}"
            return error_message, "danger"
