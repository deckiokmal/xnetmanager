import threading
import paramiko
import subprocess
from jinja2 import Template
import yaml
import platform
import json
import logging
import time
import os
from flask import current_app

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class ConfigurationManagerUtils:
    def __init__(
        self, ip_address="0.0.0.0", username="admin", password="admin", ssh=22
    ):
        """
        Inisialisasi objek ConfigurationManagerUtils dengan detail koneksi perangkat.

        :param ip_address: Alamat IP perangkat yang akan dikonfigurasi.
        :param username: Nama pengguna untuk autentikasi SSH.
        :param password: Kata sandi untuk autentikasi SSH.
        :param ssh: Port SSH perangkat.
        """
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.ssh = ssh
        self.device_status = None

    def configure_device(self, command):
        """
        Mengonfigurasi perangkat melalui SSH dengan perintah yang diberikan.
        Mengembalikan pesan sukses atau kesalahan dalam format JSON.

        :param command: Perintah konfigurasi yang akan dijalankan pada perangkat.
        :return: Hasil eksekusi perintah dalam format JSON.
        """
        try:
            start_time = time.time()
            ssh_client = paramiko.SSHClient()
            ssh_client.load_system_host_keys()
            ssh_client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )  # Menambahkan kunci otomatis
            ssh_client.connect(
                hostname=self.ip_address,
                username=self.username,
                password=self.password,
                port=self.ssh,
                timeout=5,
            )
            stdin, stdout, stderr = ssh_client.exec_command(command)
            stdout.channel.recv_exit_status()
            response = stdout.read().decode()
            ssh_client.close()
            elapsed_time = time.time() - start_time
            logging.info(
                "Konfigurasi berhasil pada %s dalam %.2fs",
                self.ip_address,
                elapsed_time,
            )
            return json.dumps({"message": response, "status": "success"})
        except paramiko.AuthenticationException:
            error_message = "Autentikasi gagal, periksa kredensial Anda."
            logging.error(
                "Autentikasi gagal untuk %s: %s", self.ip_address, error_message
            )
            return json.dumps({"message": error_message, "status": "error"})
        except paramiko.SSHException as sshException:
            error_message = f"Tidak dapat membangun koneksi SSH: {sshException}"
            logging.error(
                "Kesalahan koneksi SSH untuk %s: %s", self.ip_address, error_message
            )
            return json.dumps({"message": error_message, "status": "error"})
        except Exception as e:
            error_message = f"Kesalahan: {e}"
            logging.error(
                "Kesalahan saat mengonfigurasi perangkat %s: %s",
                self.ip_address,
                error_message,
            )
            return json.dumps({"message": error_message, "status": "error"})

    def check_device_status(self):
        """
        Mengecek status perangkat dengan melakukan ping ke alamat IP.
        Mengembalikan status perangkat dalam format JSON.

        :return: Status perangkat dalam format JSON.
        """
        try:
            # Tentukan perintah ping berdasarkan sistem operasi
            if platform.system() == "Windows":
                command = ["ping", "-n", "1", self.ip_address]
            elif platform.system() == "Linux":
                command = ["ping", "-c", "1", self.ip_address]
            else:
                error_message = "Sistem operasi tidak didukung."
                logging.error(
                    "OS tidak didukung untuk %s: %s", self.ip_address, error_message
                )
                return json.dumps({"message": error_message, "status": "error"})

            start_time = time.time()
            response = subprocess.run(command, capture_output=True, text=True)
            elapsed_time = time.time() - start_time

            if "Reply from" in response.stdout or "reply from" in response.stdout:
                self.device_status = True
                status_message = "Perangkat online"
            else:
                self.device_status = False
                status_message = "Perangkat offline"

            logging.info(
                "Status perangkat diperiksa untuk %s dalam %.2fs: %s",
                self.ip_address,
                elapsed_time,
                status_message,
            )
            return json.dumps({"message": status_message, "status": "success"})
        except Exception as e:
            error_message = f"Kesalahan: {e}"
            logging.error(
                "Kesalahan saat memeriksa status untuk %s: %s",
                self.ip_address,
                error_message,
            )
            return json.dumps({"message": error_message, "status": "error"})

    def check_device_status_threaded(self):
        """
        Mengecek status perangkat menggunakan threading.
        Mengembalikan hasil status dalam format JSON.

        :return: Status perangkat dalam format JSON.
        """
        thread = threading.Thread(target=self.check_device_status)
        thread.start()
        thread.join()
        return self.check_device_status()

    def render_template_config(self, jinja_template, yaml_params):
        """
        Merender template Jinja2 dengan parameter YAML.
        Mengembalikan konfigurasi yang telah dirender dalam format JSON.

        :param jinja_template: Template Jinja2 dalam format string.
        :param yaml_params: Parameter YAML yang akan digabungkan dengan template.
        :return: Konfigurasi yang telah dirender dalam format JSON.
        """
        try:
            # Parsing parameter YAML
            yaml_params_dict = yaml.safe_load(yaml_params)
            # Membuat objek Template Jinja2
            template = Template(jinja_template)
            # Menggabungkan parameter YAML ke dalam template Jinja2
            rendered_config = template.render(yaml_params_dict)
            logging.info("Template berhasil dirender")
            return rendered_config
        except Exception as e:
            error_message = f"Kesalahan: {e}"
            logging.error("Kesalahan saat merender template: %s", error_message)
            return json.dumps({"message": error_message, "status": "error"})

    def backup_configuration(self, command):
        """
        Menjalankan perintah pada perangkat dan mengembalikan hasil konfigurasi dalam format JSON.

        :param command: Perintah konfigurasi yang akan dijalankan pada perangkat.
        :return: JSON yang berisi status dan pesan hasil eksekusi perintah.
        """
        try:
            # Jalankan perintah konfigurasi pada perangkat
            result_json = self.configure_device(command)

            # Parse hasil JSON dari perintah konfigurasi
            result_dict = json.loads(result_json)

            # Cek apakah status sukses dan kembalikan pesan dalam format JSON
            if result_dict.get("status") == "success":
                output = result_dict.get("message")
                return json.dumps({"status": "success", "message": output})
            else:
                error_message = result_dict.get("message")
                logging.error("Konfigurasi gagal: %s", error_message)
                return json.dumps({"status": "error", "message": error_message})
        except json.JSONDecodeError as e:
            error_message = f"Kesalahan parsing JSON: {e}"
            logging.error(error_message)
            return json.dumps({"status": "error", "message": error_message})
        except Exception as e:
            error_message = f"Kesalahan tidak terduga saat menjalankan perintah: {e}"
            logging.error(error_message)
            return json.dumps({"status": "error", "message": error_message})
