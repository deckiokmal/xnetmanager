import paramiko
from jinja2 import Template
import yaml
import platform
import json
import logging
import time
import asyncio
from paramiko.ssh_exception import SSHException, AuthenticationException
import socket

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class ConfigurationManagerUtils:
    MAX_RETRIES = 3  # Jumlah retry jika koneksi gagal
    RETRY_DELAY = 5  # Delay dalam detik sebelum melakukan retry

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

    def _connect_ssh(self):
        """
        Membangun koneksi SSH dengan retry otomatis jika gagal.
        """
        retries = 0
        while retries < self.MAX_RETRIES:
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
                return ssh_client
            except (paramiko.SSHException, EOFError):
                retries += 1
                logging.error(
                    f"SSH connection failed for {self.ip_address}. Retrying... ({retries}/{self.MAX_RETRIES})"
                )
                time.sleep(self.RETRY_DELAY)
            except Exception as e:
                logging.error(
                    f"Unexpected error while connecting to {self.ip_address}: {e}"
                )
                raise e

        raise paramiko.SSHException(
            f"Unable to establish SSH connection to {self.ip_address} after {self.MAX_RETRIES} retries."
        )

    def _split_commands(self, command):
        """
        Memisahkan perintah multi-baris menjadi daftar perintah tunggal.

        :param command: Perintah multi-baris yang dipisahkan oleh \n.
        :return: Daftar perintah tunggal.
        """
        return command.strip().split("\n")

    def configure_device(self, command):
        """
        Mengonfigurasi perangkat melalui SSH dengan perintah yang diberikan.
        Mengembalikan pesan sukses atau kesalahan dalam format JSON.

        :param command: Perintah konfigurasi yang akan dijalankan pada perangkat.
        :return: Hasil eksekusi perintah dalam format JSON.
        """
        try:
            start_time = time.time()
            with self._connect_ssh() as ssh_client:
                # Pisahkan perintah multi-baris
                commands = self._split_commands(command)
                responses = []

                for cmd in commands:
                    if cmd.strip():  # Abaikan baris kosong
                        stdin, stdout, stderr = ssh_client.exec_command(cmd)
                        stdout.channel.recv_exit_status()
                        response = stdout.read().decode()
                        responses.append(response)

                elapsed_time = time.time() - start_time
                logging.info(
                    "Konfigurasi berhasil pada %s dalam %.2fs",
                    self.ip_address,
                    elapsed_time,
                )
                return json.dumps(
                    {"message": "\n".join(responses), "status": "success"}
                )
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

    async def check_device_status_async(self):
        """
        Mengecek status perangkat secara asinkron dengan melakukan ping ke alamat IP.
        Mengembalikan status perangkat dalam format JSON.
        """
        try:
            command = (
                ["ping", "-n", "1", self.ip_address]
                if platform.system() == "Windows"
                else ["ping", "-c", "1", self.ip_address]
            )
            start_time = time.time()
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            elapsed_time = time.time() - start_time

            if (
                "Reply from" in stdout.decode()
                or "reply from" in stdout.decode()
                or "bytes from" in stdout.decode().lower()
            ):
                self.device_status = True
                status_message = "Perangkat online"
                status = "success"
            else:
                self.device_status = False
                status_message = "Perangkat offline"
                status = "error"

            logging.info(
                "Status perangkat diperiksa untuk %s dalam %.2fs: %s",
                self.ip_address,
                elapsed_time,
                status_message,
            )
            return json.dumps({"message": status_message, "status": status})
        except Exception as e:
            error_message = f"Kesalahan: {e}"
            logging.error(
                "Kesalahan saat memeriksa status untuk %s: %s",
                self.ip_address,
                error_message,
            )
            return json.dumps({"message": error_message, "status": "error"})

    def check_device_status(self):
        """
        Mengecek status perangkat secara sinkron dengan menjalankan coroutine `check_device_status_async`
        menggunakan asyncio.run().
        """
        return asyncio.run(self.check_device_status_async())

    def render_template_config(self, jinja_template, yaml_params):
        """
        Merender template Jinja2 dengan parameter YAML.
        Mengembalikan konfigurasi yang telah dirender dalam format JSON.

        :param jinja_template: Template Jinja2 dalam format string.
        :param yaml_params: Parameter YAML yang akan digabungkan dengan template.
        :return: Konfigurasi yang telah dirender dalam format JSON.
        """
        try:
            yaml_params_dict = yaml.safe_load(yaml_params)
            template = Template(jinja_template)
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
        retries = 0
        while retries <= self.MAX_RETRIES:
            try:
                result_json = self.configure_device(command)
                result_dict = json.loads(result_json)

                if result_dict.get("status") == "success":
                    output = result_dict.get("message")
                    return json.dumps({"status": "success", "message": output})
                else:
                    error_message = result_dict.get("message")
                    logging.error(
                        "Konfigurasi gagal untuk %s: %s", self.ip_address, error_message
                    )
                    return json.dumps({"status": "error", "message": error_message})

            except (TimeoutError, socket.timeout):
                retries += 1
                if retries > self.MAX_RETRIES:
                    error_message = (
                        "Connection to device timed out after multiple attempts."
                    )
                    logging.error(
                        "Gagal menghubungi perangkat %s setelah %s percobaan: %s",
                        self.ip_address,
                        retries,
                        error_message,
                    )
                    return json.dumps({"status": "error", "message": error_message})
                else:
                    logging.warning(
                        "Percobaan ke-%s untuk menghubungi perangkat %s setelah timeout.",
                        retries,
                        self.ip_address,
                    )
                    time.sleep(self.RETRY_DELAY)

            except AuthenticationException:
                error_message = "Authentication failed. Please check your credentials."
                logging.error("Autentikasi gagal untuk perangkat %s", self.ip_address)
                return json.dumps({"status": "error", "message": error_message})

            except SSHException as e:
                error_message = f"SSH error occurred: {e}"
                logging.error("SSH error untuk perangkat %s: %s", self.ip_address, e)
                return json.dumps({"status": "error", "message": error_message})

            except json.JSONDecodeError as e:
                error_message = f"Kesalahan parsing JSON: {e}"
                logging.error(
                    "Kesalahan parsing JSON untuk perangkat %s: %s", self.ip_address, e
                )
                return json.dumps({"status": "error", "message": error_message})

            except Exception as e:
                error_message = f"Kesalahan tidak terduga: {e}"
                logging.error(
                    "Kesalahan tidak terduga saat mengonfigurasi perangkat %s: %s",
                    self.ip_address,
                    e,
                )
                return json.dumps({"status": "error", "message": error_message})
