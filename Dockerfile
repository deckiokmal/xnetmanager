# Gunakan base image yang ringan
FROM python:3.9-slim

# Install dependency dasar
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ping \
    dnsutils \
    nginx && \
    rm -rf /var/lib/apt/lists/*

# Set workdir di dalam container
WORKDIR /app/src

# Copy semua file yang diperlukan
COPY . /app

# Install dependency Python
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy file konfigurasi Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# Buat direktori untuk menyimpan file persisten
RUN mkdir -p /app/data/backups /app/data/configurations /app/data/templates && \
    chown -R www-data:www-data /app/data

# Ubah permission untuk keamanan
RUN chmod 600 /app/.env

# Jalankan Nginx dan aplikasi Flask
CMD ["sh", "-c", "nginx && python manage.py"]
