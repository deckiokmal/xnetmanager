# XNetManager

XNetManager adalah aplikasi web berbasis Python yang dirancang untuk mengotomatisasi konfigurasi perangkat jaringan seperti Mikrotik, Fortinet, dan Cisco melalui SSH. Aplikasi ini menggunakan Docker untuk memudahkan proses deployment.

## Fitur Utama
- Otomatisasi konfigurasi perangkat jaringan
- Dukungan untuk berbagai vendor (Mikrotik, Fortinet, Cisco)
- Antarmuka web yang user-friendly
- Multi-Factor Authentication (MFA) dengan Google Authenticator
- Pengelolaan hak akses untuk pengguna administrator
- Pemantauan status perangkat dengan ping utilities

## Aplication Stack
- Flask
- SQLAlchemy
- PostgreSQL
- Bootstrap 5
- Font Awesome Kit
- Google Font

## Persyaratan
- Docker dan Docker Compose terinstal di sistem Anda
- Git untuk mengakses repositori

## Deployment dengan docker-compose
docker-compose
```docker-compose.yml
version: '3'

services:
  xnetmanager:
    image: deckyokmal177/xnetmanager:latest
    ports:
      - "8008:80"
    restart: always
    networks:
      - frontend_l3  # Sesuaikan dengan nama jaringan yang diperlukan
    dns:
      - 8.8.8.8  # DNS server yang diinginkan

networks:
  frontend_l3:
    driver: ipvlan
    ipam:
      driver: default
      config:
        - subnet: 10.0.210.0/24  # Sesuaikan subnet dengan yang diperlukan, jika perlu
```

## Langkah-Langkah Manual Docker Image

### 1. Buat Dockerfile
Buat file `Dockerfile` dengan konten berikut:

```dockerfile
# Base image
FROM python:3.9-slim

# Install Nginx dan git
RUN apt-get update && \
    apt-get install -y nginx git iputils-ping

# Clone repository from GitHub
RUN git clone https://github.com/deckiokmal/xnetmanager.git /app

# Install Python dependencies
WORKDIR /app
RUN pip install -r requirements.txt

# Configure Nginx
RUN echo "server { \
    listen 80; \
    server_name localhost; \
    location / { \
        proxy_pass http://localhost:5000; \
        proxy_set_header Host \$host; \
        proxy_set_header X-Real-IP \$remote_addr; \
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; \
        proxy_set_header X-Forwarded-Proto \$scheme; \
    } \
}" > /etc/nginx/sites-available/default

# Install ping utils
RUN apt-get install -y iputils-ping

# Expose ports
EXPOSE 80

# Start Nginx and Flask application
CMD service nginx start && flask run --host=0.0.0.0 --port=5000
```

### 2. Build Docker Image
Bangun image Docker dengan perintah berikut:
```docker build
sudo docker build -t xnetmanager:latest .
```

### 3. Jalankan Kontainer Docker
- Jalankan kontainer dengan perintah berikut:
```docker run
sudo docker run -d -p 8008:80 --name xnetmanager --restart=always xnetmanager:latest
```

- Konfigurasi DNS Server pada Docker image:
```DNS
sudo docker exec -it xnetmanager bin/sh
echo "nameserver 8.8.8.8" > /etc/resolv.conf
```

### 4. (Opsional) Buat Jaringan Docker
Jika Anda memerlukan konfigurasi jaringan khusus, buat jaringan Docker dengan perintah berikut:
```docker network
sudo docker network create -d ipvlan --subnet 10.0.210.0/24 -o parent=ens18 -o ipvlan_mode=l3 frontend_l3
```

### 5. Testing
- Anda dapat menguji konektivitas dan ping dari dalam kontainer:
```docker ping
docker exec xnetmanager ping 8.8.8.8
```
- Akses Web Interface:
```web access
http://ip-address-dockerhost:8008
```
default username: `Adminx`
default password: `adminx`

## Jika perlu menginstal ulang, jalankan:
```
sudo docker exec -it xnetmanager apt-get update
sudo docker exec -it xnetmanager apt-get install -y iputils-ping
```

done!
Salam [Decki Okmal Pratama]
