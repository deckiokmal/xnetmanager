# Deployment xnetmanager in Production Server

## 1. Setup Server:
Pastikan server Ubuntu 22.04 sudah terpasang Docker dan Docker Compose.
```sh
sudo apt install docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker
```

## 2. Clone Repository dari Github:
Clone Repository public anda ke server.
```sh
git clone https://github.com/deckiokmal/xnetmanager.git
cd xnetmanager
```

## 3. Setup python Virtual Environment (Optional, untuk local development):
- Buat virtual environment dan aktifkan.
```sh
python3 -m venv venv
source venv/bin/activate
```

## 4. Install dependencies (Optional, untuk local development):
```sh
pip install -r requirements.txt
```

## 5. Setup .env File:
- Buat file .env dan tambahkan variable lingkungan yang diperlukan (pastikan file ini tidak di commit ke repository menggunakan .gitignore)
```sh
touch .env
echo 'SECRET_KEY=mysupersecretkey
DATABASE_URL=sqlite:///xnetmanager.sqlite
APP_NAME=XNETMANAGER
BCRYPT_LOG_ROUNDS=13
CONFIG_NAME=Development
FLASK_APP=manage.py
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your email username
MAIL_PASSWORD=your email password
MAIL_USE_TLS=True
MAIL_USE_SSL=False

sudo chmod 600 .env
```

## 6. Setup manage.py untuk WSGI (Web Server Gateway Interface):
pastikan file manage.py menginisiasi aplikasi flask.
```sh
from flask_script import Manager
from flask_migrate import Migrate, MigrateComand
from app import create_app, db

app = create_app()
migrate = Migrate(app,db)
manager = Manager(app)

manager.add_command('db',MigrateCommand)

if __name__ == "__main__":
    manager.run()
```

## 7. Setup Dockerfile


## 8. Setup PostgreSQL di Docker:


## 9. Setup Nginx

## 10. Setup HTTPS

## 11. Jalankan Docker Compose (HTTP)

## 12. Setup keamanan tambahan

## 13. Monitor dan Logging

## 14. Update .env untuk menggunakan HTTPS

## 15. Setup CI/CD (Optional):
GUnakan platform CI/CD seperti Github Actions untuk otomatisasi build dan deployment atau gunakan Jenkins, Terraform dan Ansible.