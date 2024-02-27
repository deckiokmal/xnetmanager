# Deployment XNETMANAGER

### Requirements
- Linux ubuntu 22.04
- Python3
- Python3 PIP
- Nginx
## Update dan Upgrade Repo
```bash
sudo apt update && sudo apt upgrade -y
```
## Step 1 — Installing the Components from the Ubuntu Repositories
```bash
sudo apt install python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools
```
## Step 2 — Creating a Python Virtual Environment
```bash
sudo apt install python3-venv
```
Next, clone git repository to your linux machine
```bash
sudo git clone https://github.com/deckiokmal/xnetmanager.git
```
move xnetmanager directory to `/var/www/`:
```bash
sudo mv xnetmanager/ /var/www/
cd /var/www/xnetmanager/
```
create virtual enviroment:
```bash
python3 -m venv venv
source venv/bin/activate
```
Install python library:
```bash
sudo pip install -r requirements.txt
```
## Step 4 — Configuring Gunicorn
Install `gunicorn`:
```bash
sudo pip install gunicorn
```
Testing gunicorn and makesure that running well.
```bash
gunicorn --bind 0.0.0.0:5000 wsgi:app
```
```bash
Output
[2020-05-20 14:13:00 +0000] [46419] [INFO] Starting gunicorn 20.0.4
[2020-05-20 14:13:00 +0000] [46419] [INFO] Listening at: http://0.0.0.0:5000 (46419)
[2020-05-20 14:13:00 +0000] [46419] [INFO] Using worker: sync
[2020-05-20 14:13:00 +0000] [46421] [INFO] Booting worker with pid: 46421
```
Visit xnetmanager server IP Address:
```bash
http://127.0.0.1:5000
```
When you are done using the virtual environment, you can deactivate it:
```bash
deactivate
```
Next, create the systemd service unit file. Creating a systemd unit file will allow Ubuntu’s init system to automatically start Gunicorn and serve the Flask application whenever the server boots.
```bash
sudo nano /etc/systemd/system/xnetmanager.service
```
xnetmanager.service
```bash
[Unit]
Description=XNetManager Flask App
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=/var/www/xnetmanager
Environment="PATH=/var/www/xnetmanager/venv/bin"
ExecStart=/usr/local/bin/gunicorn --workers 10 --bind unix:exnetmanager.sock -m 007 wsgi:app

[Install]
WantedBy=multi-user.target
```
You can now start the Gunicorn service that you created and enable it so that it starts at boot:
```bash
sudo systemctl start xnetmanager
sudo systemctl enable xnetmanager
```
Let’s check the status:
```bash
sudo systemctl status xnetmanager
```
```bash
[output]

xnetmanager.service - XNetManager Flask App
     Loaded: loaded (/etc/systemd/system/xnetmanager.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2024-02-27 23:24:54 WIB; 53min ago
   Main PID: 4106 (gunicorn)
      Tasks: 4 (limit: 2220)
     Memory: 159.5M
        CPU: 1.570s
     CGroup: /system.slice/xnetmanager.service
             ├─4106 /usr/bin/python3 /usr/local/bin/gunicorn --workers 3 --bind unix:/var/www/xnetmanager/xnetmanage>
             ├─4107 /usr/bin/python3 /usr/local/bin/gunicorn --workers 3 --bind unix:/var/www/xnetmanager/xnetmanage>
             ├─4108 /usr/bin/python3 /usr/local/bin/gunicorn --workers 3 --bind unix:/var/www/xnetmanager/xnetmanage>
             └─4109 /usr/bin/python3 /usr/local/bin/gunicorn --workers 3 --bind unix:/var/www/xnetmanager/xnetmanage>
```
## Step 5 — Configuring Nginx to Proxy Requests
Begin by creating a new server block configuration file in Nginx’s sites-available directory
```bash
sudo nano /etc/nginx/sites-available/xnetmanager
```
/etc/nginx/sites-available/xnetmanager
```bash
server {
    listen 80;
    server_name xnetmanager.dopnetindo.com www.xnetmanager.dopnetindo.com;

    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/xnetmanager/xnetmanager.sock;
    }
}
```
give nginx access to .sock file:
```bash
sudo chmod 777 /var/www/xnetmanager/xnetmanager.sock
```
To enable the Nginx server block configuration you’ve just created, link the file to the sites-enabled directory:
```bash
sudo ln -s /etc/nginx/sites-available/xnetmanager /etc/nginx/sites-enabled
```
