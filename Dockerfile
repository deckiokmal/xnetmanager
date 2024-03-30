# Base image
FROM python:3.9-slim

# Install Nginx
RUN apt-get update && \
    apt-get install -y nginx

# Install git
RUN apt-get install -y git

# Set your GitHub username and Personal Access Token (PAT)
ARG GITHUB_USERNAME
ARG GITHUB_PAT

# Clone repository from GitHub
RUN git clone https://${GITHUB_USERNAME}:${GITHUB_PAT}@github.com/deckiokmal/xnetmanager.git /app

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

# Expose ports
EXPOSE 80

# Start Nginx and Flask application
CMD service nginx start && flask run --host=0.0.0.0 --port=5000
