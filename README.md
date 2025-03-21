# XNetManager
"Automate Engineer Workflow to Handle CPE"

XNetManager adalah aplikasi web berbasis Python yang dirancang untuk mengotomatisasi konfigurasi perangkat jaringan seperti Mikrotik, Fortinet, dan Cisco melalui SSH. Aplikasi ini menggunakan Docker untuk memudahkan proses deployment.

## Key Feature
- Automate Configuration with AI
- Templating Configuration
- AI Analytics for Improvinng Security and Availability
- Talita Chatbot with RAG Knowledge. Easy knowledge with PDF file.
- Backup and Configuration Rollback with Versioning
- User Collaboration
- Use Same tool instead many tool from each vendor.

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
services:
  xnetmanager:
    build:
      context: ./
      dockerfile: Dockerfile
    container_name: xnetmanager_flask
    volumes:
      - xnetmanager_backups:/var/www/data/backups
      - xnetmanager_configurations:/var/www/data/configurations
      - xnetmanager_templates:/var/www/data/templates
      - .env:/var/www/.env:ro
    env_file:
      - .env
    ports:
      - "8000:8000"
    command: ["/bin/sh", "-c", "./entrypoint.sh"]
    networks:
      - xnetmanager_bridge
    depends_on:
      - db
    restart: unless-stopped

  db:
    image: postgres:15
    container_name: xnetmanager_postgres
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    env_file:
      - .env
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - xnetmanager_bridge
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB} || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 5

  nginx:
    image: nginx:latest
    container_name: xnetmanager_nginx
    volumes:
      - ./src/static:/var/www/src/static
      - ./certbot/www:/var/www/certbot
      - ./certbot/conf:/etc/letsencrypt
      - ./default.conf:/etc/nginx/conf.d/default.conf:ro
    ports:
      - "80:80"
      - "443:443"
    networks:
      - xnetmanager_bridge
    depends_on:
      - xnetmanager
    restart: unless-stopped

  certbot:
    image: certbot/certbot
    container_name: certbot
    volumes:
      - ./certbot/www:/var/www/certbot
      - ./certbot/conf:/etc/letsencrypt
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do sleep 1; done'"
    networks:
      - xnetmanager_bridge

  cloudflared:
    image: cloudflare/cloudflared:latest
    container_name: xnetmanager_cloudflared
    command: tunnel --no-autoupdate run --token ${CLOUDFLARED_TOKEN}
    env_file:
      - .env
    networks:
      - xnetmanager_bridge
    restart: unless-stopped

volumes:
  postgres_data:
  xnetmanager_backups:
  xnetmanager_configurations:
  xnetmanager_templates:

networks:
  xnetmanager_bridge:
    driver: bridge
```

- Run Command:
```docker compose
docker compose up -d
```

- Akses Web Interface:
```web access
http://ip-address-dockerhost:8000
```
default username: `xnetmanager@example.com`
default password: `xnetmanager`

done!
Salam [Decki Okmal Pratama]
