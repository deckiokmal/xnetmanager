Langkah:

1. Setup UV environment dan Install Dependencies 'requirements-dev.txt'
    ```bash
    uv init
    uv venv
    uv pip install -r requirements-dev.txt
    ```

2. Setup Database PostgreSQL 'Docker Container'
    ```docker compose
    services:
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
    ```
    Jalankan container:
    ```bash
    docker compose up -d
    ```

3. Migrasi database dan Setup .env file
    - Migrasi database:
        ```bash
        flask db init
        flask db migrate -m "Inisiasi db pertama"
        flask db upgrade
        ```

    - .env File:
        1. Atur lingkungan 'Production' atau 'Development'
        2. API Key
        3. Database

4. Jalankan scripts db_init.py
5. Jalankan run.py