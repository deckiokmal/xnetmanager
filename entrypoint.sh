#!/bin/bash
# Entrypoint script for initial database setup and application start

# Tunggu hingga PostgreSQL siap
until pg_isready -h db -U ${POSTGRES_USER}; do
    echo "Waiting for PostgreSQL to be ready..."
    sleep 2
done

echo "Memulai proses inisialisasi dan aplikasi XnetManager..."

#! Inisialisasi Database
echo "DB Initialization..."
flask db init

#! Lanjutkan dengan migrasi dan upgrade
echo "Menjalankan 'flask db migrate' dan 'flask db upgrade'..."
flask db migrate -m "Initial Migration"
flask db upgrade

#! Menjalankan inisialisasi database tambahan dari db_init.py
echo "Menjalankan inisialisasi database dengan db_init.py..."
python src/db_init.py

# Mulai aplikasi menggunakan Gunicorn
echo "Memulai aplikasi XnetManager dengan Gunicorn..."
exec gunicorn --bind 0.0.0.0:8000 --workers 4 run:app
