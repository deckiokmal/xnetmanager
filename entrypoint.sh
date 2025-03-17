#!/bin/bash
# Entrypoint script for initial database setup and application start

# Tunggu hingga PostgreSQL siap
until pg_isready -h db -U ${POSTGRES_USER}; do
    echo "Waiting for PostgreSQL to be ready..."
    sleep 2
done

echo "Memulai proses inisialisasi dan aplikasi XnetManager..."

# Jalankan migrasi database
if [ ! -d "/var/www/migrations" ]; then
    echo "Direktori migrations tidak ditemukan. Menjalankan 'flask db init'..."
    flask db init
else
    echo "Direktori migrations ditemukan. Melewati 'flask db init'."
fi

#! Inisialisasi Database
echo "DB Initialization..."
flask db init
#! Lanjutkan dengan migrasi dan upgrade
echo "Menjalankan 'flask db migrate' dan 'flask db upgrade'..."
flask db migrate -m "Initial Migration"
flask db upgrade

# Mulai aplikasi menggunakan Gunicorn
echo "Memulai aplikasi XnetManager dengan Gunicorn..."
exec gunicorn --bind 0.0.0.0:8000 --workers 4 run:app
