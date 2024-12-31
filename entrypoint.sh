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

# Lanjutkan dengan migrasi dan upgrade
echo "Menjalankan 'flask db migrate' dan 'flask db upgrade'..."
flask db migrate -m "Initial Migration"
flask db upgrade

# Jalankan skrip inisialisasi database
echo "Menjalankan inisialisasi data awal dengan db_init.py..."
python db_init.py

# Mulai aplikasi menggunakan Gunicorn
echo "Memulai aplikasi XnetManager dengan Gunicorn..."
exec gunicorn --bind 0.0.0.0:8000 --workers 4 manage:app
