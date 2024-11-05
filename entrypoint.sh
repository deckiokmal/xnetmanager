#!/bin/bash
# Entrypoint script for initial database setup and application start

# Jalankan inisialisasi database jika belum ada
if [ ! -f "/instance/xnetmanager.sqlite" ]; then
    echo "Database belum ada, memulai inisialisasi database..."

    # Cek apakah direktori migrations ada atau tidak
    if [ ! -d "/var/www/migrations" ]; then
        echo "Direktori migrations tidak ada, menjalankan flask db init..."
        flask db init
    else
        echo "Direktori migrations sudah ada, melewati flask db init."
    fi

    # Lanjutkan dengan migrasi dan upgrade
    flask db migrate -m "Initial Migration"
    flask db upgrade
    python db_init.py
else
    echo "Database sudah ada, melewati inisialisasi."
fi

# Mulai aplikasi dengan Gunicorn
exec gunicorn --bind 0.0.0.0:8000 --workers 4 manage:app
