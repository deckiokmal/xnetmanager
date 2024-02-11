from app import app
import os
import sys


# Jalur ke directory app
project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "app"))

# Tambahkan jalur proyek ke sys.path
sys.path.insert(0, project_dir)

# flask run -- debug di http port 80
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
