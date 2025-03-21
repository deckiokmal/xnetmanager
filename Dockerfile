FROM python:3.12

# Set environment variable
ENV CONTAINER_HOME=/var/www

# Copy aplikasi ke dalam container
COPY . ${CONTAINER_HOME}
WORKDIR ${CONTAINER_HOME}

# Install dependencies yang diperlukan
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping postgresql-client libpq-dev build-essential && \
    rm -rf /var/lib/apt/lists/*

# Install library Python
RUN pip install --no-cache-dir -r ${CONTAINER_HOME}/requirements.txt

# Pastikan entrypoint bisa dieksekusi
RUN chmod +x entrypoint.sh

# Tentukan variabel lingkungan default untuk Flask
ENV CONFIG_NAME=Production

EXPOSE 8000
RUN echo "All xnetmanager build successfully!"
