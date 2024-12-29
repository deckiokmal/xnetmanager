FROM python:3.9-slim

ENV CONTAINER_HOME=/var/www

RUN echo "Copy all data to /var/www"
COPY . ${CONTAINER_HOME}
WORKDIR ${CONTAINER_HOME}

RUN echo "System update & Dependency"
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping postgresql-client && \
    rm -rf /var/lib/apt/lists/*

RUN echo "Install all Python library"
RUN pip install --no-cache-dir -r ${CONTAINER_HOME}/requirements.txt

# Pastikan file entrypoint memiliki izin eksekusi
RUN chmod +x entrypoint.sh

# Tentukan variabel lingkungan default untuk Flask
ENV CONFIG_NAME Production

EXPOSE 8000
RUN echo "All xnetmanager build  successfully!"
