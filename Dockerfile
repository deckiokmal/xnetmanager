FROM python:3.9-slim

ENV CONTAINER_HOME=/var/www

ADD . ${CONTAINER_HOME}
WORKDIR ${CONTAINER_HOME}

RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r ${CONTAINER_HOME}/requirements.txt

EXPOSE 8000