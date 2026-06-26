FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libglib2.0-0 \
        libgl1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel/ ./sentinel/
COPY samples/ ./samples/
COPY tools/ ./tools/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV SENTINEL_DATA_DIR=/data \
    SENTINEL_EVENTS=/data/live_events.ndjson \
    SENTINEL_DB=/data/matches.db \
    SENTINEL_KILLCAMS=/data/killcams \
    PYTHONUNBUFFERED=1

RUN mkdir -p /data/killcams && touch /data/live_events.ndjson

VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
CMD ["automated"]
