FROM python:3.11-slim

WORKDIR /app

COPY linux_generator.py .
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh && \
    mkdir -p /app/data && \
    chmod -R 777 /app/data

# Default env variables
ENV LOG_OUTPUT_DIR=/app/data \
    LOG_FILENAME=linux_logs.log \
    ANOMALY_RATE=0.05

ENTRYPOINT ["./entrypoint.sh"]