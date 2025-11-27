#!/bin/bash
set -e

# Environment variables
LOG_OUTPUT_DIR="${LOG_OUTPUT_DIR:-/app/data}"
LOG_FILENAME="${LOG_FILENAME:-linux_logs.log}"
ANOMALY_RATE="${ANOMALY_RATE:-0.05}"

# Output path creation
OUTPUT_PATH="${LOG_OUTPUT_DIR}/${LOG_FILENAME}"

mkdir -p "${LOG_OUTPUT_DIR}"
echo "Output directory: ${LOG_OUTPUT_DIR}"
echo "Output file: ${OUTPUT_PATH}"
echo "Anomaly rate: ${ANOMALY_RATE}"

# Run the generator
echo "Starting the generator..."
exec python3 linux_generator.py -o "${OUTPUT_PATH}" -r "${ANOMALY_RATE}"
