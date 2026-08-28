FROM python:3.12-slim

WORKDIR /app

# System dependencies (if needed for bcrypt/cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Hardening: container does NOT run as root.
# UID 1001: adjust the host directory of ./data once if necessary:
#   chown -R 1001:1001 data/
RUN useradd --system --uid 1001 --no-create-home appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
