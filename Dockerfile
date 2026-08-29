# Multi-stage secure Dockerfile for BugScout Autonomous Platform
FROM python:3.11-slim as base

# Security settings: non-root user and environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Create non-privileged user and output directories
RUN useradd -m -u 1000 bugscout && \
    mkdir -p /app/outputs && \
    chown -R bugscout:bugscout /app

USER bugscout

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
