# ==============================================================================
# BugScout: LLM-Guided Multi-Agent Security Testing Platform
# Production-Grade Container Image (Python 3.11-slim)
# ==============================================================================

FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered streaming logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies (git for commit hashing, curl for health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies first for caching optimization
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy complete project source
COPY . .

# Create non-root user for secure container execution
RUN useradd -m -u 1001 scout && \
    mkdir -p /app/outputs && \
    chown -R scout:scout /app

USER scout

# Expose ports for Benchmark Lab (8888) and Hidden Lab (8899)
EXPOSE 8888 8899

# Default entrypoint
ENTRYPOINT ["python", "main.py"]
CMD ["--demo"]
