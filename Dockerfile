# -------------------------------------------------------
# Mr.Robots — AI Governance Gateway
# Multi-stage build for a lean production image
# -------------------------------------------------------

# Stage 1: base image
FROM python:3.11-slim AS base

# Set working directory
WORKDIR /app

# Prevent Python from writing .pyc files and enable stdout logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------
# Stage 2: dependencies
# -------------------------------------------------------
FROM base AS dependencies

# Copy only requirements first (better Docker layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Pre-download the ML model so the container doesn't need internet at runtime
RUN python -c "\
from transformers import pipeline; \
pipeline('zero-shot-classification', model='cross-encoder/nli-distilroberta-base'); \
print('ML model cached successfully.')"

# -------------------------------------------------------
# Stage 3: final image
# -------------------------------------------------------
FROM dependencies AS final

# Copy project source code
COPY gateway/     ./gateway/
COPY providers/   ./providers/
COPY ml/          ./ml/
COPY policies/    ./policies/
COPY config.py    .
COPY static/      ./static/

# Create logs directory
RUN mkdir -p logs

# Expose the API port
EXPOSE 8000

# Health check — Docker will monitor this endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start the server
CMD ["python", "-m", "uvicorn", "gateway.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1"]
