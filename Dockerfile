FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Run setup (download NIST CSV + build RAG index)
# This bakes the index into the image — faster cold starts on Render
RUN python setup.py

# Expose port
EXPOSE 8000

# Start FastAPI server using the PORT environment variable injected by Render (fallback to 8000)
CMD uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1
