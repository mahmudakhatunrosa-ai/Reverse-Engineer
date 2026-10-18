# HexStrike AI FastMCP Server Dockerfile
# Optimized for Render (Web Service / Background Service) & 24/7 Hosting

FROM python:3.11-slim

# Prevent Python from writing .pyc and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install system utilities & reverse engineering binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    binutils \
    file \
    radare2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Render dynamically binds the PORT environment variable
EXPOSE ${PORT}

# Healthcheck for container orchestrators
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Start FastMCP server via Uvicorn
CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT}"]
