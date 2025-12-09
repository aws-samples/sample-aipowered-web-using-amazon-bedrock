FROM --platform=linux/amd64 public.ecr.aws/docker/library/python:3.12-slim

# Set security labels
LABEL maintainer="Customer Support AI Team"
LABEL security.scan="enabled"

# Expose port
EXPOSE 8501

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt ./requirements.txt

# Install Python dependencies with security optimizations
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# Install system dependencies with proper cleanup
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* /var/tmp/*

# Copy application files
COPY *.py ./
COPY components ./components
COPY pages ./pages

# Create non-root user with specific UID for security
RUN useradd -u 8877 -r -s /bin/false demouser && \
    chown -R demouser:demouser /app && \
    chmod -R 755 /app

# Switch to non-root user
USER demouser

# Health check for container monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["curl", "-f", "http://localhost:8501/_stcore/health"]

# Run application with security settings
CMD ["streamlit", "run", "Home.py", \
    "--server.headless", "true", \
    "--browser.serverAddress=0.0.0.0", \
    "--server.enableCORS", "false", \
    "--browser.gatherUsageStats", "false", \
    "--server.enableXsrfProtection", "true", \
    "--server.enableWebsocketCompression", "false"]