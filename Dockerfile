FROM python:3.10-slim

WORKDIR /app

# Install required packages
RUN apt-get update && apt-get install -y \
    tk \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY *.py .
COPY config .
COPY src/ ./src/

# Create necessary directories
RUN mkdir -p keys
RUN mkdir -p data/encrypted
RUN mkdir -p data/decrypted
RUN mkdir -p data/signatures
RUN mkdir -p logs

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the application with the launcher
CMD ["python", "main.py", "--launcher"]