FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    netcat-openbsd \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Add vulnerable application and scripts
ADD vulnerable_app.py /app/vulnerable_app.py
ADD generate_payload.py /app/generate_payload.py
ADD test_reverse_shell.sh /app/test_reverse_shell.sh

# Make scripts executable
RUN chmod +x /app/vulnerable_app.py /app/generate_payload.py /app/test_reverse_shell.sh

# Expose port
EXPOSE 8080

# Set the default command
CMD ["python3", "/app/vulnerable_app.py"] 