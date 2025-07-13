# Use Node.js LTS version with slim variant
FROM node:20-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy all project files
COPY . .

# Create a non-root user
RUN useradd -m appuser

# Set proper permissions
RUN chown -R appuser:appuser /app && \
    chmod -R 755 /app && \
    chmod 644 /app/*.js && \
    chmod 644 /app/*.json

USER appuser

# Simple startup script: just run the PDS
RUN echo '#!/bin/bash\necho "Starting PDS..."\nexec node pds.js' > /app/start.sh && \
chmod +x /app/start.sh

# Expose the port the app runs on
EXPOSE 31337

# Command to run the application
CMD ["/app/start.sh"] 