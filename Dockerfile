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
RUN chown -R appuser:appuser /app
USER appuser

# Create a startup script that uses our specific config
RUN echo '#!/bin/bash\n\
# Ensure config.js exists with our specific DID\n\
if [ ! -f "config.js" ]; then\n\
    echo "Error: config.js is missing"\n\
    exit 1\n\
fi\n\
\n\
# Start the PDS\n\
exec node pds.js' > /app/start.sh && \
chmod +x /app/start.sh

# Expose the port the app runs on
EXPOSE 31337

# Command to run the application
CMD ["/app/start.sh"] 