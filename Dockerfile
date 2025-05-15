# Use Node.js LTS version with slim variant
FROM node:20-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json .

# Install dependencies
RUN npm install

# Copy all project files
COPY . .

# Create a non-root user
RUN useradd -m appuser
RUN chown -R appuser:appuser /app
USER appuser

# Create a startup script
RUN echo '#!/bin/bash\n\
# Check if we need to create identity\n\
if [ ! -f "privkey.pem" ] || ! grep -q "DID_PLC" config.js; then\n\
    echo "Creating new identity..."\n\
    # Run create_identity.js and capture the DID\n\
    DID=$(node create_identity.js | grep "Created DID:" | cut -d" " -f3)\n\
    if [ -n "$DID" ]; then\n\
        echo "Updating config.js with DID: $DID"\n\
        # Update config.js with the new DID\n\
        sed -i "s/DID_PLC = .*/DID_PLC = \"$DID\";/" config.js\n\
        # Run request_crawl.js after successful identity creation\n\
        node request_crawl.js\n\
    else\n\
        echo "Failed to create identity"\n\
        exit 1\n\
    fi\n\
else\n\
    echo "Using existing identity..."\n\
fi\n\
\n\
# Start the PDS\n\
exec node pds.js' > /app/start.sh && \
chmod +x /app/start.sh

# Expose the port the app runs on
EXPOSE 31337

# Command to run the application
CMD ["/app/start.sh"] 