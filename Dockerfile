# Use Node.js LTS version
FROM node:20-slim

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy all project files
COPY . .

# Create data directory for persistent storage
RUN mkdir -p /data

# Create a non-root user
RUN useradd -m appuser
RUN chown -R appuser:appuser /app /data
USER appuser

# Create a startup script
RUN echo '#!/bin/bash\n\
# Check if we need to create identity\n\
if [ ! -f "/data/private.key" ] && [ ! -f "private.key" ]; then\n\
    echo "Creating new identity..."\n\
    # Run create_did.js and capture the DID\n\
    DID=$(node create_did.js | grep "Generated DID:" | cut -d" " -f3)\n\
    if [ -n "$DID" ]; then\n\
        echo "Generated DID: $DID"\n\
        echo "Please update config.js manually with this DID"\n\
        # Move private key to volume\n\
        mv private.key /data/\n\
    else\n\
        echo "Failed to create identity"\n\
        exit 1\n\
    fi\n\
else\n\
    echo "Using existing identity..."\n\
    # If private.key exists in root but not in /data, move it\n\
    if [ -f "private.key" ] && [ ! -f "/data/private.key" ]; then\n\
        mv private.key /data/\n\
    fi\n\
fi\n\
\n\
# Always ensure private.key is in the correct location\n\
cp /data/private.key .\n\
\n\
# Modify pds.js to listen on all interfaces\n\
sed -i "s/app\.listen(PORT, .127.0.0.1./app.listen(PORT, .0.0.0.0./" pds.js\n\
\n\
# Start the PDS\n\
exec node pds.js' > /app/start.sh && \
chmod +x /app/start.sh

# Expose the port the app runs on
EXPOSE 31337

# Command to run the application
CMD ["/app/start.sh"] 