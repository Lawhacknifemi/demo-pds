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

# Create a non-root user
RUN useradd -m appuser
RUN chown -R appuser:appuser /app
USER appuser

# Create a startup script
RUN echo '#!/bin/bash\n\
# Check if we need to create identity\n\
if [ ! -f "private.key" ] || ! grep -q "DID_PLC" config.js; then\n\
    echo "Creating new identity..."\n\
    # Run create_did.js and capture the DID\n\
    DID=$(node create_did.js | grep "Generated DID:" | cut -d" " -f3)\n\
    if [ -n "$DID" ]; then\n\
        echo "Updating config.js with DID: $DID"\n\
        # Update config.js with the new DID\n\
        sed -i "s/DID_PLC = .*/DID_PLC = \"$DID\";/" config.js\n\
    else\n\
        echo "Failed to create identity"\n\
        exit 1\n\
    fi\n\
else\n\
    echo "Using existing identity..."\n\
fi\n\
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