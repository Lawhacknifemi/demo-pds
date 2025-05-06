FROM node:18

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    python3 \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create data directory for SQLite database with appropriate permissions
RUN mkdir -p /data && chmod 777 /data
VOLUME /data

# Copy package.json first to leverage Docker cache
COPY package.json ./

# Install all dependencies except sqlite3
RUN npm install --no-save
RUN npm uninstall sqlite3 --no-save || true

# Install better-sqlite3 as an alternative
RUN npm install --no-save better-sqlite3

# Copy all project files
COPY . .

# Create a SQLite3 compatibility wrapper for better-sqlite3
RUN echo "// SQLite3 compatibility wrapper for better-sqlite3\n\
import BetterSQLite3 from 'better-sqlite3';\n\
\n\
class Database {\n\
  constructor(filename, mode, callback) {\n\
    this.db = new BetterSQLite3(filename, { fileMustExist: false });\n\
    if (callback) callback(null);\n\
  }\n\
\n\
  run(sql, params, callback) {\n\
    try {\n\
      const stmt = this.db.prepare(sql);\n\
      const result = stmt.run(params);\n\
      if (callback) callback(null, result);\n\
      return this;\n\
    } catch (err) {\n\
      if (callback) callback(err);\n\
      return this;\n\
    }\n\
  }\n\
\n\
  get(sql, params, callback) {\n\
    try {\n\
      const stmt = this.db.prepare(sql);\n\
      const row = stmt.get(params);\n\
      if (callback) callback(null, row);\n\
      return this;\n\
    } catch (err) {\n\
      if (callback) callback(err);\n\
      return this;\n\
    }\n\
  }\n\
\n\
  all(sql, params, callback) {\n\
    try {\n\
      const stmt = this.db.prepare(sql);\n\
      const rows = stmt.all(params);\n\
      if (callback) callback(null, rows);\n\
      return this;\n\
    } catch (err) {\n\
      if (callback) callback(err);\n\
      return this;\n\
    }\n\
  }\n\
\n\
  each(sql, params, callback, completeFn) {\n\
    try {\n\
      const stmt = this.db.prepare(sql);\n\
      let rows = [];\n\
      if (typeof params === 'function') {\n\
        completeFn = callback;\n\
        callback = params;\n\
        rows = stmt.all([]);\n\
      } else {\n\
        rows = stmt.all(params);\n\
      }\n\
      for (const row of rows) {\n\
        callback(null, row);\n\
      }\n\
      if (completeFn) completeFn(null, rows.length);\n\
      return this;\n\
    } catch (err) {\n\
      if (callback) callback(err);\n\
      if (completeFn) completeFn(err);\n\
      return this;\n\
    }\n\
  }\n\
\n\
  exec(sql, callback) {\n\
    try {\n\
      this.db.exec(sql);\n\
      if (callback) callback(null);\n\
      return this;\n\
    } catch (err) {\n\
      if (callback) callback(err);\n\
      return this;\n\
    }\n\
  }\n\
\n\
  serialize(callback) {\n\
    // better-sqlite3 is already serialized\n\
    if (callback) callback();\n\
    return this;\n\
  }\n\
\n\
  parallelize(callback) {\n\
    // better-sqlite3 doesn't support parallelization in the same way, this is a no-op\n\
    if (callback) callback();\n\
    return this;\n\
  }\n\
\n\
  close(callback) {\n\
    try {\n\
      this.db.close();\n\
      if (callback) callback(null);\n\
    } catch (err) {\n\
      if (callback) callback(err);\n\
    }\n\
  }\n\
}\n\
\n\
export default { Database };" > /app/sqlite3-wrapper.js

# Patch repo.js to use our compatibility wrapper
RUN sed -i "s/import sqlite3 from 'sqlite3';/import sqlite3 from '.\/sqlite3-wrapper.js';/" repo.js

# Modify pds.js to listen on all interfaces
RUN sed -i "s/app\.listen(PORT, '127.0.0.1'/app.listen(PORT, '0.0.0.0'/" pds.js

# Create a startup script
RUN echo '#!/bin/bash\n\
# Link database if it exists in volume\n\
if [ -f "/data/repo.db" ]; then\n\
    ln -sf /data/repo.db /app/repo.db\n\
elif [ -f "/app/repo.db" ]; then\n\
    cp -f /app/repo.db /data/\n\
fi\n\
\n\
# Link private key if it exists in volume\n\
if [ -f "/data/private.key" ]; then\n\
    ln -sf /data/private.key /app/private.key\n\
elif [ -f "/app/private.key" ]; then\n\
    cp -f /app/private.key /data/\n\
fi\n\
\n\
# Check if we need to create identity\n\
if [ ! -f "private.key" ] || ! grep -q "DID_PLC" config.js; then\n\
    echo "Creating new identity..."\n\
    # Run create_did.js and capture the DID\n\
    DID=$(node create_did.js 2>&1 | grep "Generated DID:" | cut -d" " -f3)\n\
    if [ -n "$DID" ]; then\n\
        echo "Updating config.js with DID: $DID"\n\
        # Update config.js with the new DID\n\
        sed -i "s/const DID_PLC = .*/const DID_PLC = \"$DID\";/" config.js\n\
        # Copy to data volume for persistence\n\
        cp -f private.key /data/\n\
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