# PDS Demo - AT Protocol Personal Data Server in JavaScript

This is a basic demonstration of an AT Protocol Personal Data Server (PDS) implemented in pure JavaScript. The goal of this project is to provide a clear, educational implementation that helps developers understand how PDS works in the AT Protocol ecosystem.

## Overview

This PDS implementation provides a single-user instance that hosts a repository following the AT Protocol specification. It's designed to be a learning resource for understanding the core concepts of PDS implementation.

## Features

### Core Functionality
- ✅ DID (Decentralized Identifier) management
- ✅ Repository management with Merkle Search Tree (MST)
- ✅ Record creation, deletion, and retrieval
- ✅ Blob storage and retrieval
- ✅ JWT-based authentication
- ✅ Handle resolution
- ✅ Repository synchronization

### Available Endpoints

1. **Basic Endpoints**
   - `GET /` - Returns a greeting message
   - `GET /.well-known/atproto-did` - Returns the server's DID
   - `GET /xrpc/com.atproto.server.describeServer` - Returns server capabilities

2. **Authentication**
   - `POST /xrpc/com.atproto.server.createSession` - Creates a new session
   - `GET /xrpc/com.atproto.server.getSession` - Gets current session info

3. **Identity**
   - `GET /xrpc/com.atproto.identity.resolveHandle` - Resolves handles to DIDs

4. **Repository Operations**
   - `GET /xrpc/com.atproto.sync.getRepo` - Retrieves repository data
   - `POST /xrpc/com.atproto.repo.createRecord` - Creates new records
   - `POST /xrpc/com.atproto.repo.deleteRecord` - Deletes records
   - `GET /xrpc/com.atproto.repo.getRecord` - Retrieves specific records
   - `POST /xrpc/com.atproto.repo.uploadBlob` - Uploads blobs (e.g., images)

## Implementation Details

### Key Components

1. **Repository Management (`repo.js`)**
   - Implements Merkle Search Tree (MST) for efficient record storage
   - Handles record creation, deletion, and retrieval
   - Manages blob storage
   - Uses SQLite for persistent storage

2. **Record Serialization (`recordSerdes.js`)**
   - Handles conversion between records and JSON
   - Manages CID (Content Identifier) references
   - Implements DAG-CBOR encoding/decoding

3. **Authentication (`pds.js`)**
   - JWT-based authentication
   - Session management
   - Access token generation and validation

4. **Signing (`signing.js`)**
   - ECDSA signing with low-S mitigation
   - Private key management
   - Signature verification

### Data Structures

1. **Merkle Search Tree (MST)**
   - Efficient key-value storage
   - Cryptographic verification
   - Incremental updates

2. **Records**
   - JSON-based structure
   - CID references for content addressing
   - Version tracking

3. **Blobs**
   - Content-addressable storage
   - MIME type support
   - Efficient retrieval

## Getting Started

1. **Prerequisites**
   ```bash
   npm install
   ```

2. **Configuration**
   - Copy `config.js.example` to `config.js`
   - Update configuration values as needed

3. **Running the Server**
   ```bash
   node pds.js
   ```

4. **Testing**
   ```bash
   node test_pds.js
   ```

## Security Considerations

- This is a demo implementation and should not be used in production without proper security hardening
- Private keys are stored in PEM format
- JWT tokens use ES256 algorithm with low-S mitigation
- Authentication is required for sensitive operations

## Learning Resources

- [AT Protocol Documentation](https://atproto.com/docs)
- [Bluesky Protocol Guide](https://blueskyweb.xyz/blog/4-28-2023-domain-handle-tutorial)
- [DAG-CBOR Specification](https://ipld.io/specs/codecs/dag-cbor/)

## Contributing

Feel free to:
- Submit issues for bugs or improvements
- Create pull requests for fixes or enhancements
- Fork the project for your own experiments

## License

This project is open source and available under the MIT License.

## Acknowledgments

This implementation is inspired by the original [picopds](https://github.com/DavidBuchanan314/picopds) project and is intended for educational purposes.
