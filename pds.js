import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import { promisify } from 'util';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { base32 } from 'multiformats/bases/base32';
import crypto from 'crypto';
import { Repo } from './repo.js';
import { recordToJson, jsonToRecord } from './recordSerdes.js';
import config from './config.js';
import winston from 'winston';
import { rawSign } from './signing.js';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import base64url from 'base64url';
import { WebSocketServer } from 'ws';
import http from 'http';
import WebSocket from 'ws';

// Initialize logging with Python-like format
const logger = winston.createLogger({
    level: 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ level, message, timestamp }) => {
            return `${timestamp} ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console()
    ]
});

// Load private key
let privkeyObj;
try {
    const privkeyPem = fs.readFileSync("privkey.pem", 'utf8');
    // Extract the private key bytes from the PEM
    const privateKeyBase64 = privkeyPem
        .replace('-----BEGIN PRIVATE KEY-----', '')
        .replace('-----END PRIVATE KEY-----', '')
        .replace(/\s/g, '');
    const privateKeyDer = Buffer.from(privateKeyBase64, 'base64');
    // The last 32 bytes of the DER are the actual private key
    privkeyObj = privateKeyDer.slice(-32);
    logger.info('Private key loaded successfully');
} catch (err) {
    logger.error('Failed to load private key:', err);
    process.exit(1);
}

// Initialize firehose queues
const firehoseQueues = new Set();
const firehoseQueuesLock = new Map();

// Cache for appview auth
const appviewAuthCache = new Map();
const APPVIEW_AUTH_TTL = 60 * 60 * 1000; // 1 hour in milliseconds

function getAppviewAuth() {
    if (!privkeyObj) {
        throw new Error('Private key not available');
    }
    
    const now = Date.now();
    const cached = appviewAuthCache.get('auth');
    if (cached && (now - cached.timestamp) < APPVIEW_AUTH_TTL) {
        return cached.auth;
    }

    const payload = {
        iss: config.DID_PLC,
        aud: `did:web:${config.APPVIEW_SERVER}`,
        exp: Math.floor(now / 1000) + 60 * 60 * 24 // 24h
    };

    const header = { alg: 'ES256K', typ: 'JWT' };
    const encodedHeader = base64url(JSON.stringify(header));
    const encodedPayload = base64url(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    
    // Hash the signing input
    const msgHash = sha256(Buffer.from(signingInput));
    
    // Sign the JWT
    const signature = secp256k1.sign(msgHash, privkeyObj);
    
    // Convert signature to raw bytes
    const r = Buffer.from(signature.r.toString(16).padStart(64, '0'), 'hex');
    const s = Buffer.from(signature.s.toString(16).padStart(64, '0'), 'hex');
    const rawSignature = Buffer.concat([r, s]);
    
    // Convert to DER format
    const derSignature = rawToDer(rawSignature);
    const encodedSignature = base64url(derSignature);
    
    const token = `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
    
    const auth = {
        "Authorization": `Bearer ${token}`
    };

    appviewAuthCache.set('auth', { auth, timestamp: now });
    return auth;
}

// Function to convert raw signature to DER format
function rawToDer(rawSignature) {
    const r = rawSignature.slice(0, 32);
    const s = rawSignature.slice(32);
    
    // Remove leading zeros
    let rStart = 0;
    while (rStart < r.length && r[rStart] === 0) rStart++;
    let sStart = 0;
    while (sStart < s.length && s[sStart] === 0) sStart++;
    
    // If all zeros, use one zero byte
    if (rStart === r.length) rStart = r.length - 1;
    if (sStart === s.length) sStart = s.length - 1;
    
    const rVal = r.slice(rStart);
    const sVal = s.slice(sStart);
    
    // Add leading zero if high bit is set
    const rPad = (rVal[0] & 0x80) !== 0 ? 1 : 0;
    const sPad = (sVal[0] & 0x80) !== 0 ? 1 : 0;
    
    const rLen = rVal.length + rPad;
    const sLen = sVal.length + sPad;
    const totalLen = 2 + rLen + 2 + sLen;
    
    const der = Buffer.alloc(2 + totalLen);
    let offset = 0;
    
    // DER header
    der[offset++] = 0x30;
    der[offset++] = totalLen;
    
    // R value
    der[offset++] = 0x02;
    der[offset++] = rLen;
    if (rPad) der[offset++] = 0;
    rVal.copy(der, offset);
    offset += rVal.length;
    
    // S value
    der[offset++] = 0x02;
    der[offset++] = sLen;
    if (sPad) der[offset++] = 0;
    sVal.copy(der, offset);
    
    return der;
}

function jwtAccessSubject(token) {
    try {
        const payload = jwt.verify(token, config.JWT_ACCESS_SECRET, { algorithms: ['HS256'] });
        
        if (payload.scope !== "com.atproto.access") {
            throw new Error("invalid jwt scope");
        }
        
        const now = Math.floor(Date.now() / 1000);
        if (!payload.iat || payload.iat > now) {
            throw new Error("invalid jwt: issued in the future");
        }
        
        if (!payload.exp || payload.exp < now) {
            throw new Error("invalid jwt: expired");
        }

        return payload.sub || config.DID_PLC; // Return the subject from payload or fallback to configured DID
    } catch (err) {
        throw new Error("invalid jwt");
    }
}

// Authentication middleware
function authenticated(handler) {
    return async (req, res) => {
        const auth = req.headers.authorization;
        if (!auth) {
            return res.status(401).json({ 
                error: "AuthenticationRequired",
                message: "authentication required (this may be a bug, I'm erring on the side of caution for now)"
            });
        }

        const [authtype, value] = auth.split(" ");
        if (authtype !== "Bearer") {
            return res.status(401).json({ 
                error: "InvalidAuthType",
                message: "invalid auth type"
            });
        }

        try {
            const subject = jwtAccessSubject(value);
            if (subject !== config.DID_PLC) {
                return res.status(401).json({ 
                    error: "InvalidAuthSubject",
                    message: "invalid auth subject"
                });
            }
            return handler(req, res);
        } catch (err) {
            return res.status(401).json({ 
                error: "InvalidAuth",
                message: err.message
            });
        }
    };
}

// Add function to notify appview server
async function notifyAppviewServer(msg) {
    try {
        const response = await fetch(`https://${config.APPVIEW_SERVER}/xrpc/com.atproto.sync.notifyOfUpdate`, {
            method: 'POST',
            headers: {
                ...getAppviewAuth(),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                hostname: config.PDS_SERVER,
                message: msg.toString('base64')
            })
        });

        if (!response.ok) {
            logger.error('Failed to notify appview server:', await response.text());
            // Retry after a delay
            setTimeout(() => notifyAppviewServer(msg), 5000);
        } else {
            logger.info('Successfully notified appview server of update');
        }
    } catch (err) {
        logger.error('Error notifying appview server:', err);
        // Retry after a delay
        setTimeout(() => notifyAppviewServer(msg), 5000);
    }
}

async function firehoseBroadcast(msg) {
    // Use a lock to prevent queue modifications during broadcast
    const lockKey = 'broadcast';
    if (firehoseQueuesLock.get(lockKey)) {
        await new Promise(resolve => setTimeout(resolve, 100));
        return firehoseBroadcast(msg);
    }
    
    firehoseQueuesLock.set(lockKey, true);
    try {
        // Broadcast to all connected clients (including appview server)
        for (const queue of firehoseQueues) {
            await queue.put(msg);
        }
        
        // Log the broadcast for debugging
        logger.info('Firehose message broadcast:', {
            msgType: msg[0] === 0x82 ? 'commit' : 'unknown',
            msgLength: msg.length
        });
    } finally {
        firehoseQueuesLock.delete(lockKey);
    }
}

// Route handlers
async function hello(req, res) {
    res.send("Hello! This is an ATProto PDS instance");
}

async function serverDescribeServer(req, res) {
    res.json({ availableUserDomains: [] });
}

async function serverCreateSession(req, res) {
    try {
        const { identifier, password } = req.body;
        console.log("Creating session for:", identifier);

        if (identifier !== config.HANDLE || password !== config.PASSWORD) {
            return res.status(401).json({ error: "invalid username or password" });
        }

        const now = Math.floor(Date.now() / 1000);
        const payload = {
            scope: "com.atproto.access",
            sub: config.DID_PLC,  // Add DID to payload
            iat: now,
            exp: now + 60 * 60 * 24, // 24 hours
            aud: "com.atproto.access"
        };

        const accessJwt = jwt.sign(payload, config.JWT_ACCESS_SECRET, { algorithm: 'HS256' });

        return res.json({
            accessJwt,
            refreshJwt: "todo",
            handle: config.HANDLE,
            did: config.DID_PLC  // Add DID to response
        });
    } catch (err) {
        console.error('Error in serverCreateSession:', err);
        res.status(500).json({ 
            error: "InternalError", 
            message: err.message,
            details: err.stack
        });
    }
}

async function serverGetSession(req, res) {
    res.json({
        handle: config.HANDLE,
        did: config.DID_PLC,
        email: "email@example.org"
    });
}

async function identityResolveHandle(req, res) {
    const { handle } = req.query;
    if (!handle) {
        return res.status(400).json({
            error: "InvalidRequest",
            message: "missing or invalid handle"
        });
    }

    if (handle === config.HANDLE) {
        return res.json({ did: config.DID_PLC });
    }

    try {
        const response = await fetch(`https://${config.APPVIEW_SERVER}/xrpc/com.atproto.identity.resolveHandle?${new URLSearchParams(req.query)}`, {
            headers: getAppviewAuth()
        });
        
        if (response.status === 200) {
            const data = await response.json();
            return res.json(data);
        } else {
            return res.status(404).json({ 
                error: "HandleNotFound",
                message: "Handle not found"
            });
        }
    } catch (err) {
        console.error('Error resolving handle:', err);
        return res.status(500).json({ 
            error: "InternalError", 
            message: err.message 
        });
    }
}

async function syncSubscribeRepos(req, res) {
    logger.info('New WebSocket subscription request received');
    logger.debug('Request headers:', req.headers);
    logger.debug('Request query:', req.query);
    
    // Set proper headers for WebSocket upgrade
    res.setHeader('Upgrade', 'websocket');
    res.setHeader('Connection', 'Upgrade');
    res.setHeader('Sec-WebSocket-Accept', crypto
        .createHash('sha1')
        .update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
        .digest('base64'));
    
    // Create a queue for this client
    const queue = {
        messages: [],
        put: async (msg) => {
            queue.messages.push(msg);
        },
        get: async () => {
            if (queue.messages.length === 0) {
                await new Promise(resolve => setTimeout(resolve, 100));
                return queue.get();
            }
            return queue.messages.shift();
        }
    };
    
    // Add to firehose queues with lock
    const lockKey = 'queue_add';
    if (firehoseQueuesLock.get(lockKey)) {
        await new Promise(resolve => setTimeout(resolve, 100));
        return syncSubscribeRepos(req, res);
    }
    
    firehoseQueuesLock.set(lockKey, true);
    try {
        firehoseQueues.add(queue);
        logger.info(`New firehose client connected. Total clients: ${firehoseQueues.size}`);
        logger.info('Client details:', {
            remote: req.socket.remoteAddress,
            forwardedFor: req.headers['x-forwarded-for'],
            query: req.query
        });
    } finally {
        firehoseQueuesLock.delete(lockKey);
    }
    
    // Handle the upgrade
    const server = req.socket.server;
    server.handleUpgrade(req, req.socket, Buffer.alloc(0), (ws) => {
        logger.info('WebSocket connection upgraded successfully');
        
        // Handle WebSocket connection
        const sendMessages = async () => {
            try {
                while (true) {
                    const msg = await queue.get();
                    ws.send(msg, { binary: true });
                }
            } catch (err) {
                logger.error('Error sending message:', err);
                ws.close();
            }
        };
        
        sendMessages();
        
        ws.on('close', () => {
            logger.info('Firehose client disconnected');
            // Remove from firehose queues with lock
            const lockKey = 'queue_remove';
            if (firehoseQueuesLock.get(lockKey)) {
                setTimeout(() => {
                    firehoseQueues.delete(queue);
                }, 100);
            } else {
                firehoseQueuesLock.set(lockKey, true);
                try {
                    firehoseQueues.delete(queue);
                } finally {
                    firehoseQueuesLock.delete(lockKey);
                }
            }
        });
        
        ws.on('error', (err) => {
            logger.error('WebSocket error:', err);
            firehoseQueues.delete(queue);
        });
    });
}

async function syncGetRepo(req, res) {
    try {
        const { did } = req.query;
        if (!did) {
            return res.status(400).json({
                error: "InvalidRequest",
                message: "Missing did parameter"
            });
        }

        if (did !== config.DID_PLC) {
            return res.status(404).json({
                error: "NotFound",
                message: "Repo not found"
            });
        }

        // Get the repository checkout as a CAR file
        const carData = await repo.getCheckout();
        
        // Set the proper content type for CAR files
        res.setHeader('Content-Type', 'application/vnd.ipld.car');
        
        // Send the CAR file data
        res.send(carData);
    } catch (err) {
        logger.error('Error in syncGetRepo:', err);
        res.status(500).json({ 
            error: "InternalError", 
            message: err.message 
        });
    }
}

async function syncGetCheckout(req, res) {
    try {
        const { did, commit } = req.query;
        if (!did) {
            return res.status(400).json({
                error: "InvalidRequest",
                message: "Missing did parameter"
            });
        }

        if (did !== config.DID_PLC) {
            return res.status(404).json({
                error: "NotFound",
                message: "Repo not found"
            });
        }

        // Decode commit CID if provided
        let commitCid = null;
        if (commit) {
            try {
                commitCid = CID.decode(commit);
            } catch (err) {
                return res.status(400).json({
                    error: "InvalidRequest",
                    message: "Invalid commit CID format"
                });
            }
        }

        // Get the repository checkout as a CAR file
        const carData = await repo.getCheckout(commitCid);
        
        // Set the proper content type for CAR files
        res.setHeader('Content-Type', 'application/vnd.ipld.car');
        
        // Send the CAR file data
        res.send(carData);
    } catch (err) {
        logger.error('Error in syncGetCheckout:', err);
        res.status(500).json({ 
            error: "InternalError", 
            message: err.message 
        });
    }
}

// Global variables
let repo;

async function repoCreateRecord(req, res) {
    try {
        logger.info('Creating new record');
        logger.debug('Request body:', req.body);
        logger.debug('Config DID_PLC:', config.DID_PLC);
        
        const record = jsonToRecord(req.body);
        logger.debug('Converted record:', record);
        logger.debug('Record repo:', record.repo);
        
        if (!record.repo) {
            logger.error('Missing repo parameter in request');
            return res.status(400).json({
                error: "InvalidRequest",
                message: "Missing repo parameter"
            });
        }

        if (record.repo !== config.DID_PLC) {
            logger.error('Invalid repo:', record.repo);
            return res.status(400).json({
                error: "InvalidRequest",
                message: "Invalid repo"
            });
        }

        // Ensure the record includes the $type field
        if (!record.record.$type) {
            record.record.$type = `app.bsky.feed.${record.collection.split('.').pop()}`;
        }

        const [uri, cid, firehoseMsg] = await repo.createRecord(
            record.collection,
            record.record,
            record.rkey
        );

        // Broadcast the firehose message
        await firehoseBroadcast(firehoseMsg);

        return res.json({
            uri,
            cid: cid.toString(base32)
        });
    } catch (err) {
        logger.error('Error in repoCreateRecord:', err);
        logger.error('Error stack:', err.stack);
        logger.error('Request body:', req.body);
        logger.error('Config DID_PLC:', config.DID_PLC);
        
        // Handle specific error cases
        if (err.message === "Record not found") {
            return res.status(404).json({
                error: "NotFound",
                message: "Record not found"
            });
        }
        
        return res.status(500).json({
            error: "InternalServerError",
            message: "An unexpected error occurred"
        });
    }
}

async function repoDeleteRecord(req, res) {
    try {
        const record = jsonToRecord(req.body);
        if (record.repo !== config.DID_PLC) {
            throw new Error("Invalid repo");
        }

        const { collection, rkey } = record;
        const firehoseMsg = await repo.deleteRecord(collection, rkey);
        await firehoseBroadcast(firehoseMsg);

        res.status(200).end();
    } catch (err) {
        res.status(500).json({ error: "InternalError", message: err.message });
    }
}

async function repoGetRecord(req, res) {
    try {
        const { collection, repo: repoDid, rkey } = req.query;
        
        if (repoDid === repo.did) {
            const [uri, cid, value] = await repo.getRecord(collection, rkey);
            res.json({
                uri,
                cid: cid.toString(),
                value: dagCbor.decode(value)
            });
        } else {
            const response = await fetch(`https://${config.APPVIEW_SERVER}/xrpc/com.atproto.repo.getRecord?${new URLSearchParams(req.query)}`, {
                headers: getAppviewAuth()
            });
            const data = await response.json();
            res.status(response.status).json(data);
        }
    } catch (err) {
        res.status(500).json({ error: "InternalError", message: err.message });
    }
}

async function repoUploadBlob(req, res) {
    try {
        const mime = req.headers['content-type'];
        const blob = await promisify(fs.readFile)(req.file.path);
        const ref = await repo.putBlob(blob);
        ref.mimeType = mime;
        res.json(recordToJson({ blob: ref }));
    } catch (err) {
        res.status(500).json({ error: "InternalError", message: err.message });
    }
}

async function bskyFeedGetAuthorFeed(req, res) {
    try {
        const response = await fetch(`https://${config.APPVIEW_SERVER}/xrpc/app.bsky.feed.getAuthorFeed?${new URLSearchParams(req.query)}`, {
            headers: getAppviewAuth()
        });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch (err) {
        res.status(500).json({ error: "InternalError", message: err.message });
    }
}

async function bskyActorGetProfile(req, res) {
    try {
        const response = await fetch(`https://${config.APPVIEW_SERVER}/xrpc/app.bsky.actor.getProfile?${new URLSearchParams(req.query)}`, {
            headers: getAppviewAuth()
        });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch (err) {
        res.status(500).json({ error: "InternalError", message: err.message });
    }
}

async function syncNotifyOfUpdate(req, res) {
    try {
        const { hostname, message } = req.body;
        if (!hostname || !message) {
            return res.status(400).json({
                error: "InvalidRequest",
                message: "Missing required fields"
            });
        }

        // Decode the message
        const msgBuffer = Buffer.from(message, 'base64');
        
        // Broadcast the message to our firehose clients
        await firehoseBroadcast(msgBuffer);
        
        res.status(200).end();
    } catch (err) {
        logger.error('Error in syncNotifyOfUpdate:', err);
        res.status(500).json({
            error: "InternalError",
            message: err.message
        });
    }
}

// Modify initServer to remove appview connection
async function initServer() {
    try {
        // Initialize repository
        repo = await Repo.create(config.DID_PLC, "repo.db", privkeyObj);
        logger.info('Repository initialized successfully');

        // Initialize Express app
        const app = express();
        const server = http.createServer(app);
        
        // Initialize WebSocket server
        const wss = new WebSocketServer({ server });
        logger.info('WebSocket server initialized');
        
        app.use(cors({
            origin: '*',
            methods: '*',
            allowedHeaders: '*',
            exposedHeaders: '*',
            credentials: true
        }));
        app.use(express.json());

        // Add routes
        app.get('/', hello);
        app.get('/.well-known/atproto-did', (req, res) => res.send(config.DID_PLC));
        app.get('/xrpc/com.atproto.server.describeServer', serverDescribeServer);
        app.post('/xrpc/com.atproto.server.createSession', serverCreateSession);
        app.get('/xrpc/com.atproto.server.getSession', authenticated(serverGetSession));
        app.get('/xrpc/com.atproto.identity.resolveHandle', identityResolveHandle);
        app.get('/xrpc/com.atproto.sync.subscribeRepos', syncSubscribeRepos);
        app.get('/xrpc/com.atproto.sync.getRepo', syncGetRepo);
        app.get('/xrpc/com.atproto.sync.getCheckout', syncGetCheckout);
        app.post('/xrpc/com.atproto.repo.createRecord', authenticated(repoCreateRecord));
        app.post('/xrpc/com.atproto.repo.deleteRecord', authenticated(repoDeleteRecord));
        app.get('/xrpc/com.atproto.repo.getRecord', authenticated(repoGetRecord));
        app.post('/xrpc/com.atproto.repo.uploadBlob', authenticated(repoUploadBlob));
        app.get('/xrpc/app.bsky.feed.getAuthorFeed', authenticated(bskyFeedGetAuthorFeed));
        app.get('/xrpc/app.bsky.actor.getProfile', authenticated(bskyActorGetProfile));
        app.post('/xrpc/com.atproto.sync.notifyOfUpdate', authenticated(syncNotifyOfUpdate));

        // Start server
        const PORT = 31337;  // Fixed port to match Python implementation
        server.listen(PORT, '0.0.0.0', () => {
            logger.info(`PDS server running on port ${PORT}`);
            logger.info(`WebSocket endpoint available at ws://${config.PDS_SERVER}:${PORT}/xrpc/com.atproto.sync.subscribeRepos`);
        });

        // Handle process termination
        const shutdown = async () => {
            logger.info('Shutting down server...');
            try {
                await new Promise((resolve) => server.close(resolve));
                logger.info('Server closed');
                process.exit(0);
            } catch (err) {
                logger.error('Error during shutdown:', err);
                process.exit(1);
            }
        };

        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
        process.on('uncaughtException', (err) => {
            logger.error('Uncaught exception:', err);
            shutdown();
        });
        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled rejection at:', promise, 'reason:', reason);
            shutdown();
        });

        return { app, server };
    } catch (err) {
        logger.error('Error initializing server:', err);
        process.exit(1);
    }
}

// Initialize the server
initServer().catch(err => {
    logger.error('Failed to start server:', err);
    process.exit(1);
});

// Keep the process alive
setInterval(() => {
    // Keep the event loop running
}, 1000); 