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
import AsyncLock from 'async-lock';
import { createServer } from 'http';

// Global variables
let repo;

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
const firehoseQueuesLock = new AsyncLock();

// Cache for appview auth
const appviewAuthCache = new Map();
const APPVIEW_AUTH_TTL = 60 * 60 * 1000; // 1 hour in milliseconds
let retryCount = 0; // Add retry count for exponential backoff

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
        logger.debug('Notifying appview server of update:', {
            hostname: config.PDS_SERVER,
            messageLength: msg.length
        });
        
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
            const errorText = await response.text();
            logger.error('Failed to notify appview server:', {
                status: response.status,
                statusText: response.statusText,
                error: errorText
            });
            // Retry after a delay with exponential backoff
            const retryDelay = Math.min(5000 * Math.pow(2, retryCount), 300000); // Max 5 minutes
            setTimeout(() => notifyAppviewServer(msg), retryDelay);
        } else {
            const responseData = await response.json();
            logger.info('Successfully notified appview server of update:', responseData);
        }
    } catch (err) {
        logger.error('Error notifying appview server:', err);
        // Retry after a delay with exponential backoff
        const retryDelay = Math.min(5000 * Math.pow(2, retryCount), 300000); // Max 5 minutes
        setTimeout(() => notifyAppviewServer(msg), retryDelay);
    }
}

async function firehoseBroadcast(msg) {
    logger.info('Broadcasting firehose message to', firehoseQueues.size, 'clients');
    await firehoseQueuesLock.acquire('firehose', async () => {
        const messageBuffer = Buffer.isBuffer(msg) ? msg : Buffer.from(JSON.stringify(msg));
        for (const ws of firehoseQueues) {
            if (ws.readyState === WebSocket.OPEN && ws.firehoseQueue) {
                ws.firehoseQueue.push(messageBuffer);
            }
        }
    });
}

// Route handlers
async function hello(req, res) {
    res.send("Hello! This is an ATProto PDS instance");
}

async function serverDescribeServer(req, res) {
    res.json({
        availableUserDomains: ["jpd.memory-design.xyz"],
        inviteCodeRequired: false,
        links: {
            privacyPolicy: "https://jpd.memory-design.xyz/privacy",
            termsOfService: "https://jpd.memory-design.xyz/terms"
        }
    });
}

async function syncGetRepoStatus(req, res) {
    try {
        const { did } = req.query;
        if (!did) {
            return res.status(400).json({
                error: "InvalidRequest",
                message: "Missing did parameter"
            });
        }

        // Only support your own DID for now
        if (did !== config.DID_PLC) {
            return res.status(404).json({
                error: "NotFound",
                message: "Repo not found"
            });
        }

        // You may want to fetch this info from your repo object if available
        // Here is a minimal example:
        res.json({
            did: config.DID_PLC,
            handle: config.HANDLE, // or whatever handle you use
            service: `https://${config.PDS_SERVER}`,
            status: "active", // or "inactive", "takendown", etc.
            type: "repo"
            // You can add more fields as needed per the atproto spec
        });
    } catch (err) {
        res.status(500).json({ error: "InternalError", message: err.message });
    }
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
    logger.info('Received subscribeRepos request');
    logger.debug('Request headers:', req.headers);
    
    if (req.headers.upgrade !== 'websocket') {
        logger.warn('Non-WebSocket request to subscribeRepos');
        return res.status(426).json({
            error: "UpgradeRequired",
            message: "Expected WebSocket connection"
        });
    }

    // The upgrade will be handled by the server's 'upgrade' event
    logger.info('Upgrade request will be handled by server');
}

async function syncGetRepo(req, res) {
    console.log(
      '[syncGetRepo] Request from',
      req.ip,
      '| user-agent:', req.headers['user-agent'],
      '| time:', new Date().toISOString()
    );
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
        
        // Send the CAR file data as binary
        res.end(carData);
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
        
        // Send the CAR file data as binary
        res.end(carData);
    } catch (err) {
        logger.error('Error in syncGetCheckout:', err);
        res.status(500).json({ 
            error: "InternalError", 
            message: err.message 
        });
    }
}

async function repoCreateRecord(req, res) {
    try {
        const record = jsonToRecord(req.body);
        if (record.repo !== config.DID_PLC) {
            throw new Error("Invalid repo");
        }

        const { collection, repo: repoDid } = record;
        const result = await repo.createRecord(collection, repoDid, record.record);

        // Broadcast to firehose
        await firehoseBroadcast(result.firehoseMsg);

        return res.json({
            uri: result.uri,
            cid: result.cid
        });
    } catch (err) {
        logger.error('Error in repoCreateRecord:', err);
        res.status(500).json({ 
            error: "InternalError", 
            message: err.message 
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
            const result = await repo.getRecord(collection, rkey);
            if (!result) {
                return res.status(404).json({ error: "NotFound", message: "Record not found" });
            }
            const [uri, cid, value] = result;
            logger.info('repoGetRecord: value type', typeof value, Array.isArray(value), value && value.constructor && value.constructor.name);
            logger.info('repoGetRecord: value (first 32 bytes)', value && value.slice ? value.slice(0, 32) : value);
            res.json({
                uri,
                cid: cid.toString(),
                value: dagCbor.decode(value)  // Decode the CBOR data
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

// Initialize WebSocket server
const wss = new WebSocketServer({ noServer: true });

// Handle WebSocket connections
wss.on('connection', (ws) => {
    logger.info('New WebSocket connection established');

    // Create a queue for this client
    const queue = [];
    let isAlive = true;

    // Add to global set
    firehoseQueues.add(ws);

    // Function to send messages from the queue
    async function sendFromQueue() {
        while (isAlive) {
            if (queue.length > 0 && ws.readyState === ws.OPEN) {
                const msg = queue.shift();
                try {
                    ws.send(msg);
                } catch (err) {
                    logger.error('Error sending firehose message:', err);
                }
            }
            await new Promise(resolve => setTimeout(resolve, 10)); // avoid busy loop
        }
    }

    // Start sending messages from the queue
    sendFromQueue();

    // Attach the queue to the ws object for easy access
    ws.firehoseQueue = queue;

    ws.on('close', () => {
        logger.info('WebSocket connection closed');
        isAlive = false;
        firehoseQueues.delete(ws);
    });

    ws.on('error', (error) => {
        logger.error('WebSocket error:', error);
        isAlive = false;
        firehoseQueues.delete(ws);
    });

    ws.on('message', (message) => {
        logger.debug('Received message from client:', message);
    });
});

// Modify initServer to remove appview connection
async function initServer() {
    try {
        // Initialize repository
        repo = await Repo.initialize(config.DID_PLC, "repo.db", privkeyObj, null);
        logger.info('Repository initialized successfully');

        // Initialize Express app
        const app = express();
        
        // Configure middleware
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
        app.get('/xrpc/com.atproto.sync.getRepoStatus', syncGetRepoStatus);
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
        app.get('/xrpc/com.atproto.repo.listRecords', async (req, res) => {
            try {
                const { repo: repoDid, collection, limit, cursor, reverse } = req.query;
                if (!repoDid || !collection) {
                    return res.status(400).json({ error: 'Missing repo or collection parameter' });
                }
                if (repoDid !== config.DID_PLC) {
                    return res.status(404).json({ error: 'Repo not found' });
                }
                const records = await repo.listRecordsForCollection({
                    collection,
                    limit: limit ? parseInt(limit) : 50,
                    cursor: cursor || null,
                    reverse: reverse === 'true'
                });
                const lastRecord = records[records.length - 1];
                const lastUri = lastRecord ? lastRecord.uri : undefined;
                const lastRkey = lastUri ? lastUri.split('/').pop() : undefined;
                res.json({
                    records,
                    cursor: lastRkey
                });
            } catch (err) {
                logger.error('Error in listRecords endpoint:', err);
                res.status(500).json({ error: err.message });
            }
        });
        app.get('/debug/db', async (req, res) => {
          try {
            const commits = repo.con.prepare("SELECT commit_seq, hex(commit_cid) FROM commits ORDER BY commit_seq").all();
            const blocks = repo.con.prepare("SELECT hex(block_cid), length(block_value) FROM blocks").all();
            
            // Enhanced commit chain analysis
            const commitChain = [];
            for (const commit of commits) {
              try {
                const commitCid = Buffer.from(commit['hex(commit_cid)'], 'hex');
                const blockValue = repo.con.prepare("SELECT block_value FROM blocks WHERE block_cid = ?").get(commitCid);
                if (blockValue) {
                  const commitObj = dagCbor.decode(new Uint8Array(blockValue.block_value));
                  commitChain.push({
                    seq: commit.commit_seq,
                    cid: commit['hex(commit_cid)'],
                    rev: commitObj.rev,
                    prev: commitObj.prev ? commitObj.prev.toString() : 'null',
                    data: commitObj.data ? (typeof commitObj.data === 'object' ? commitObj.data.toString() : commitObj.data) : 'null',
                    did: commitObj.did
                  });
                }
              } catch (e) {
                commitChain.push({
                  seq: commit.commit_seq,
                  cid: commit['hex(commit_cid)'],
                  error: e.message
                });
              }
            }
            
            res.json({ 
              commits, 
              blocks,
              commitChain,
              totalCommits: commits.length,
              totalBlocks: blocks.length
            });
          } catch (e) {
            res.status(500).json({ error: e.message });
          }
        });

        // Create HTTP server
        const server = http.createServer(app);
        
        // Handle WebSocket upgrade
        server.on('upgrade', (request, socket, head) => {
            logger.info('Received upgrade request');
            const pathname = new URL(request.url, `http://${request.headers.host}`).pathname;
            
            if (pathname === '/xrpc/com.atproto.sync.subscribeRepos') {
                logger.info('Upgrading to WebSocket for subscribeRepos');
                wss.handleUpgrade(request, socket, head, (ws) => {
                    logger.info('WebSocket upgrade completed');
                    wss.emit('connection', ws, request);
                });
            } else {
                logger.warn('Invalid WebSocket path:', pathname);
                socket.destroy();
            }
        });

        // Start server
        const PORT = process.env.PORT || 3000;
        server.listen(PORT, () => {
            logger.info(`Server is running on port ${PORT}`);
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
            logger.error('Unhandled rejection at:', promise, 'reason:', reason && reason.stack ? reason.stack : reason);
            console.error('Unhandled rejection at:', promise, 'reason:', reason);
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