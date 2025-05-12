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

// Initialize logging
const logger = winston.createLogger({
    level: 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console()
    ]
});

// Load private key
const privkeyBytes = fs.readFileSync("private.key", 'utf8').trim();

// Create private key from raw bytes
const privkeyObj = Buffer.from(privkeyBytes, 'hex');

// Initialize firehose queues
const firehoseQueues = new Set();
const firehoseQueuesLock = new Map();

// Cache for appview auth
const appviewAuthCache = new Map();
const APPVIEW_AUTH_TTL = 60 * 60 * 1000; // 1 hour in milliseconds

function getAppviewAuth() {
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

    const header = { alg: 'ES256', typ: 'JWT' };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    
    const signature = rawSign(privkeyObj, Buffer.from(signingInput));
    const encodedSignature = signature.toString('base64url');
    
    const auth = {
        "Authorization": `Bearer ${encodedHeader}.${encodedPayload}.${encodedSignature}`
    };

    appviewAuthCache.set('auth', { auth, timestamp: now });
    return auth;
}

function jwtAccessSubject(token) {
    try {
        console.log('Verifying JWT with secret:', config.JWT_ACCESS_SECRET);
        const payload = jwt.verify(token, config.JWT_ACCESS_SECRET, { algorithms: ['HS256'] });
        console.log('JWT payload:', payload);
        
        if (payload.scope !== "com.atproto.access") {
            console.error('Invalid JWT scope:', payload.scope);
            throw new Error("invalid jwt scope");
        }
        
        const now = Math.floor(Date.now() / 1000);
        if (!payload.iat || payload.iat > now) {
            console.error('Invalid JWT iat:', payload.iat, 'now:', now);
            throw new Error("invalid jwt: issued in the future");
        }
        
        if (!payload.exp || payload.exp < now) {
            console.error('Invalid JWT exp:', payload.exp, 'now:', now);
            throw new Error("invalid jwt: expired");
        }
        
        if (!payload.sub) {
            console.error('Missing JWT sub field');
            throw new Error("invalid jwt: no subject");
        }
        
        return payload.sub;
    } catch (err) {
        console.error('JWT verification error:', err);
        throw new Error("invalid jwt");
    }
}

// Authentication middleware
function authenticated(handler) {
    return async (req, res, next) => {
        try {
            const auth = req.headers.authorization;
            if (!auth) {
                return res.status(401).json({ error: "authentication required (this may be a bug, I'm erring on the side of caution for now)" });
            }

            const [authtype, value] = auth.split(" ");
            if (authtype !== "Bearer") {
                return res.status(401).json({ error: "invalid auth type" });
            }

            const subject = jwtAccessSubject(value);
            if (subject !== config.DID_PLC) {
                return res.status(401).json({ error: "invalid auth subject" });
            }

            return handler(req, res, next);
        } catch (err) {
            return res.status(401).json({ error: err.message });
        }
    };
}

async function firehoseBroadcast(msg) {
    for (const queue of firehoseQueues) {
        await queue.put(msg);
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
    const { identifier, password } = req.body;

    if (identifier !== config.HANDLE || password !== config.PASSWORD) {
        return res.status(401).json({ error: "invalid username or password" });
    }

    const now = Math.floor(Date.now() / 1000);
    const accessJwt = jwt.sign({
        scope: "com.atproto.access",
        sub: config.DID_PLC,
        iat: now,
        exp: now + 60 * 60 * 24 // 24h
    }, config.JWT_ACCESS_SECRET, { algorithm: 'HS256' });

    return res.json({
        accessJwt,
        refreshJwt: "todo",
        handle: config.HANDLE,
        did: config.DID_PLC
    });
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
            message: "Missing handle parameter"
        });
    }

    if (handle === config.HANDLE) {
        return res.json({ did: config.DID_PLC });
    }

    try {
        const response = await fetch(`https://${config.APPVIEW_SERVER}/xrpc/com.atproto.identity.resolveHandle?${new URLSearchParams(req.query)}`, {
            headers: getAppviewAuth()
        });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch (err) {
        res.status(500).json({ error: "InternalError", message: err.message });
    }
}

async function syncSubscribeRepos(req, res) {
    // WebSocket implementation would go here
    res.status(501).json({ error: "NotImplemented" });
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

        res.json({
            did: config.DID_PLC,
            rev: "0",
            data: {
                posts: [],
                profiles: [],
                lists: []
            }
        });
    } catch (err) {
        res.status(500).json({ error: "InternalError", message: err.message });
    }
}

// Global variables
let repo;

async function repoCreateRecord(req, res) {
    try {
        console.log('Received request body:', req.body);
        const record = jsonToRecord(req.body);
        console.log('Converted record:', record);
        
        if (record.repo !== config.DID_PLC) {
            throw new Error("Invalid repo");
        }

        const { collection, rkey, record: recordData } = record;
        console.log('Creating record with:', { collection, rkey, recordData });
        
        const [uri, cid, firehoseMsg] = await repo.createRecord(collection, recordData, rkey);
        console.log('Created record:', { uri, cid, firehoseMsg });
        
        await firehoseBroadcast(firehoseMsg);

        res.json({
            uri,
            cid: cid.toString(base32)
        });
    } catch (err) {
        console.error('Error in repoCreateRecord:', err);
        console.error('Error stack:', err.stack);
        res.status(500).json({ 
            error: "InternalError", 
            message: err.message,
            details: err.stack
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

async function initServer() {
    try {
        // Initialize repository
        repo = await Repo.create(config.DID_PLC, "repo.db", privkeyObj);
        console.log('Repository initialized successfully');

        // Initialize Express app
        const app = express();
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
        app.post('/xrpc/com.atproto.repo.createRecord', authenticated(repoCreateRecord));
        app.post('/xrpc/com.atproto.repo.deleteRecord', authenticated(repoDeleteRecord));
        app.get('/xrpc/com.atproto.repo.getRecord', authenticated(repoGetRecord));
        app.post('/xrpc/com.atproto.repo.uploadBlob', authenticated(repoUploadBlob));

        // Start server
        const PORT = process.env.PORT || 31337;
        const server = app.listen(PORT, '0.0.0.0', () => {
            console.log(`PDS server running on port ${PORT}`);
        });

        // Handle process termination
        const shutdown = async () => {
            console.log('Shutting down server...');
            try {
                await new Promise((resolve) => server.close(resolve));
                console.log('Server closed');
                process.exit(0);
            } catch (err) {
                console.error('Error during shutdown:', err);
                process.exit(1);
            }
        };

        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
        process.on('uncaughtException', (err) => {
            console.error('Uncaught exception:', err);
            shutdown();
        });
        process.on('unhandledRejection', (reason, promise) => {
            console.error('Unhandled rejection at:', promise, 'reason:', reason);
            shutdown();
        });

        return { app, server };
    } catch (err) {
        console.error('Failed to initialize server:', err);
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