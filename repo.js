import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { base32 } from 'multiformats/bases/base32';
import Database from 'better-sqlite3';
import { promisify } from 'util';
import { MSTNode, MST } from './mst.js';
import { rawSign } from './signing.js';
import { serialise } from './carfile.js';
import { randomInt } from 'crypto';
import { createHash } from 'crypto';
import pkg from 'base64url';
import winston from 'winston';
import config from './config.js';
import crypto from 'crypto';
import { EventEmitter } from 'events';
const { base64url } = pkg;

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

const B32_CHARSET = "234567abcdefghijklmnopqrstuvwxyz";

function base32Encode(bytes) {
    let bits = 0;
    let value = 0;
    let output = '';
    
    for (let i = 0; i < bytes.length; i++) {
        value = (value << 8) | bytes[i];
        bits += 8;
        
        while (bits >= 5) {
            output += B32_CHARSET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    
    if (bits > 0) {
        output += B32_CHARSET[(value << (5 - bits)) & 31];
    }
    
    return output;
}

function tidNow() {
    const micros = Math.floor(Date.now() * 1000000); // Convert to microseconds to match Python
    const clkid = Math.floor(Math.random() * (1 << 10)); // Random 10-bit number
    const tidInt = (micros << 10) | clkid;
    let output = '';
    for (let i = 0; i < 13; i++) {
        output += B32_CHARSET[(tidInt >> (60 - (i * 5))) & 31];
    }
    return output;
}

async function hashToCid(data, codec = "dag-cbor") {
    const hash = await sha256.digest(data);
    const cid = CID.create(1, codec === "dag-cbor" ? 0x71 : 0x55, hash);
    return cid;
}

function dtToStr(dt) {
    return dt.toISOString().replace('.000Z', 'Z');
}

function timestampStrNow() {
    return dtToStr(new Date());
}

function enumerateRecordCids(obj) {
    const cids = new Set();
    function traverse(value) {
        if (value === null || value === undefined) {
            return;
        }
        if (typeof value === 'string' && value.startsWith('bafy')) {
            try {
                cids.add(CID.parse(value));
            } catch (e) {
                // Not a valid CID
            }
        } else if (Array.isArray(value)) {
            value.forEach(traverse);
        } else if (typeof value === 'object') {
            Object.values(value).forEach(traverse);
        }
    }
    traverse(obj);
    return cids;
}

class ATNode extends MSTNode {
    /**
     * @param {Array<ATNode|null>} subtrees
     * @param {Array<string>} keys
     * @param {Array<any>} vals
     */
    constructor(subtrees, keys, vals) {
        super(subtrees, keys, vals);
        // Define _cid as a writable property
        Object.defineProperty(this, '_cid', {
            value: null,
            writable: true,
            configurable: true
        });
    }

    /**
     * @param {string} key
     * @returns {number}
     */
    static key_height(key) {
        // Convert key to bytes
        const keyBytes = Buffer.from(key);
        
        // Compute SHA-256 hash
        const hash = crypto.createHash('sha256').update(keyBytes).digest();
        
        // Convert to bigint and count leading zero bits
        const digest = BigInt('0x' + hash.toString('hex'));
        const leadingZeroes = 256 - digest.toString(2).length;
        
        // Return half the number of leading zero bits
        return Math.floor(leadingZeroes / 2);
    }

    /**
     * @returns {ATNode}
     */
    static empty_root() {
        return new this([null], [], []);
    }

    /**
     * @param {string} key
     * @returns {string}
     */
    keyPath() {
        return this.key;
    }

    /**
     * @yields {any}
     */
    *enumerateBlocks() {
        yield this.value;
        for (const child of this.subtrees) {
            if (child) {
                yield* child.enumerateBlocks();
            }
        }
    }
}

// Add this helper function before the Repo class
function cleanObject(obj) {
    if (obj === null || obj === undefined) {
        return null;
    }
    if (typeof obj !== 'object') {
        return obj;
    }
    if (Array.isArray(obj)) {
        return obj.map(cleanObject);
    }
    const cleaned = {};
    for (const [key, value] of Object.entries(obj)) {
        if (value !== undefined) {
            cleaned[key] = cleanObject(value);
        }
    }
    return cleaned;
}

// Add this before the Repo class
async function firehoseBroadcast(message) {
    try {
        // Log the raw message first
        logger.info('Raw firehose message:', {
            type: message?.t,
            op: message?.op,
            hasOps: Array.isArray(message?.ops),
            opsLength: message?.ops?.length,
            hasBlocks: Array.isArray(message?.blocks),
            blocksLength: message?.blocks?.length,
            commit: message?.commit
        });

        // Ensure we have a valid message object
        if (!message || typeof message !== 'object') {
            logger.warn('Invalid message format in firehoseBroadcast');
            return false;
        }

        // Validate and process blocks first
        let processedBlocks = [];
        if (Array.isArray(message.blocks)) {
            for (const block of message.blocks) {
                try {
                    if (!Array.isArray(block) || block.length !== 2) {
                        logger.warn('Invalid block format:', block);
                        continue;
                    }
                    
                    const [cid, data] = block;
                    if (!cid || !data) {
                        logger.warn('Missing cid or data in block:', block);
                        continue;
                    }

                    // Ensure cid and data are Buffers
                    const cidBuffer = Buffer.isBuffer(cid) ? cid : Buffer.from(cid);
                    const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
                    
                    processedBlocks.push([cidBuffer, dataBuffer]);
                } catch (error) {
                    logger.error('Error processing block:', error);
                }
            }
        }

        // Create a safe copy of the message with proper structure
        const safeMessage = {
            t: message.t || '#commit',
            op: message.op || 1,
            ops: Array.isArray(message.ops) ? message.ops.map(op => ({
                action: op?.action || 'create',
                path: op?.path || '',
                cid: op?.cid || ''
            })) : [],
            seq: message.seq || Math.floor(Date.now() * 1000),
            rev: message.rev || 0,
            repo: message.repo || '',
            time: message.time || new Date().toISOString().replace('.000Z', 'Z'),
            blobs: Array.isArray(message.blobs) ? message.blobs : [],
            blocks: processedBlocks,
            commit: message.commit || ''
        };

        // Log the processed message structure
        logger.info('Processed message structure:', {
            type: safeMessage.t,
            op: safeMessage.op,
            hasOps: Array.isArray(safeMessage.ops),
            opsLength: safeMessage.ops.length,
            hasBlocks: Array.isArray(safeMessage.blocks),
            blocksLength: safeMessage.blocks.length,
            blocksFormat: safeMessage.blocks.map(block => ({
                isArray: Array.isArray(block),
                length: block.length,
                cidType: block[0] ? 'Buffer' : 'undefined',
                dataType: block[1] ? 'Buffer' : 'undefined',
                cidLength: block[0]?.length || 0,
                dataLength: block[1]?.length || 0
            }))
        });

        // Log the full message
        logger.info('Firehose broadcast:', JSON.stringify(safeMessage, null, 2));
        return true;
    } catch (error) {
        logger.error('Error in firehoseBroadcast:', error);
        logger.error('Error stack:', error.stack);
        // Don't throw the error, just log it and continue
        return false;
    }
}

// Add this helper function before the Repo class
function generateRkey() {
    const bytes = crypto.randomBytes(8);
    return base32Encode(bytes);
}

class Repo extends EventEmitter {
    constructor(did, db, signingKey, tree) {
        super(); // Call EventEmitter constructor
        this.did = did;
        this.con = new Database(db);
        this.signingKey = signingKey;
        this.tree = new MST(ATNode.empty_root());
    }

    static async initialize(did, db, signingKey, tree) {
        const repo = new Repo(did, db, signingKey, tree);
        
        // Initialize database tables
        repo.con.exec(`
            -- Drop existing tables to ensure clean schema
            DROP TABLE IF EXISTS blocks;
            DROP TABLE IF EXISTS commits;
            DROP TABLE IF EXISTS blobs;
            DROP TABLE IF EXISTS repos;
            DROP TABLE IF EXISTS records;

            -- Create tables
            CREATE TABLE blocks (
                block_cid BLOB PRIMARY KEY NOT NULL,
                block_value BLOB NOT NULL
            );

            CREATE TABLE commits (
                commit_seq INTEGER PRIMARY KEY NOT NULL,
                commit_cid BLOB NOT NULL,
                block_value BLOB NOT NULL
            );

            CREATE TABLE blobs (
                blob_cid BLOB PRIMARY KEY NOT NULL,
                blob_data BLOB NOT NULL,
                blob_refcount INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE repos (
                did TEXT PRIMARY KEY NOT NULL,
                root TEXT NOT NULL,
                rev TEXT NOT NULL
            );

            CREATE TABLE records (
                rkey TEXT NOT NULL,
                collection TEXT NOT NULL,
                cid TEXT NOT NULL,
                repo TEXT NOT NULL,
                commit_cid TEXT NOT NULL,
                prev_cid TEXT,
                data BLOB NOT NULL,
                PRIMARY KEY (rkey, collection, repo)
            );
        `);

        // Create initial commit if needed
        const row = repo.con.prepare("SELECT * FROM commits WHERE commit_seq=0").get();
        if (!row) {
            try {
                // Get the root node's CID and serialised data
                const rootCid = await repo.tree.root.getCid();
                const rootSerialised = await repo.tree.root.getSerialised();
                
                const commit = cleanObject({
                    version: 3,
                    data: rootCid.toString(),
                    rev: tidNow(),
                    did: repo.did,
                    prev: null
                });
                
                const commitBlob = dagCbor.encode(commit);
                const commitCid = await hashToCid(commitBlob);
                const sig = await rawSign(repo.signingKey, commitBlob);
                commit.sig = sig;

                repo.con.transaction(() => {
                    repo.con.prepare(
                        "INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)"
                    ).run(Buffer.from(rootCid.bytes), rootSerialised);
                    
                    repo.con.prepare(
                        "INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)"
                    ).run(Buffer.from(commitCid.bytes), commitBlob);
                    
                    repo.con.prepare(
                        "INSERT INTO commits (commit_seq, commit_cid, block_value) VALUES (?, ?, ?)"
                    ).run(0, Buffer.from(commitCid.bytes), commitBlob);
                })();
            } catch (error) {
                logger.error('Error creating initial commit:', error);
                throw error;
            }
        }

        return repo;
    }

    async putRecord(record) {
        const recordBytes = dagCbor.encode(record);
        const recordCid = await hashToCid(recordBytes);
        
        return new Promise((resolve, reject) => {
            this.con.transaction(() => {
                this.con.prepare(
                    "INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)"
                ).run(Buffer.from(recordCid.bytes), recordBytes);
            });
            resolve(recordCid);
        });
    }

    async validateRecord(collection, record) {
        console.log('Validating record:', { collection, record });
        
        if (!record || typeof record !== 'object') {
            console.error('Invalid record:', record);
            throw new Error('Invalid record: must be an object');
        }

        // Basic validation for app.bsky.feed.post
        if (collection === 'app.bsky.feed.post') {
            if (!record.text || typeof record.text !== 'string') {
                throw new Error('Invalid post: must have text field');
            }
            if (!record.createdAt || typeof record.createdAt !== 'string') {
                throw new Error('Invalid post: must have createdAt field');
            }
            // Validate createdAt is a valid ISO date
            try {
                new Date(record.createdAt);
            } catch (e) {
                throw new Error('Invalid post: createdAt must be a valid ISO date');
            }
        }

        return true;
    }

    async createRecord(collection, repo, record, rkey = null, validate = true) {
        console.log('Starting createRecord:', { collection, repo, record, rkey, validate });
        
        if (!record || typeof record !== 'object') {
            console.error('Invalid record:', record);
            throw new Error('Invalid record: must be an object');
        }

        if (!collection || typeof collection !== 'string') {
            console.error('Invalid collection:', collection);
            throw new Error('Invalid collection: must be a string');
        }

        if (!repo || typeof repo !== 'string') {
            console.error('Invalid repo:', repo);
            throw new Error('Invalid repo: must be a string');
        }

        const recordKey = rkey || tidNow();
        const fullKey = `${collection}/${recordKey}`;
        
        if (validate) {
            await this.validateRecord(collection, record);
        }
        
        // Handle blob references
        if (record.blobs) {
            for (const blob of record.blobs) {
                if (blob.ref) {
                    blob.ref = CID.parse(blob.ref.$link);
                }
            }
        }
        
        // Clean the record to remove any undefined values
        const cleanedRecord = cleanObject(record);
        console.log('Cleaned record:', cleanedRecord);
        
        // Encode the record
        const recordBytes = dagCbor.encode(cleanedRecord);
        const recordCid = await hashToCid(recordBytes);
        
        // Update MST
        this.tree = await this.tree.set(fullKey, recordCid);
        
        // Get the root CID and serialized data
        const rootCid = await this.tree.getCid();
        const rootSerialised = await this.tree.getSerialised();
        
        console.log('Root CID:', rootCid.toString());
        console.log('Root serialised length:', rootSerialised.length);
        
        // Get the latest commit
        const latestCommit = this.con.prepare(
            "SELECT c.commit_seq, b.block_value FROM commits c INNER JOIN blocks b ON b.block_cid=c.commit_cid ORDER BY c.commit_seq DESC LIMIT 1"
        ).get();
        
        // Create new commit
        const commit = cleanObject({
            version: 3,
            data: rootCid.toString(),
            rev: tidNow(),
            prev: latestCommit ? latestCommit.block_value : null,
            did: this.did
        });
        
        // Sign the commit
        const commitBytes = dagCbor.encode(commit);
        const commitCid = await hashToCid(commitBytes);
        const signature = await rawSign(this.signingKey, commitBytes);
        commit.sig = signature;
        
        // Store blocks in database
        this.con.transaction(() => {
            // Store record block
            this.con.prepare(
                "INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)"
            ).run(Buffer.from(recordCid.bytes), recordBytes);
            
            // Store root block
            this.con.prepare(
                "INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)"
            ).run(Buffer.from(rootCid.bytes), rootSerialised);
            
            // Store commit block
            this.con.prepare(
                "INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)"
            ).run(Buffer.from(commitCid.bytes), commitBytes);
            
            // Update records table
            this.con.prepare(`
                INSERT INTO records (rkey, collection, cid, repo, commit_cid, prev_cid, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).run(recordKey, collection, recordCid.toString(), repo, commitCid.toString(), latestCommit?.block_value?.toString(), recordBytes);
            
            // Update commits table
            const row = this.con.prepare("SELECT MAX(commit_seq) as max_seq FROM commits").get();
            const nextSeq = (row?.max_seq ?? -1) + 1;
            this.con.prepare(
                "INSERT INTO commits (commit_seq, commit_cid, block_value) VALUES (?, ?, ?)"
            ).run(nextSeq, Buffer.from(commitCid.bytes), commitBytes);
        })();
        
        // Update head
        this.head = commitCid;

        // Create firehose message in Python format
        const header = dagCbor.encode({
            t: "#commit",
            op: 1
        });

        const body = dagCbor.encode({
            ops: [{
                cid: recordCid,
                path: fullKey,
                action: "create"
            }],
            seq: Math.floor(Date.now() * 1000000), // Use microseconds like Python
            rev: commit.rev,
            since: latestCommit?.block_value?.rev || null,
            prev: null,
            repo: this.did,
            time: new Date().toISOString().replace('.000Z', 'Z'), // Match Python's format
            blobs: [],
            blocks: [commitCid, recordCid, rootCid].map(cid => ({
                cid: cid.toString(),
                bytes: Buffer.from(cid.bytes).toString('base64')
            })),
            commit: commitCid.toString(),
            rebase: false,
            tooBig: false
        });

        // Concatenate the two parts like Python does
        const firehoseMsg = Buffer.concat([header, body]);
        
        return {
            uri: `at://${repo}/${collection}/${recordKey}`,
            cid: recordCid.toString(),
            commitCid: commitCid.toString(),
            firehoseMsg
        };
    }

    async deleteRecord(collection, rkey) {
        try {
            const recordKey = `${collection}/${rkey}`;
            const [existingUri, existingCid, existingValue] = await this.getRecord(collection, rkey);
            
            // Handle blob references
            const existingValueRecord = dagCbor.decode(existingValue);
            for (const blob of enumerateRecordCids(existingValueRecord)) {
                await this.decrefBlob(blob);
            }
            
            const dbBlockInserts = [];
            const newBlocks = new Set();
            this.tree.delete(recordKey, newBlocks);
            for (const block of newBlocks) {
                dbBlockInserts.push([Buffer.from(block.cid.bytes), block.serialised]);
            }
            
            // Get previous commit
            const prevCommit = this.con.prepare(
                "SELECT commit_seq, block_value FROM commits INNER JOIN blocks ON block_cid=commit_cid ORDER BY commit_seq DESC LIMIT 1"
            ).get();
            
            const prevCommitData = dagCbor.decode(prevCommit.block_value);
            
            // Create new commit
            const newCommitRev = tidNow();
            const commit = cleanObject({
                version: 3,
                data: this.tree.cid.toString(),
                rev: newCommitRev,
                prev: null,
                did: this.did
            });
            
            // Sign the commit
            const commitBytes = dagCbor.encode(commit);
            const commitSig = await rawSign(this.signingKey, commitBytes);
            commit.sig = commitSig;
            
            const commitBlob = dagCbor.encode(commit);
            const commitCid = await hashToCid(commitBlob);
            dbBlockInserts.push([Buffer.from(commitCid.bytes), commitBlob]);
            
            // Create firehose message
            const firehoseBlob = Buffer.concat([
                dagCbor.encode({
                    t: "#commit",
                    op: 1
                }),
                dagCbor.encode({
                    ops: [{
                        cid: null,
                        path: recordKey,
                        action: "delete"
                    }],
                    seq: Math.floor(Date.now() * 1000000), // Use microseconds like Python
                    rev: newCommitRev,
                    since: prevCommitData.rev,
                    prev: prevCommitData.prev || null,
                    repo: this.did,
                    time: new Date().toISOString().replace('.000Z', 'Z'), // Match Python's format
                    blobs: [],
                    blocks: await serialise([commitCid], dbBlockInserts),
                    commit: commitCid.toString(),
                    rebase: false,
                    tooBig: false
                })
            ]);
            
            // Insert blocks into database
            await new Promise((resolve, reject) => {
                this.con.transaction(() => {
                    const stmt = this.con.prepare("INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)");
                    for (const [cid, value] of dbBlockInserts) {
                        stmt.run([cid, value]);
                    }
                    
                    // Delete record
                    this.con.run("DELETE FROM records WHERE record_key = ?", [recordKey]);
                    
                    // Get the next commit sequence number
                    const row = this.con.prepare("SELECT MAX(commit_seq) as max_seq FROM commits").get();
                    const nextSeq = (row?.max_seq ?? -1) + 1;
                    
                    // Insert commit with the next sequence number
                    this.con.run("INSERT INTO commits (commit_seq, commit_cid) VALUES (?, ?)", 
                        [nextSeq, Buffer.from(commitCid.bytes)], (err) => {
                            if (err) {
                                reject(err);
                                return;
                            }
                            resolve();
                        });
                });
            });
            
            return firehoseBlob;
        } catch (err) {
            logger.error('Error in deleteRecord:', err);
            throw err;
        }
    }

    async increfBlob(cid) {
        return new Promise((resolve, reject) => {
            this.con.run(
                "UPDATE blobs SET blob_refcount = blob_refcount + 1 WHERE blob_cid = ?",
                [cid.toString()],
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
        });
    }

    async decrefBlob(cid) {
        return new Promise((resolve, reject) => {
            this.con.run(
                "UPDATE blobs SET blob_refcount = blob_refcount - 1 WHERE blob_cid = ?",
                [cid.toString()],
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
            this.con.run(
                "DELETE FROM blobs WHERE blob_cid = ? AND blob_refcount < 1",
                [cid.toString()],
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
        });
    }

    async getRecord(uri, cid) {
        try {
            const record = this.con.prepare(
                'SELECT * FROM records WHERE uri = ? AND (cid = ? OR ? IS NULL)'
            ).get(uri, cid, cid);
            if (!record) {
                return null;
            }
            return {
                uri,
                cid: record.cid,
                value: await this.getBlock(record.cid)
            };
        } catch (error) {
            logger.error('Error in getRecord:', error);
            throw error;
        }
    }

    async getPreferences() {
        const row = this.con.prepare(
            "SELECT preferences_blob FROM preferences WHERE preferences_did = ?"
        ).get(this.did);
        return row ? row.preferences_blob : dagCbor.encode({ preferences: [] });
    }

    async putPreferences(blob) {
        return new Promise((resolve, reject) => {
            this.con.run(
                "INSERT OR REPLACE INTO preferences (preferences_did, preferences_blob) VALUES (?, ?)",
                [this.did, blob],
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
        });
    }

    async putBlob(data) {
        const cid = await hashToCid(data);
        
        return new Promise((resolve, reject) => {
            this.con.run(
                "INSERT OR IGNORE INTO blobs (blob_cid, blob_data, blob_refcount) VALUES (?, ?, 0)",
                [cid.toString(), data],
                (err) => {
                    if (err) reject(err);
                    resolve({
                        ref: cid.toString(),
                        size: data.length,
                        mimeType: 'application/octet-stream'
                    });
                }
            );
        });
    }

    async getBlob(cid) {
        const row = this.con.prepare(
            "SELECT blob_data FROM blobs WHERE blob_cid = ? AND blob_refcount > 0"
        ).get(cid.toString());
        if (!row) throw new Error("Blob not found");
        return row.blob_data;
    }

    async getCheckout(commit = null) {
        try {
            // If no commit specified, get the latest commit
            if (!commit) {
                const latestCommit = this.con.prepare(
                    "SELECT commit_seq, commit_cid FROM commits ORDER BY commit_seq DESC LIMIT 1"
                ).get();
                if (!latestCommit) {
                    throw new Error("No commits found");
                }
                commit = CID.decode(latestCommit.commit_cid);
            }

            // Get all blocks from the database
            const blocks = await new Promise((resolve, reject) => {
                this.con.all(
                    "SELECT block_cid, block_value FROM blocks",
                    (err, rows) => {
                        if (err) reject(err);
                        resolve(rows);
                    }
                );
            });

            // Convert blocks to the format needed for CAR serialization
            const carBlocks = blocks.map(row => [
                Buffer.from(row.block_cid), // Use raw bytes for CID
                row.block_value
            ]);

            // Serialize to CAR format using carfile.js
            return serialise([commit], carBlocks);
        } catch (err) {
            logger.error('Error in getCheckout:', err);
            throw err;
        }
    }

    async getRepo(did) {
        try {
            const repo = this.con.prepare(
                'SELECT * FROM repos WHERE did = ?'
            ).get(did);
            if (!repo) {
                return null;
            }
            return {
                did,
                root: repo.root,
                rev: repo.rev
            };
        } catch (error) {
            logger.error('Error in getRepo:', error);
            throw error;
        }
    }

    async getBlocks(did, cids) {
        try {
            const blocks = [];
            for (const cid of cids) {
                const block = await this.getBlock(cid);
                if (block) {
                    blocks.push({
                        cid,
                        data: block
                    });
                }
            }
            return blocks;
        } catch (error) {
            logger.error('Error in getBlocks:', error);
            throw error;
        }
    }

    async getCommitPath(did, latest, earliest) {
        try {
            const commits = await this.con.all(
                'SELECT * FROM commits WHERE did = ? AND rev <= ? AND rev >= ? ORDER BY rev DESC',
                [did, latest, earliest || 0]
            );
            if (!commits.length) {
                return null;
            }
            return commits.map(commit => ({
                cid: commit.cid,
                rev: commit.rev
            }));
        } catch (error) {
            logger.error('Error in getCommitPath:', error);
            throw error;
        }
    }

    async listRepos(limit = 50, cursor = null) {
        try {
            const repos = await this.con.all(
                'SELECT * FROM repos WHERE did > ? ORDER BY did LIMIT ?',
                [cursor || '', limit]
            );
            return {
                repos: repos.map(repo => ({
                    did: repo.did,
                    root: repo.root,
                    rev: repo.rev
                })),
                cursor: repos.length === limit ? repos[repos.length - 1].did : null
            };
        } catch (error) {
            logger.error('Error in listRepos:', error);
            throw error;
        }
    }

    async notifyOfUpdate(hostname) {
        try {
            await this.con.run(
                'INSERT OR REPLACE INTO updates (hostname, last_update) VALUES (?, ?)',
                [hostname, Date.now()]
            );
        } catch (error) {
            logger.error('Error in notifyOfUpdate:', error);
            throw error;
        }
    }

    async requestCrawl(hostname) {
        try {
            const update = this.con.prepare(
                'SELECT * FROM updates WHERE hostname = ?'
            ).get(hostname);
            if (!update) {
                return;
            }
            // Implement crawl logic here
        } catch (error) {
            logger.error('Error in requestCrawl:', error);
            throw error;
        }
    }

    async createCommit(recordKey, recordCid) {
        logger.info('Creating commit for record:', recordKey);
        
        try {
            // Get the latest commit
            const latestCommit = this.con.prepare(
                "SELECT commit_seq, block_value FROM commits INNER JOIN blocks ON block_cid=commit_cid ORDER BY commit_seq DESC LIMIT 1"
            ).get();

            // Ensure tree is initialized
            if (!this.tree || !this.tree.root) {
                logger.error('Tree not properly initialized');
                throw new Error('Tree not properly initialized');
            }

            // Get the tree CID
            const treeCid = await this.tree.getCid();
            if (!treeCid) {
                logger.error('Tree CID not available');
                throw new Error('Tree CID not available');
            }

            // Create new commit
            const newCommitRev = tidNow();
            const commit = cleanObject({
                version: 3,
                data: treeCid.toString(),
                rev: newCommitRev,
                prev: latestCommit ? latestCommit.block_value : null,
                did: this.did
            });

            logger.info('Created commit object:', commit);
            return commit;
        } catch (error) {
            logger.error('Error in createCommit:', error);
            throw error;
        }
    }

    async signCommit(commit) {
        logger.info('Signing commit');
        
        // Encode the commit
        const commitBytes = dagCbor.encode(commit);
        
        // Sign the commit
        const commitSig = await rawSign(this.signingKey, commitBytes);
        
        // Add signature to commit
        commit.sig = commitSig;
        
        logger.info('Commit signed successfully');
        return commit;
    }
}

// Export the Repo class and other required exports
export { Repo, ATNode, tidNow, hashToCid, dtToStr, timestampStrNow }; 