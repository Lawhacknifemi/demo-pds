import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { base32 } from 'multiformats/bases/base32';
import Database from 'better-sqlite3';
import { promisify } from 'util';
import { MSTNode, MST, StrlenNode } from './mst.js';
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
        this.tree = new MST(StrlenNode.emptyRoot());
    }

    static async initialize(did, db, signingKey, tree) {
        const repo = new Repo(did, db, signingKey, tree);
        
        // Initialize database tables
        const statements = [
            // Create tables if they don't exist
            `CREATE TABLE IF NOT EXISTS blocks (
                block_cid BLOB PRIMARY KEY NOT NULL,
                block_value BLOB NOT NULL
            )`,

            `CREATE TABLE IF NOT EXISTS commits (
                commit_seq INTEGER PRIMARY KEY NOT NULL,
                commit_cid BLOB NOT NULL,
                block_value BLOB NOT NULL
            )`,

            `CREATE TABLE IF NOT EXISTS blobs (
                blob_cid BLOB PRIMARY KEY NOT NULL,
                blob_data BLOB NOT NULL,
                blob_refcount INTEGER NOT NULL DEFAULT 0
            )`,

            `CREATE TABLE IF NOT EXISTS repos (
                did TEXT PRIMARY KEY NOT NULL,
                root TEXT NOT NULL,
                rev TEXT NOT NULL
            )`,

            `CREATE TABLE IF NOT EXISTS records (
                rkey TEXT NOT NULL,
                collection TEXT NOT NULL,
                cid TEXT NOT NULL,
                repo TEXT NOT NULL,
                commit_cid TEXT NOT NULL,
                prev_cid TEXT,
                data BLOB NOT NULL,
                PRIMARY KEY (rkey, collection, repo)
            )`
        ];

        // Execute each statement
        for (const statement of statements) {
            repo.con.prepare(statement).run();
        }

        // Create initial commit if needed
        const row = repo.con.prepare("SELECT * FROM commits WHERE commit_seq=0").get();
        if (!row) {
            try {
                // Get the root node's CID and serialised data
                const rootCid = await repo.tree.getCid();
                const rootSerialised = await repo.tree.getSerialised();
                
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
        const referencedBlobs = new Set();
        if (record.blobs) {
            for (const blob of record.blobs) {
                if (blob.ref) {
                    const blobCid = CID.parse(blob.ref.$link);
                    referencedBlobs.add(blobCid);
                    await this.increfBlob(blobCid);
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
        const newCommitRev = tidNow();
        const commit = {
            version: 3,
            data: await this.tree.getCid(),  // Use CID object, not string
            rev: newCommitRev,
            prev: latestCommit ? latestCommit.block_value : null,
            did: this.did
        };
        
        // Sign the commit
        const commitBytes = dagCbor.encode(commit);
        const commitCid = await hashToCid(commitBytes);
        const signature = await rawSign(this.signingKey, commitBytes);
        commit.sig = signature;
        
        // Prepare database block inserts
        const dbBlockInserts = [
            [Buffer.from(recordCid.bytes), recordBytes],
            [Buffer.from(rootCid.bytes), rootSerialised],
            [Buffer.from(commitCid.bytes), commitBytes]
        ];
        
        // Calculate next sequence number before transaction
        const row = this.con.prepare("SELECT MAX(commit_seq) as max_seq FROM commits").get();
        const nextSeq = (row?.max_seq ?? -1) + 1;
        
        // Store blocks in database
        this.con.transaction(() => {
            // Store all blocks
            const stmt = this.con.prepare(
                "INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)"
            );
            for (const [cid, value] of dbBlockInserts) {
                stmt.run(cid, value);
            }
            
            // Update records table
            this.con.prepare(`
                INSERT INTO records (rkey, collection, cid, repo, commit_cid, prev_cid, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).run(recordKey, collection, recordCid.toString(), repo, commitCid.toString(), latestCommit?.block_value?.toString(), Buffer.from(recordBytes));
            
            // Update commits table
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

        // Include ALL new blocks in the firehose message (like Python does)
        const firehoseBlockInserts = [
            [new Uint8Array(recordCid.bytes), new Uint8Array(recordBytes)],
            [new Uint8Array(rootCid.bytes), new Uint8Array(rootSerialised)],
            [new Uint8Array(commitCid.bytes), new Uint8Array(commitBytes)]
        ];

        // Get previous commit for prevData
        const prevCommit = this.con.prepare(
            "SELECT c.commit_seq, b.block_value FROM commits c INNER JOIN blocks b ON b.block_cid=c.commit_cid ORDER BY c.commit_seq DESC LIMIT 1"
        ).get();
        
        const prevCommitData = prevCommit ? dagCbor.decode(prevCommit.block_value) : null;

        const body = {
            ops: [{
                cid: recordCid,
                path: fullKey,
                action: "create"
            }],
            seq: nextSeq,  // Use the same sequence number as the database
            rev: commit.rev,
            since: latestCommit ? dagCbor.decode(latestCommit.block_value).rev : null,
            prev: null,
            repo: this.did,
            time: new Date().toISOString().replace('.000Z', 'Z'),
            blobs: Array.from(referencedBlobs).map(cid => cid.bytes),
            blocks: await serialise([commitCid], firehoseBlockInserts),
            commit: commitCid,
            rebase: false,
            tooBig: false,
            prevData: prevCommitData ? prevCommitData.data : null
        };

        // Concatenate the two parts like Python does
        const firehoseMsg = Buffer.concat([header, dagCbor.encode(body)]);
        
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
            
            // Update MST
            this.tree = await this.tree.delete(recordKey);
            
            // Get the root CID and serialized data
            const rootCid = await this.tree.getCid();
            const rootSerialised = await this.tree.getSerialised();
            
            // Get previous commit
            const prevCommit = this.con.prepare(
                "SELECT c.commit_seq, b.block_value FROM commits c INNER JOIN blocks b ON b.block_cid=c.commit_cid ORDER BY c.commit_seq DESC LIMIT 1"
            ).get();
            
            const prevCommitData = dagCbor.decode(prevCommit.block_value);
            
            // Create new commit
            const newCommitRev = tidNow();
            const commit = cleanObject({
                version: 3,
                data: rootCid,  // Use CID object, not string
                rev: newCommitRev,
                prev: null,
                did: this.did
            });
            
            // Sign the commit
            const commitBytes = dagCbor.encode(commit);
            const commitCid = await hashToCid(commitBytes);
            const commitSig = await rawSign(this.signingKey, commitBytes);
            commit.sig = commitSig;
            
            const commitBlob = dagCbor.encode(commit);
            
            // Prepare database block inserts
            const dbBlockInserts = [
                [new Uint8Array(rootCid.bytes), new Uint8Array(rootSerialised)],
                [new Uint8Array(commitCid.bytes), new Uint8Array(commitBlob)]
            ];
            
            // Calculate next sequence number before transaction
            const row = this.con.prepare("SELECT MAX(commit_seq) as max_seq FROM commits").get();
            const nextSeq = (row?.max_seq ?? -1) + 1;
            
            // Generate CAR file bytes for blocks field
            const carBytes = await serialise([commitCid], dbBlockInserts);
            
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
                        action: "delete",
                        prev: existingCid
                    }],
                    seq: nextSeq,  // Use the same sequence number as the database
                    rev: newCommitRev,
                    since: prevCommitData.rev,
                    prev: prevCommitData.prev || null,
                    repo: this.did,
                    time: new Date().toISOString().replace('.000Z', 'Z'),
                    blobs: [],
                    blocks: carBytes,
                    commit: commitCid.toString(),
                    rebase: false,
                    tooBig: false,
                    prevData: prevCommitData ? prevCommitData.data : null
                })
            ]);
            
            // Insert blocks into database
            this.con.transaction(() => {
                const stmt = this.con.prepare("INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)");
                for (const [cid, value] of dbBlockInserts) {
                    stmt.run(cid, value);
                }
                
                // Delete record
                this.con.prepare("DELETE FROM records WHERE rkey = ? AND collection = ?").run(rkey, collection);
                
                // Insert commit with the next sequence number
                this.con.prepare("INSERT INTO commits (commit_seq, commit_cid, block_value) VALUES (?, ?, ?)").run(nextSeq, Buffer.from(commitCid.bytes), commitBlob);
            })();
            
            return firehoseBlob;
        } catch (err) {
            logger.error('Error in deleteRecord:', err);
            throw err;
        }
    }

    async increfBlob(cid) {
        this.con.prepare(
            "UPDATE blobs SET blob_refcount = blob_refcount + 1 WHERE blob_cid = ?"
        ).run(cid.toString());
    }

    async decrefBlob(cid) {
        this.con.prepare(
            "UPDATE blobs SET blob_refcount = blob_refcount - 1 WHERE blob_cid = ?"
        ).run(cid.toString());
        
        this.con.prepare(
            "DELETE FROM blobs WHERE blob_cid = ? AND blob_refcount < 1"
        ).run(cid.toString());
    }

    async getRecord(collection, rkey) {
        try {
            const record = this.con.prepare(
                'SELECT * FROM records WHERE collection = ? AND rkey = ?'
            ).get(collection, rkey);
            if (!record) {
                throw new Error("record not found");
            }
            console.log('Record from DB:', {
                collection: record.collection,
                rkey: record.rkey,
                dataType: typeof record.data,
                isBuffer: Buffer.isBuffer(record.data),
                dataLength: record.data ? record.data.length : 0,
                dataSample: record.data ? record.data.slice(0, 32) : null
            });
            
            // Convert Buffer to Uint8Array for dagCbor.decode
            const uint8Array = new Uint8Array(record.data);
            console.log('Converted to Uint8Array:', {
                type: uint8Array.constructor.name,
                length: uint8Array.length,
                sample: Array.from(uint8Array.slice(0, 32))
            });
            
            const decodedValue = dagCbor.decode(uint8Array);
            console.log('Decoded value:', decodedValue);
            
            return [
                `at://${record.repo}/${record.collection}/${record.rkey}`,
                CID.parse(record.cid),
                record.data
            ];
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
        this.con.prepare(
            "INSERT OR REPLACE INTO preferences (preferences_did, preferences_blob) VALUES (?, ?)"
        ).run(this.did, blob);
    }

    async putBlob(data) {
        const cid = await hashToCid(data);
        
        this.con.prepare(
            "INSERT OR IGNORE INTO blobs (blob_cid, blob_data, blob_refcount) VALUES (?, ?, 0)"
        ).run(cid.toString(), data);
        
        return {
            ref: cid.toString(),
            size: data.length,
            mimeType: 'application/octet-stream'
        };
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
            const blocks = this.con.prepare(
                "SELECT block_cid, block_value FROM blocks"
            ).all();

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
            const commits = this.con.prepare(
                'SELECT * FROM commits WHERE did = ? AND rev <= ? AND rev >= ? ORDER BY rev DESC'
            ).all(did, latest, earliest || 0);
            
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
            const repos = this.con.prepare(
                'SELECT * FROM repos WHERE did > ? ORDER BY did LIMIT ?'
            ).all(cursor || '', limit);
            
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

    async createCommit(collection, rkey, valueCid, referencedBlobs, dbBlockInserts) {
        logger.info('Creating commit for record:', rkey);

        const latestCommitStmt = this.con.prepare(`
            SELECT c.commit_seq, b.block_value
            FROM commits c
            JOIN blocks b ON c.commit_cid = b.block_cid
            ORDER BY c.commit_seq DESC
            LIMIT 1
        `);
        const latestCommitResult = latestCommitStmt.get();
        const prevCommitSeq = latestCommitResult.commit_seq;
        const prevCommit = dagCbor.decode(latestCommitResult.block_value);
        
        const newCommitRev = tidNow();
        const commit = {
            version: 3,
            data: (await this.tree.getCid()).toString(),
            rev: newCommitRev,
            prev: prevCommit.cid,
            did: this.did
        };
        commit.sig = await this.signCommit(commit);
        const commitBytes = dagCbor.encode(commit);
        const commitCid = await hashToCid(commitBytes);
        dbBlockInserts.push([commitCid.bytes, commitBytes]);

        const recordKey = `${collection}/${rkey}`;
        const uri = `at://${this.did}/${recordKey}`;

        // CONSTRUCT FIREHOSE MESSAGE LIKE PYTHON
        const ops = [{ action: 'create', cid: valueCid, path: recordKey }];
        const header = { t: '#commit', op: 1 };
        
        // Only serialize the commit block for the firehose message
        const commitBlockInserts = [[commitCid.bytes, commitBytes]];
        
        const body = {
            ops: ops,
            seq: prevCommitSeq + 1,  // Use incrementing integer instead of timestamp
            rev: newCommitRev,
            since: prevCommit.rev,
            repo: this.did,
            time: timestampStrNow(),
            blobs: Array.from(referencedBlobs).map(cid => cid.bytes),
            blocks: await serialise([commitCid], commitBlockInserts),
            commit: commitCid,
            rebase: false,
            tooBig: false,
        };

        const firehoseMsg = Buffer.concat([
            dagCbor.encode(header),
            dagCbor.encode(body)
        ]);
        
        // Database updates
        this.con.prepare('INSERT OR IGNORE INTO records (record_key, record_cid) VALUES (?, ?)').run(recordKey, valueCid.bytes);
        const stmt = this.con.prepare('INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)');
        for (const block of dbBlockInserts) {
            stmt.run(block[0], block[1]);
        }
        this.con.prepare('INSERT INTO commits (commit_seq, commit_cid) VALUES (?, ?)').run(prevCommitSeq + 1, commitCid.bytes);

        return { firehoseMsg, uri, cid: valueCid };
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
export { Repo, tidNow, hashToCid, dtToStr, timestampStrNow }; 