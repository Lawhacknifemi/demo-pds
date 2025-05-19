import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { base32 } from 'multiformats/bases/base32';
import sqlite3 from 'sqlite3';
import { promisify } from 'util';
import { MSTNode } from './mst.js';
import { rawSign } from './signing.js';
import { serialise } from './carfile.js';
import { randomInt } from 'crypto';
import { createHash } from 'crypto';
import pkg from 'base64url';
import winston from 'winston';
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
    const micros = Math.floor(Date.now() * 1000); // Convert to microseconds
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
        return key.length;
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

class Repo {
    constructor(did, db, signingKey, tree) {
        this.did = did;
        this.con = new sqlite3.Database(db);
        this.signingKey = signingKey;
        this.tree = tree;

        // Enable WAL mode
        this.con.run("pragma journal_mode=wal");

        // Create tables
        this.con.serialize(() => {
            this.con.run(`
                CREATE TABLE IF NOT EXISTS records (
                    record_key TEXT PRIMARY KEY NOT NULL,
                    record_cid BLOB NOT NULL
                )
            `);
            this.con.run(`
                CREATE TABLE IF NOT EXISTS blocks (
                    block_cid BLOB PRIMARY KEY NOT NULL,
                    block_value BLOB NOT NULL
                )
            `);
            this.con.run(`
                CREATE TABLE IF NOT EXISTS commits (
                    commit_seq INTEGER PRIMARY KEY NOT NULL,
                    commit_cid BLOB NOT NULL
                )
            `);
            this.con.run(`
                CREATE TABLE IF NOT EXISTS preferences (
                    preferences_did TEXT PRIMARY KEY NOT NULL,
                    preferences_blob BLOB NOT NULL
                )
            `);
            this.con.run(`
                CREATE TABLE IF NOT EXISTS blobs (
                    blob_cid BLOB PRIMARY KEY NOT NULL,
                    blob_data BLOB NOT NULL,
                    blob_refcount INTEGER NOT NULL
                )
            `);
        });

        // Create initial commit if needed
        this.con.get("SELECT * FROM commits WHERE commit_seq=0", async (err, row) => {
            if (err) throw err;
            if (!row) {
                const commit = cleanObject({
                    version: 3,
                    data: this.tree.cid.toString(),
                    rev: tidNow(),
                    did: this.did,
                    prev: null
                });
                
                const commitBlob = dagCbor.encode(commit);
                const commitCid = await hashToCid(commitBlob);
                commit.sig = rawSign(this.signingKey, commitBlob);

                this.con.serialize(() => {
                    this.con.run(
                        "INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)",
                        [Buffer.from(this.tree.cid.bytes), this.tree.value || Buffer.from([])]
                    );
                    this.con.run(
                        "INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)",
                        [Buffer.from(commitCid.bytes), commitBlob]
                    );
                    this.con.run(
                        "INSERT INTO commits (commit_seq, commit_cid) VALUES (?, ?)",
                        [0, Buffer.from(commitCid.bytes)]
                    );
                });
            }
        });

        // Load existing records
        this.con.each("SELECT record_key, record_cid FROM records", (err, row) => {
            if (err) throw err;
            this.tree.put(row.record_key, CID.decode(row.record_cid));
        });
    }

    static async create(did, db, signingKey) {
        const tree = ATNode.empty_root();
        const emptyRootData = dagCbor.encode({});
        const emptyRootCid = await hashToCid(emptyRootData);
        return new Repo(did, db, signingKey, tree);
    }

    async createRecord(collection, record, rkey = null) {
        try {
            logger.debug(`Creating record in collection: ${collection}, rkey: ${rkey}`);
            
            if (!rkey) {
                rkey = tidNow();
            }
            
            const recordKey = `${collection}/${rkey}`;
            
            // Clean the record before processing
            const cleanRecord = cleanObject(record);
            logger.debug('Cleaned record:', cleanRecord);
            
            // Handle blob references
            const referencedBlobs = new Set();
            for (const cid of enumerateRecordCids(cleanRecord)) {
                referencedBlobs.add(cid);
                await this.increfBlob(cid);
            }
            
            const value = dagCbor.encode(cleanRecord);
            const valueCid = await hashToCid(value);
            const dbBlockInserts = [[Buffer.from(valueCid.bytes), value]];
            
            // Update MST
            const newBlocks = new Set();
            this.tree = this.tree.put(recordKey, valueCid, newBlocks);
            for (const block of newBlocks) {
                dbBlockInserts.push([Buffer.from(block.cid.bytes), block.serialised]);
            }
            
            // Get previous commit
            const prevCommit = await new Promise((resolve, reject) => {
                this.con.get(
                    "SELECT commit_seq, block_value FROM commits INNER JOIN blocks ON block_cid=commit_cid ORDER BY commit_seq DESC LIMIT 1",
                    (err, row) => {
                        if (err) reject(err);
                        resolve(row);
                    }
                );
            });
            
            if (!prevCommit) {
                // Create initial commit if it doesn't exist
                const commit = cleanObject({
                    version: 3,
                    data: this.tree.cid.toString(),
                    rev: tidNow(),
                    did: this.did,
                    prev: null
                });
                
                const commitBlob = dagCbor.encode(commit);
                const commitCid = await hashToCid(commitBlob);
                commit.sig = await rawSign(this.signingKey, commitBlob);

                await new Promise((resolve, reject) => {
                    this.con.serialize(() => {
                        this.con.run(
                            "INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)",
                            [Buffer.from(this.tree.cid.bytes), this.tree.value || Buffer.from([])]
                        );
                        this.con.run(
                            "INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)",
                            [Buffer.from(commitCid.bytes), commitBlob]
                        );
                        this.con.run(
                            "INSERT INTO commits (commit_seq, commit_cid) VALUES (?, ?)",
                            [0, Buffer.from(commitCid.bytes)]
                        );
                        resolve();
                    });
                });
                
                prevCommit = { commit_seq: 0, block_value: commitBlob };
            }
            
            const prevCommitData = dagCbor.decode(prevCommit.block_value);
            
            // Create new commit
            const newCommitRev = tidNow();
            const commit = cleanObject({
                version: 3,
                data: this.tree.cid,
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
                dagCbor.encode({ t: "#commit", op: 1 }),
                dagCbor.encode({
                    ops: [{
                        cid: valueCid,
                        path: recordKey,
                        action: "create"
                    }],
                    seq: Math.floor(Date.now() * 1000), // Microseconds timestamp
                    rev: newCommitRev,
                    since: prevCommitData.rev,
                    prev: null,
                    repo: this.did,
                    time: new Date().toISOString().replace('.000Z', 'Z'), // Match Python's format
                    blobs: Array.from(referencedBlobs),
                    blocks: await serialise([commitCid], dbBlockInserts), // Use the same serialization as Python
                    commit: commitCid,
                    rebase: false,
                    tooBig: false
                })
            ]);
            
            // Insert blocks into database
            await new Promise((resolve, reject) => {
                this.con.run("BEGIN TRANSACTION");
                const stmt = this.con.prepare("INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)");
                for (const [cid, value] of dbBlockInserts) {
                    stmt.run([cid, value]);
                }
                stmt.finalize();
                
                // Update records
                this.con.run("INSERT OR REPLACE INTO records (record_key, record_cid) VALUES (?, ?)", 
                    [recordKey, Buffer.from(valueCid.bytes)]);
                
                // Get the next commit sequence number
                this.con.get("SELECT MAX(commit_seq) as max_seq FROM commits", (err, row) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    const nextSeq = (row?.max_seq ?? -1) + 1;
                    
                    // Insert commit with the next sequence number
                    this.con.run("INSERT INTO commits (commit_seq, commit_cid) VALUES (?, ?)", 
                        [nextSeq, Buffer.from(commitCid.bytes)], (err) => {
                            if (err) {
                                reject(err);
                                return;
                            }
                            this.con.run("COMMIT", (err) => {
                                if (err) reject(err);
                                else resolve();
                            });
                        });
                });
            });
            
            logger.info(`Record created successfully. URI: at://${this.did}/${recordKey}, CID: ${valueCid}`);
            return [`at://${this.did}/${recordKey}`, valueCid, firehoseBlob];
        } catch (err) {
            logger.error('Error in createRecord:', err);
            throw err;
        }
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
            this.tree = this.tree.delete(recordKey, newBlocks);
            for (const block of newBlocks) {
                dbBlockInserts.push([Buffer.from(block.cid.bytes), block.serialised]);
            }
            
            // Get previous commit
            const prevCommit = await new Promise((resolve, reject) => {
                this.con.get(
                    "SELECT commit_seq, block_value FROM commits INNER JOIN blocks ON block_cid=commit_cid ORDER BY commit_seq DESC LIMIT 1",
                    (err, row) => {
                        if (err) reject(err);
                        resolve(row);
                    }
                );
            });
            
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
                dagCbor.encode({ t: "#commit", op: 1 }),
                dagCbor.encode({
                    ops: [{
                        cid: null,
                        path: recordKey,
                        action: "delete"
                    }],
                    seq: Math.floor(Date.now() * 1000), // Microseconds timestamp
                    rev: newCommitRev,
                    since: prevCommitData.rev,
                    prev: null,
                    repo: this.did,
                    time: new Date().toISOString().replace('.000Z', 'Z'), // Match Python's format
                    blobs: [],
                    blocks: await serialise([commitCid], dbBlockInserts), // Use the same serialization as Python
                    commit: commitCid,
                    rebase: false,
                    tooBig: false
                })
            ]);
            
            // Insert blocks into database
            await new Promise((resolve, reject) => {
                this.con.run("BEGIN TRANSACTION");
                const stmt = this.con.prepare("INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)");
                for (const [cid, value] of dbBlockInserts) {
                    stmt.run([cid, value]);
                }
                stmt.finalize();
                
                // Delete record
                this.con.run("DELETE FROM records WHERE record_key = ?", [recordKey]);
                
                // Get the next commit sequence number
                this.con.get("SELECT MAX(commit_seq) as max_seq FROM commits", (err, row) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    const nextSeq = (row?.max_seq ?? -1) + 1;
                    
                    // Insert commit with the next sequence number
                    this.con.run("INSERT INTO commits (commit_seq, commit_cid) VALUES (?, ?)", 
                        [nextSeq, Buffer.from(commitCid.bytes)], (err) => {
                            if (err) {
                                reject(err);
                                return;
                            }
                            this.con.run("COMMIT", (err) => {
                                if (err) reject(err);
                                else resolve();
                            });
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

    async getRecord(collection, rkey) {
        return new Promise((resolve, reject) => {
            const recordKey = `${collection}/${rkey}`;
            this.con.get(
                "SELECT record_cid FROM records WHERE record_key = ?",
                [recordKey],
                (err, row) => {
                    if (err) return reject(err);
                    if (!row) return reject(new Error("Record not found"));
                    const recordCid = CID.decode(row.record_cid);
                    this.con.get(
                        "SELECT block_value FROM blocks WHERE block_cid = ?",
                        [row.record_cid],
                        async (err2, row2) => {
                            if (err2) return reject(err2);
                            if (!row2) return reject(new Error("Block not found for record"));
                            const value = row2.block_value;
                            const uri = `at://${this.did}/${collection}/${rkey}`;
                            resolve([uri, recordCid, value]);
                        }
                    );
                }
            );
        });
    }

    async getPreferences() {
        return new Promise((resolve, reject) => {
            this.con.get(
                "SELECT preferences_blob FROM preferences WHERE preferences_did = ?",
                [this.did],
                (err, row) => {
                    if (err) reject(err);
                    resolve(row ? row.preferences_blob : dagCbor.encode({ preferences: [] }));
                }
            );
        });
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
        return new Promise((resolve, reject) => {
            this.con.get(
                "SELECT blob_data FROM blobs WHERE blob_cid = ? AND blob_refcount > 0",
                [cid.toString()],
                (err, row) => {
                    if (err) reject(err);
                    if (!row) reject(new Error("Blob not found"));
                    resolve(row.blob_data);
                }
            );
        });
    }
}

// Export the Repo class and other required exports
export { Repo, ATNode, tidNow, hashToCid, dtToStr, timestampStrNow }; 