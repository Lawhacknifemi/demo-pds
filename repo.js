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
const { base64url } = pkg;

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
    const d = new Date();
    return d.getTime() * 1000 + randomInt(1000);
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
    constructor(data) {
        super(data);
    }

    keyHeight() {
        return 1;
    }

    keyPath() {
        return this.key;
    }

    *enumerateBlocks() {
        yield this.value;
        for (const child of this.children) {
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
        const tree = ATNode.emptyRoot();
        const emptyRootData = dagCbor.encode({});
        const emptyRootCid = await hashToCid(emptyRootData);
        tree.cid = emptyRootCid;
        return new Repo(did, db, signingKey, tree);
    }

    async createRecord(collection, record, rkey = null) {
        try {
            if (!rkey) {
                rkey = tidNow();
            }
            
            const recordKey = `${collection}/${rkey}`;
            
            // Clean the record before processing
            const cleanRecord = cleanObject(record);
            
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
            
            const commitBlob = dagCbor.encode(commit);
            commit.sig = rawSign(this.signingKey, commitBlob);
            const commitCid = await hashToCid(commitBlob);
            dbBlockInserts.push([Buffer.from(commitCid.bytes), commitBlob]);
            
            // Store blocks
            for (const [cid, data] of dbBlockInserts) {
                this.con.run("INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)", [cid, data]);
            }
            
            // Store record
            this.con.run("INSERT OR REPLACE INTO records (record_key, record_cid) VALUES (?, ?)", 
                [recordKey, Buffer.from(valueCid.bytes)]);
            
            // Store commit
            this.con.run("INSERT INTO commits (commit_seq, commit_cid) VALUES (?, ?)",
                [prevCommit.commit_seq + 1, Buffer.from(commitCid.bytes)]);
            
            const uri = `at://${this.did}/${recordKey}`;
            
            // Create firehose message
            const firehoseMsg = dagCbor.encode(cleanObject({
                t: "#commit",
                op: 1,
                ops: [{
                    cid: valueCid,
                    path: recordKey,
                    action: "create"
                }],
                seq: Date.now() * 1000,
                rev: newCommitRev,
                since: prevCommitData.rev,
                prev: null,
                repo: this.did,
                time: timestampStrNow(),
                blobs: Array.from(referencedBlobs),
                blocks: serialise([commitCid], dbBlockInserts),
                commit: commitCid,
                rebase: false,
                tooBig: false
            }));
            
            return [uri, valueCid, firehoseMsg];
        } catch (error) {
            console.error('Error in createRecord:', error);
            throw error;
        }
    }

    async deleteRecord(collection, rkey) {
        const recordKey = `${collection}/${rkey}`;
        const [uri, cid, value] = await this.getRecord(collection, rkey);
        const recordData = dagCbor.decode(value);
        
        // Handle blob references
        for (const blobCid of enumerateRecordCids(recordData)) {
            await this.decrefBlob(blobCid);
        }
        
        // Update MST
        const newBlocks = new Set();
        this.tree = this.tree.delete(recordKey, newBlocks);
        
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
            data: this.tree.cid,
            rev: newCommitRev,
            prev: null,
            did: this.did
        });
        
        const commitBlob = dagCbor.encode(commit);
        commit.sig = rawSign(this.signingKey, commitBlob);
        const commitCid = await hashToCid(commitBlob);
        
        // Store blocks
        this.con.run("INSERT OR IGNORE INTO blocks (block_cid, block_value) VALUES (?, ?)",
            [Buffer.from(commitCid.bytes), commitBlob]);
        
        // Delete record
        this.con.run("DELETE FROM records WHERE record_key = ?", [recordKey]);
        
        // Store commit
        this.con.run("INSERT INTO commits (commit_seq, commit_cid) VALUES (?, ?)",
            [prevCommit.commit_seq + 1, Buffer.from(commitCid.bytes)]);
        
        // Create firehose message
        const firehoseMsg = dagCbor.encode(cleanObject({
            t: "#commit",
            op: 1,
            ops: [{
                cid: null,
                path: recordKey,
                action: "delete"
            }],
            seq: Date.now() * 1000,
            rev: newCommitRev,
            since: prevCommitData.rev,
            prev: null,
            repo: this.did,
            time: timestampStrNow(),
            blobs: [],
            blocks: serialise([commitCid], [[Buffer.from(commitCid.bytes), commitBlob]]),
            commit: commitCid,
            rebase: false,
            tooBig: false
        }));
        
        return firehoseMsg;
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