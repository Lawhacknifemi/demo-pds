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
                    collection TEXT,
                    rkey TEXT,
                    value BLOB,
                    PRIMARY KEY (collection, rkey)
                )
            `);
            this.con.run(`
                CREATE TABLE IF NOT EXISTS blocks (
                    cid TEXT PRIMARY KEY,
                    data BLOB
                )
            `);
            this.con.run(`
                CREATE TABLE IF NOT EXISTS commits (
                    rev TEXT PRIMARY KEY,
                    root TEXT,
                    data BLOB
                )
            `);
            this.con.run(`
                CREATE TABLE IF NOT EXISTS preferences (
                    key TEXT PRIMARY KEY,
                    value BLOB
                )
            `);
            this.con.run(`
                CREATE TABLE IF NOT EXISTS blobs (
                    cid TEXT PRIMARY KEY,
                    data BLOB,
                    mimeType TEXT
                )
            `);
        });

        // Create initial commit if needed
        this.con.get("SELECT * FROM commits WHERE rev=0", async (err, row) => {
            if (err) throw err;
            if (!row) {
                const commit = {
                    version: 3,
                    data: this.tree.cid.toString(),
                    rev: tidNow(),
                    did: this.did,
                    prev: null,
                    sig: null  // Will be set after signing
                };
                
                // Clean the commit object before encoding
                const cleanCommit = Object.fromEntries(
                    Object.entries(commit).filter(([_, v]) => v !== undefined)
                );
                
                const commitBlob = dagCbor.encode(cleanCommit);
                const commitCid = await hashToCid(commitBlob);
                cleanCommit.sig = rawSign(this.signingKey, commitBlob);

                this.con.serialize(() => {
                    this.con.run(
                        "INSERT OR IGNORE INTO blocks (cid, data) VALUES (?, ?)",
                        [Buffer.from(this.tree.cid.bytes), this.tree.value || Buffer.from([])]
                    );
                    this.con.run(
                        "INSERT OR IGNORE INTO blocks (cid, data) VALUES (?, ?)",
                        [Buffer.from(commitCid.bytes), commitBlob]
                    );
                    this.con.run(
                        "INSERT INTO commits (rev, root) VALUES (?, ?)",
                        [0, Buffer.from(this.tree.cid.bytes)]
                    );
                });
            }
        });

        // Load existing records
        this.con.each("SELECT collection, rkey, value FROM records", (err, row) => {
            if (err) throw err;
            this.tree.put(row.collection + '/' + row.rkey, row.value);
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
            // Remove undefined values from record
            const cleanRecord = Object.fromEntries(
                Object.entries(record).filter(([_, v]) => v !== undefined)
            );
            
            console.log('Encoding record:', cleanRecord);
            const value = dagCbor.encode(cleanRecord);
            console.log('Encoded value:', value);
            
            console.log('Creating CID...');
            const cid = await hashToCid(value);
            console.log('Created CID:', cid);
            console.log('CID bytes:', cid.bytes);
            console.log('CID multihash:', cid.multihash);
            console.log('CID code:', cid.code);
            
            if (!rkey) {
                rkey = tidNow();
            }
            
            const uri = `at://${this.did}/${collection}/${rkey}`;
            console.log('Generated URI:', uri);
            
            // Store in database
            console.log('Storing in database...');
            const stmt = this.con.prepare("INSERT OR REPLACE INTO records (collection, rkey, value) VALUES (?, ?, ?)");
            stmt.run(collection, rkey, value);
            stmt.finalize();
            
            // Update MST
            console.log('Updating MST...');
            this.tree.put(collection + '/' + rkey, value);
            
            // Create firehose message
            console.log('Creating firehose message...');
            const firehoseMsg = dagCbor.encode({
                op: 'create',
                uri,
                cid: cid.bytes.toString('hex'),
                record: cleanRecord
            });
            console.log('Created firehose message:', firehoseMsg);
            
            return [uri, cid, firehoseMsg];
        } catch (error) {
            console.error('Error in createRecord:', error);
            console.error('Error stack:', error.stack);
            throw new Error(`Failed to create record: ${error.message}`);
        }
    }

    async deleteRecord(collection, rkey) {
        const uri = `at://${this.did}/${collection}/${rkey}`;
        
        // Delete from database
        const stmt = this.con.prepare("DELETE FROM records WHERE collection = ? AND rkey = ?");
        stmt.run(collection, rkey);
        stmt.finalize();
        
        // Update MST
        this.tree.delete(collection + '/' + rkey);
        
        // Create firehose message
        const firehoseMsg = dagCbor.encode({
            op: 'delete',
            uri
        });
        
        return firehoseMsg;
    }

    async getRecord(collection, rkey) {
        return new Promise((resolve, reject) => {
            this.con.get(
                "SELECT value FROM records WHERE collection = ? AND rkey = ?",
                [collection, rkey],
                async (err, row) => {
                    if (err) reject(err);
                    if (!row) reject(new Error("Record not found"));
                    
                    const value = row.value;
                    const cid = await hashToCid(value);
                    const uri = `at://${this.did}/${collection}/${rkey}`;
                    
                    resolve([uri, cid, value]);
                }
            );
        });
    }

    async getPreferences() {
        return new Promise((resolve, reject) => {
            this.con.get(
                "SELECT value FROM preferences WHERE key = 'preferences'",
                (err, row) => {
                    if (err) reject(err);
                    resolve(row ? row.value : dagCbor.encode({}));
                }
            );
        });
    }

    async putPreferences(value) {
        const stmt = this.con.prepare("INSERT OR REPLACE INTO preferences (key, value) VALUES (?, ?)");
        stmt.run('preferences', value);
        stmt.finalize();
    }

    async putBlob(data) {
        const cid = await hashToCid(data);
        
        const stmt = this.con.prepare("INSERT OR REPLACE INTO blobs (cid, data) VALUES (?, ?)");
        stmt.run(cid.toString('base32'), data);
        stmt.finalize();
        
        return {
            ref: cid.toString('base32'),
            size: data.length,
            mimeType: 'application/octet-stream'
        };
    }

    async getBlob(cid) {
        return new Promise((resolve, reject) => {
            this.con.get(
                "SELECT data FROM blobs WHERE cid = ?",
                [cid.toString('base32')],
                (err, row) => {
                    if (err) reject(err);
                    if (!row) reject(new Error("Blob not found"));
                    resolve(row.data);
                }
            );
        });
    }

    async put(collection, rkey, value) {
        const key = `${collection}/${rkey}`;
        const cid = await hashToCid(value);
        this.tree = await this.tree.put(key, cid.toString());
        
        // Store in SQLite
        const stmt = this.con.prepare("INSERT OR REPLACE INTO records (collection, rkey, value) VALUES (?, ?, ?)");
        stmt.run(collection, rkey, value);
        stmt.finalize();
        
        // Store block
        const blockStmt = this.con.prepare("INSERT OR REPLACE INTO blocks (cid, data) VALUES (?, ?)");
        blockStmt.run(cid.toString(), value);
        blockStmt.finalize();
        
        return cid;
    }
}

// Export the Repo class and other required exports
export { Repo, ATNode, tidNow, hashToCid, dtToStr, timestampStrNow }; 