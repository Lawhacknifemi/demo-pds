// mst.js - Fixed implementation to match official atproto MST algorithm

import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';

/**
 * Helper function to create a CID from a buffer
 * @param {Uint8Array} bytes - The bytes to create a CID from
 * @returns {Promise<CID>} The created CID
 */
async function hashToCid(bytes) {
    const hash = await sha256.digest(bytes);
    return CID.create(1, 0x71, hash);
}

/**
 * Helper function to calculate shared prefix length between two strings
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {number} Length of shared prefix
 */
function countPrefixLen(a, b) {
    let i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) {
        i++;
    }
    return i;
}

/**
 * Calculate leading zeros on hash for MST layering
 * @param {string} key - The key to hash
 * @returns {Promise<number>} Number of leading zero bits (in pairs for 4-bit fanout)
 */
async function leadingZerosOnHash(key) {
    const keyBytes = new TextEncoder().encode(key);
    const hash = await sha256.digest(keyBytes);
    let total = 0;
    
    for (const byte of hash.digest) {
        if (byte & 0xC0) {
            // No leading pair of zero bits
            break;
        }
        if (byte === 0x00) {
            total += 4;
            continue;
        }
        if ((byte & 0xFC) === 0x00) {
            total += 3;
        } else if ((byte & 0xF0) === 0x00) {
            total += 2;
        } else {
            total += 1;
        }
        break;
    }
    return total;
}

/**
 * Validate MST key format
 * @param {string} key - The key to validate
 * @returns {boolean} Whether the key is valid
 */
function isValidMstKey(key) {
    if (key.length > 256) return false;
    const parts = key.split('/');
    if (parts.length !== 2) return false;
    if (parts[1].length === 0) return false;
    
    const validChars = /^[a-zA-Z0-9_:.-]+$/;
    return validChars.test(parts[0]) && validChars.test(parts[1]);
}

/**
 * Ensure MST key is valid
 * @param {string} key - The key to validate
 * @throws {Error} If key is invalid
 */
function ensureValidMstKey(key) {
    if (!isValidMstKey(key)) {
        throw new Error(`Not a valid MST key: ${key}`);
    }
}

/**
 * MST Node Entry - represents either a leaf or tree pointer
 */
class NodeEntry {
    constructor(kind, key = '', val = null, tree = null) {
        this.kind = kind; // 'leaf', 'tree', or 'undefined'
        this.key = key;
        this.val = val;
        this.tree = tree;
    }

    isLeaf() {
        return this.kind === 'leaf';
    }

    isTree() {
        return this.kind === 'tree';
    }

    isUndefined() {
        return this.kind === 'undefined';
    }
}

/**
 * Merkle Search Tree implementation matching atproto spec
 */
export class MST {
    constructor(storage = null, entries = [], layer = 0, fanout = 4) {
        this.storage = storage;
        this.entries = entries;
        this.layer = layer;
        this.fanout = fanout;
        this._pointer = null;
        this._validPtr = false;
    }

    /**
     * Create a new empty MST
     * @param {any} storage - Storage backend
     * @returns {MST} New empty MST
     */
    static create(storage) {
        return new MST(storage, [], 0, 4);
    }

    /**
     * Load MST from CID
     * @param {any} storage - Storage backend
     * @param {CID} cid - Root CID
     * @returns {MST} Loaded MST
     */
    static async load(storage, cid) {
        const mst = new MST(storage, null, -1, 4);
        mst._pointer = cid;
        mst._validPtr = true;
        return mst;
    }

    /**
     * Get the layer of this MST node
     * @returns {number} Layer number
     */
    async getLayer() {
        if (this.layer >= 0) {
            return this.layer;
        }

        const entries = await this.getEntries();
        if (entries.length === 0) {
            return 0;
        }

        // Find first leaf to determine layer
        for (const entry of entries) {
            if (entry.isLeaf()) {
                this.layer = await leadingZerosOnHash(entry.key);
                return this.layer;
            }
        }

        // If no leaves, check subtrees
        for (const entry of entries) {
            if (entry.isTree()) {
                const childLayer = await entry.tree.getLayer();
                if (childLayer >= 0) {
                    this.layer = childLayer + 1;
                    return this.layer;
                }
            }
        }

        return 0;
    }

    /**
     * Get entries (lazy load if needed)
     * @returns {Promise<NodeEntry[]>} Array of entries
     */
    async getEntries() {
        if (this.entries !== null) {
            return this.entries;
        }

        if (this._pointer) {
            // Load from storage
            const data = await this.storage.get(this._pointer);
            this.entries = await this.deserializeNodeData(data);
            return this.entries;
        }

        throw new Error('No entries or pointer available');
    }

    /**
     * Set entries (for internal use after mutation)
     * @param {NodeEntry[]} entries - The new entries array
     */
    setEntries(entries) {
        this.entries = entries;
    }

    /**
     * Get pointer (CID) for this MST node
     * @returns {Promise<CID>} Node CID
     */
    async getPointer() {
        if (this._validPtr) {
            return this._pointer;
        }

        const entries = await this.getEntries();
        const nodeData = await this.serializeNodeData(entries);
        this._pointer = await this.storage.put(nodeData);
        this._validPtr = true;
        return this._pointer;
    }

    /**
     * Add a key-value pair to the MST
     * @param {string} key - The key
     * @param {any} val - The value
     * @param {number} knownZeros - Known leading zeros (optional)
     * @returns {Promise<MST>} New MST with added entry
     */
    async add(key, val, knownZeros = -1) {
        ensureValidMstKey(key);

        if (val === null || val === undefined) {
            throw new Error('Value cannot be null or undefined');
        }

        const keyZeros = knownZeros >= 0 ? knownZeros : await leadingZerosOnHash(key);
        const layer = await this.getLayer();

        const newLeaf = new NodeEntry('leaf', key, val);

        if (keyZeros === layer) {
            // Key belongs in this layer
            return await this.addToLayer(newLeaf);
        } else if (keyZeros < layer) {
            // Key belongs in a lower layer
            return await this.addToLowerLayer(key, val, keyZeros);
        } else {
            // Key belongs in a higher layer
            return await this.addToHigherLayer(key, val, keyZeros);
        }
    }

    /**
     * Add entry to current layer
     * @param {NodeEntry} newLeaf - The new leaf entry
     * @returns {Promise<MST>} New MST
     */
    async addToLayer(newLeaf) {
        const entries = await this.getEntries();
        const index = this.findGtOrEqualLeafIndex(entries, newLeaf.key);

        if (index < entries.length && entries[index].isLeaf() && entries[index].key === newLeaf.key) {
            throw new Error(`Value already set at key: ${newLeaf.key}`);
        }

        let newEntries = [...entries];
        newEntries.splice(index, 0, newLeaf);
        newEntries = await mergeAdjacentTrees(newEntries, this.storage, this.layer, this.fanout);
        this.setEntries(newEntries);

        console.log('DEBUG: addToLayer newEntries:', newEntries.map(e => ({kind: e.kind, key: e.key})));
        return new MST(this.storage, newEntries, this.layer, this.fanout);
    }

    /**
     * Add entry to lower layer
     * @param {string} key - The key
     * @param {any} val - The value
     * @param {number} keyZeros - Leading zeros for the key
     * @returns {Promise<MST>} New MST
     */
    async addToLowerLayer(key, val, keyZeros) {
        const entries = await this.getEntries();
        const index = this.findGtOrEqualLeafIndex(entries, key);
        const prevNode = index > 0 ? entries[index - 1] : new NodeEntry('undefined');

        let newEntries;
        if (prevNode.isTree()) {
            // Add to existing subtree
            const newSubtree = await prevNode.tree.add(key, val, keyZeros);
            newEntries = [...entries];
            newEntries[index - 1] = new NodeEntry('tree', '', null, newSubtree);
        } else {
            // Create new subtree
            const subtree = new MST(this.storage, [], this.layer - 1, this.fanout);
            const newSubtree = await subtree.add(key, val, keyZeros);
            newEntries = [...entries];
            newEntries.splice(index, 0, new NodeEntry('tree', '', null, newSubtree));
        }
        newEntries = await mergeAdjacentTrees(newEntries, this.storage, this.layer, this.fanout);
        this.setEntries(newEntries);
        console.log('DEBUG: addToLowerLayer newEntries:', newEntries.map(e => ({kind: e.kind, key: e.key})));
        return new MST(this.storage, newEntries, this.layer, this.fanout);
    }

    /**
     * Add entry to higher layer
     * @param {string} key - The key
     * @param {any} val - The value
     * @param {number} keyZeros - Leading zeros for the key
     * @returns {Promise<MST>} New MST
     */
    async addToHigherLayer(key, val, keyZeros) {
        const [left, right] = await this.splitAround(key);
        const newLeaf = new NodeEntry('leaf', key, val);

        let newEntries = [];
        if (left) {
            newEntries.push(new NodeEntry('tree', '', null, left));
        }
        newEntries.push(newLeaf);
        if (right) {
            newEntries.push(new NodeEntry('tree', '', null, right));
        }
        // Strictly enforce: [at most one left tree], [leaves...], [at most one right tree]
        let leftTrees = [];
        let rightTrees = [];
        let leaves = [];
        let foundLeaf = false;
        for (let i = 0; i < newEntries.length; i++) {
            const entry = newEntries[i];
            if (entry.isTree()) {
                if (!foundLeaf) {
                    leftTrees.push(entry);
                } else {
                    rightTrees.push(entry);
                }
            } else if (entry.isLeaf()) {
                foundLeaf = true;
                leaves.push(entry);
            }
        }
        // Merge left trees if more than one
        let leftTree = null;
        if (leftTrees.length > 0) {
            leftTree = await mergeTrees(leftTrees, this.storage, keyZeros, this.fanout);
        }
        // Merge right trees if more than one
        let rightTree = null;
        if (rightTrees.length > 0) {
            rightTree = await mergeTrees(rightTrees, this.storage, keyZeros, this.fanout);
        }
        newEntries = [];
        if (leftTree) newEntries.push(new NodeEntry('tree', '', null, leftTree));
        newEntries.push(...leaves);
        if (rightTree) newEntries.push(new NodeEntry('tree', '', null, rightTree));
        // After mutation, merge adjacent trees
        this.entries = await mergeAdjacentTrees(newEntries, this.storage, this.layer, this.fanout);
        console.log('DEBUG: addToHigherLayer newEntries:', newEntries.map(e => ({kind: e.kind, key: e.key})));
        return new MST(this.storage, newEntries, keyZeros, this.fanout);
    }

    /**
     * Find index of first leaf >= key
     * @param {NodeEntry[]} entries - Entries to search
     * @param {string} key - Key to find
     * @returns {number} Index
     */
    findGtOrEqualLeafIndex(entries, key) {
        for (let i = 0; i < entries.length; i++) {
            if (entries[i].isLeaf() && entries[i].key >= key) {
                return i;
            }
        }
        return entries.length;
    }

    /**
     * Split MST around a key
     * @param {string} key - Key to split around
     * @returns {Promise<[MST, MST]>} Left and right subtrees
     */
    async splitAround(key) {
        const entries = await this.getEntries();
        const index = this.findGtOrEqualLeafIndex(entries, key);

        const leftEntries = entries.slice(0, index);
        const rightEntries = entries.slice(index);

        const left = leftEntries.length > 0 ? new MST(this.storage, leftEntries, this.layer, this.fanout) : null;
        const right = rightEntries.length > 0 ? new MST(this.storage, rightEntries, this.layer, this.fanout) : null;

        return [left, right];
    }

    /**
     * Serialize node data to CBOR format
     * @param {NodeEntry[]} entries - Entries to serialize
     * @returns {Promise<Object>} Serialized data
     */
    async serializeNodeData(entries) {
        const nodeData = {
            e: [], // entries
            l: null // left subtree
        };

        let i = 0;
        let lastKey = '';
        let lastWasLeaf = false;

        // Handle left subtree
        if (entries.length > 0 && entries[0].isTree()) {
            nodeData.l = await entries[0].tree.getPointer();
            i++;
            lastWasLeaf = false;
        }

        for (; i < entries.length; i++) {
            const entry = entries[i];
            if (entry.isLeaf()) {
                // Add leaf entry
                const prefixLen = countPrefixLen(lastKey, entry.key);
                const keySuffix = entry.key.slice(prefixLen);
                let valueToStore = entry.val;
                if (typeof entry.val === 'string' && entry.val.match(/^bafy[a-z0-9]+$/)) {
                    try {
                        valueToStore = CID.parse(entry.val);
                    } catch (e) {}
                }
                nodeData.e.push({
                    p: prefixLen,
                    k: new TextEncoder().encode(keySuffix),
                    v: valueToStore,
                    t: null
                });
                lastKey = entry.key;
                lastWasLeaf = true;
            } else if (entry.isTree()) {
                // Tree after a leaf: set as right subtree for previous entry
                if (!lastWasLeaf || nodeData.e.length === 0) {
                    // Two trees in a row or tree after tree: invalid
                    console.error('serializeNodeData: entries =', entries.map(e => ({ kind: e.kind, key: e.key })));
                    throw new Error('Invalid node structure: tree in invalid position');
                }
                nodeData.e[nodeData.e.length - 1].t = await entry.tree.getPointer();
                lastWasLeaf = false;
            } else {
                // Undefined or invalid entry
                console.error('serializeNodeData: entries =', entries.map(e => ({ kind: e.kind, key: e.key })));
                throw new Error('Invalid node structure: undefined entry');
            }
        }

        // Debug print for nodeData structure
        console.log('DEBUG: serializeNodeData nodeData =', JSON.stringify(nodeData, (key, value) => {
            if (value && value.asCID) return value.toString();
            if (value instanceof Uint8Array) return Array.from(value);
            return value;
        }, 2));

        return nodeData;
    }

    /**
     * Deserialize node data from CBOR format
     * @param {Object} data - Serialized data
     * @returns {Promise<NodeEntry[]>} Deserialized entries
     */
    async deserializeNodeData(data) {
        const entries = [];
        let lastKey = '';

        // Handle left subtree
        if (data.l) {
            const leftTree = await MST.load(this.storage, data.l);
            entries.push(new NodeEntry('tree', '', null, leftTree));
        }

        // Handle entries
        for (const entry of data.e) {
            const keySuffix = new TextDecoder().decode(entry.k);
            const key = lastKey.slice(0, entry.p) + keySuffix;

            let valueToStore = entry.v;
            if (typeof entry.v === 'string' && entry.v.match(/^bafy[a-z0-9]+$/)) {
                try {
                    valueToStore = CID.parse(entry.v);
                } catch (e) {
                    // Not a valid CID, keep as is
                }
            }

            entries.push(new NodeEntry('leaf', key, valueToStore));

            if (entry.t) {
                const subtree = await MST.load(this.storage, entry.t);
                entries.push(new NodeEntry('tree', key, null, subtree));
            }

            lastKey = key;
        }

        return entries;
    }

    /**
     * Walk all leaves in the MST
     * @param {Function} callback - Callback function(key, value)
     * @returns {Promise<void>}
     */
    async walkLeaves(callback) {
        const entries = await this.getEntries();
        
        for (const entry of entries) {
            if (entry.isLeaf()) {
                await callback(entry.key, entry.val);
            } else if (entry.isTree()) {
                await entry.tree.walkLeaves(callback);
            }
        }
    }

    /**
     * Get all keys in the MST
     * @returns {Promise<string[]>} Array of keys
     */
    async getKeys() {
        const keys = [];
        await this.walkLeaves((key, val) => {
            keys.push(key);
        });
        return keys.sort();
    }

    // Structure validation: checks for adjacent tree nodes, key order, and duplicates
    verifyStructure() {
        function checkNode(node, lastKey = null) {
            let lastWasTree = false;
            let prevKey = lastKey;
            let keys = [];
            for (let i = 0; i < node.entries.length; i++) {
                const entry = node.entries[i];
                if (entry.isTree() && entry.isTree()) {
                    if (lastWasTree) throw new Error('Adjacent tree nodes found');
                    lastWasTree = true;
                    if (entry.tree) {
                        const childKeys = checkNode(entry.tree, prevKey);
                        if (childKeys.length > 0) prevKey = childKeys[childKeys.length - 1];
                        keys = keys.concat(childKeys);
                    }
                } else if (entry.isLeaf() && entry.isLeaf()) {
                    lastWasTree = false;
                    if (prevKey !== null && entry.key < prevKey) throw new Error('Keys out of order');
                    if (keys.includes(entry.key)) throw new Error('Duplicate key in tree');
                    keys.push(entry.key);
                    prevKey = entry.key;
                }
            }
            return keys;
        }
        checkNode(this);
    }
}

/**
 * Simple in-memory storage for testing
 */
export class MemoryStorage {
    constructor() {
        this.data = new Map();
    }

    async put(data) {
        const serialized = dagCbor.encode(data);
        const hash = await sha256.digest(serialized);
        const cid = CID.create(1, 0x71, hash);
        this.data.set(cid.toString(), { cid, data, serialized });
        return cid;
    }

    async get(cid) {
        const entry = this.data.get(cid.toString());
        if (!entry) {
            throw new Error(`CID not found: ${cid}`);
        }
        return entry.data;
    }
  }

// Helper to recursively merge multiple trees into a valid MST
async function mergeTrees(trees, storage, layer, fanout) {
    if (trees.length === 0) return null;
    if (trees.length === 1) return trees[0].tree;
    // Start with the first tree
    let merged = trees[0].tree;
    for (let i = 1; i < trees.length; i++) {
        const entries = await trees[i].tree.getEntries();
        for (const entry of entries) {
            if (entry.isLeaf()) {
                merged = await merged.add(entry.key, entry.val);
            } else if (entry.isTree()) {
                // Recursively merge subtrees
                const subtree = entry.tree;
                const subEntries = await subtree.getEntries();
                for (const subEntry of subEntries) {
                    if (subEntry.isLeaf()) {
                        merged = await merged.add(subEntry.key, subEntry.val);
                    } else if (subEntry.isTree()) {
                        // Recursively merge deeper
                        merged = await mergeTrees([new NodeEntry('tree', '', null, subEntry.tree)], storage, layer, fanout);
                    }
                }
            }
        }
    }
    return merged;
}

// Recursively merge adjacent tree (child) nodes in the entries array
async function mergeAdjacentTrees(entries, storage, layer, fanout) {
  if (!entries.length) return entries;
  let out = [];
  let i = 0;
  while (i < entries.length) {
    if (entries[i].isTree()) {
      // Start of a run of tree nodes
      let trees = [entries[i]];
      let j = i + 1;
      while (j < entries.length && entries[j].isTree()) {
        trees.push(entries[j]);
        j++;
      }
      if (trees.length === 1) {
        out.push(trees[0]);
      } else {
        // Recursively merge all trees into one
        let merged = trees[0].tree;
        for (let k = 1; k < trees.length; k++) {
          // Insert all leaves from trees[k] into merged
          const ents = await trees[k].tree.getEntries();
          for (const entry of ents) {
            if (entry.isLeaf()) {
              merged = await merged.add(entry.key, entry.val);
            } else if (entry.isTree()) {
              // Recursively merge subtrees
              merged = await mergeAdjacentTrees([new NodeEntry('tree', '', null, merged), entry], storage, layer - 1, fanout)[0].tree;
            }
          }
        }
        out.push(new NodeEntry('tree', '', null, merged));
      }
      i = j;
    } else {
      out.push(entries[i]);
      i++;
    }
  }
  return out;
}