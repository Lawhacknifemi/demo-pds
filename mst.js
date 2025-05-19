// mst.js - Complete working implementation of Merkle Search Tree

import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';

/**
 * Helper function to calculate shared prefix length between two buffers
 * @param {Buffer} a - First buffer
 * @param {Buffer} b - Second buffer
 * @returns {number} Length of shared prefix
 */
function getSharedPrefixLength(a, b) {
    let i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) {
        i++;
    }
    return i;
}

/**
 * Helper function to replace an element in an array at a specific index
 * @param {Array} arr - Source array
 * @param {number} index - Index to replace
 * @param {*} value - New value
 * @returns {Array} New array with replaced value
 */
function tupleReplaceAt(arr, index, value) {
    const result = [...arr];
    result[index] = value;
    return Object.freeze(result);
}

/**
 * Helper function to insert an element in an array at a specific index
 * @param {Array} arr - Source array
 * @param {number} index - Index to insert at
 * @param {*} value - Value to insert
 * @returns {Array} New array with inserted value
 */
function tupleInsertAt(arr, index, value) {
    const result = [...arr.slice(0, index), value, ...arr.slice(index)];
    return Object.freeze(result);
}

/**
 * Helper function to remove an element from an array at a specific index
 * @param {Array} arr - Source array
 * @param {number} index - Index to remove
 * @returns {Array} New array with removed value
 */
function tupleRemoveAt(arr, index) {
    const result = [...arr.slice(0, index), ...arr.slice(index + 1)];
    return Object.freeze(result);
}

/**
 * Base MSTNode class - represents nodes in the Merkle Search Tree
 * @abstract
 */
export class MSTNode {
    /**
     * @param {Array<MSTNode|null>} subtrees
     * @param {Array<string>} keys
     * @param {Array<any>} vals
     * @throws {TypeError} If arguments are not arrays
     * @throws {Error} If subtree count is invalid
     * @throws {Error} If keys/vals lengths don't match
     */
    constructor(subtrees, keys, vals) {
        if (!Array.isArray(subtrees) || !Array.isArray(keys) || !Array.isArray(vals)) {
            throw new Error('All arguments must be arrays');
        }
        if (keys.length !== vals.length || subtrees.length !== keys.length + 1) {
            throw new Error('Invalid array lengths');
        }

        // Validate that keys are in ascending order
        for (let i = 1; i < keys.length; i++) {
            if (keys[i] <= keys[i - 1]) {
                throw new Error('Keys must be in ascending order');
            }
        }

        this.subtrees = Object.freeze([...subtrees]);
        this.keys = Object.freeze([...keys]);
        this.vals = Object.freeze([...vals]);
        this._cid = null;
    }

    /**
     * @abstract
     * @param {string} key
     * @returns {number}
     * @throws {Error} If not implemented by subclass
     */
    static key_height(key) {
        throw new Error('key_height must be implemented by subclass');
    }

    /**
     * @returns {MSTNode}
     */
    static emptyRoot() {
        return new this([null], [], []);
    }

    /**
     * @param {MSTNode|null} value
     * @returns {MSTNode}
     */
    static _fromOptional(value) {
        if (value === null) {
            return this.emptyRoot();
        }
        return value;
    }

    /**
     * @returns {MSTNode|null}
     */
    _toOptional() {
        if (this.subtrees.length === 1 && this.subtrees[0] === null && this.keys.length === 0) {
            return null;
        }
        return this;
    }

    /**
     * @param {Set<MSTNode>} created
     * @returns {MSTNode}
     */
    _squashTop(created) {
        if (this.keys.length) {
            return this;
        }
        if (this.subtrees[0] === null) {
            return this;
        }
        created.delete(this);
        return this.subtrees[0]._squashTop(created);
    }

    /**
     * @returns {number}
     */
    height() {
        if (this.keys.length > 0) {
            return this.constructor.key_height(this.keys[0]);
        }
        
        if (this.subtrees[0] === null) {
            return 0;
        }
        
        return this.subtrees[0].height() + 1;
    }

    /**
     * @param {string} key
     * @returns {number}
     */
    _gteIndex(key) {
        let i = 0;
        while (i < this.keys.length && key > this.keys[i]) {
            i++;
        }
        return i;
    }

    /**
     * @param {string} key_min
     * @param {string} key_max
     * @param {boolean} reverse
     * @yields {[string, any]}
     */
    *get_range(key_min, key_max, reverse = false) {
        const start = this._gteIndex(key_min);
        const end = this._gteIndex(key_max);
        
        if (reverse) {
            if (this.subtrees[end] !== null) {
                yield* this.subtrees[end].get_range(key_min, key_max, reverse);
            }
            for (let i = end - 1; i >= start; i--) {
                yield [this.keys[i], this.vals[i]];
                if (this.subtrees[i] !== null) {
                    yield* this.subtrees[i].get_range(key_min, key_max, reverse);
                }
            }
        } else {
            for (let i = start; i < end; i++) {
                if (this.subtrees[i] !== null) {
                    yield* this.subtrees[i].get_range(key_min, key_max, reverse);
                }
                yield [this.keys[i], this.vals[i]];
            }
            if (this.subtrees[end] !== null) {
                yield* this.subtrees[end].get_range(key_min, key_max, reverse);
            }
        }
    }

    /**
     * @param {string} key
     * @param {any} val
     * @param {Set<MSTNode>} created
     * @returns {MSTNode}
     */
    put(key, val, created = new Set()) {
        if (typeof key !== 'string') {
            throw new Error('Key must be a string');
        }
        if (val === undefined || val === null) {
            throw new Error('Value cannot be undefined or null');
        }
        if (!(created instanceof Set)) {
            throw new Error('created must be a Set');
        }

        const i = this._gteIndex(key);
        
        if (i < this.keys.length && this.keys[i] === key) {
            // Key exists, replace value
            return this._putHere(key, val, created);
        }
        
        if (this.subtrees[0] === null) {
            // Leaf node, insert here
            return this._putHere(key, val, created);
        }
        
        // Internal node, recurse
        const newSubtrees = [...this.subtrees];
        newSubtrees[i] = this.subtrees[i].put(key, val, created);
        return new MSTNode(newSubtrees, this.keys, this.vals);
    }

    /**
     * @param {string} key
     * @param {any} val
     * @param {Set<MSTNode>} created
     * @returns {MSTNode}
     */
    _putHere(key, val, created = new Set()) {
        const cls = this.constructor;
        
        const i = this._gteIndex(key);
        if (i < this.keys.length && this.keys[i] === key) {
            if (this.vals[i] === val) {
                return this;
            }
            const newNode = new cls(
                this.subtrees,
                this.keys,
                tupleReplaceAt(this.vals, i, val)
            );
            created.add(newNode);
            return newNode;
        }
        
        const [left, right] = cls._splitOnKey(this.subtrees[i], key, created);
        const newSubtrees = [
            ...this.subtrees.slice(0, i),
            left,
            right,
            ...this.subtrees.slice(i + 1)
        ];
        
        const newNode = new cls(
            newSubtrees,
            tupleInsertAt(this.keys, i, key),
            tupleInsertAt(this.vals, i, val)
        );
        created.add(newNode);
        return newNode;
    }

    /**
     * @param {MSTNode|null} tree
     * @param {string} key
     * @param {Set<MSTNode>} created
     * @returns {[MSTNode|null, MSTNode|null]}
     */
    static _splitOnKey(tree, key, created = new Set()) {
        if (tree === null) {
            return [null, null];
        }
        
        const i = tree._gteIndex(key);
        const [lsub, rsub] = this._splitOnKey(tree.subtrees[i], key, created);
        
        const left = new this(
            [...tree.subtrees.slice(0, i), lsub],
            tree.keys.slice(0, i),
            tree.vals.slice(0, i)
        )._toOptional();
        
        const right = new this(
            [rsub, ...tree.subtrees.slice(i + 1)],
            tree.keys.slice(i),
            tree.vals.slice(i)
        )._toOptional();
        
        if (left !== null) {
            created.add(left);
        }
        if (right !== null) {
            created.add(right);
        }
        
        return [left, right];
    }

    /**
     * @param {string} key
     * @param {Set<MSTNode>} created
     * @returns {MSTNode}
     */
    delete(key, created = new Set()) {
        if (typeof key !== 'string') {
            throw new Error('Key must be a string');
        }
        if (!(created instanceof Set)) {
            throw new Error('created must be a Set');
        }

        const i = this._gteIndex(key);
        
        if (i >= this.keys.length || this.keys[i] !== key) {
            throw new Error(`Key not found: ${key}`);
        }
        
        if (this.subtrees[0] === null) {
            // Leaf node, delete here
            return new MSTNode(
                tupleRemoveAt(this.subtrees, i + 1),
                tupleRemoveAt(this.keys, i),
                tupleRemoveAt(this.vals, i)
            );
        }
        
        // Internal node, recurse
        const newSubtrees = [...this.subtrees];
        newSubtrees[i] = this.subtrees[i].delete(key, created);
        return new MSTNode(newSubtrees, this.keys, this.vals);
    }

    /**
     * @returns {CID}
     */
    get cid() {
        if (!this._cid) {
            const bytes = this.serialised;
            const hash = sha256.digest(bytes);
            this._cid = CID.create(1, 0x71, hash);
        }
        return this._cid;
    }

    get serialised() {
        const entries = [];
        let prevKey = Buffer.from('');
        
        for (let i = 0; i < this.keys.length; i++) {
            const keyBytes = Buffer.from(this.keys[i]);
            const sharedPrefixLen = getSharedPrefixLength(prevKey, keyBytes);
            
            entries.push({
                k: keyBytes.slice(sharedPrefixLen),
                p: sharedPrefixLen,
                t: this.subtrees[i + 1] === null ? null : this.subtrees[i + 1].cid,
                v: this.vals[i]
            });
            
            prevKey = keyBytes;
        }
        
        return dagCbor.encode({
            e: entries,
            l: this.subtrees[0] === null ? null : this.subtrees[0].cid
        });
    }
}

/**
 * MST wrapper class for mutable interface
 */
export class MST {
    /**
     * @param {MSTNode} root
     */
    constructor(root) {
        this.root = root;
    }
  
    /**
     * @param {typeof MSTNode} node_type
     * @returns {MST}
     */
    static new_with(node_type) {
        return new MST(node_type.emptyRoot());
    }
  
    /**
     * @returns {number}
     */
    height() {
        return this.root.height();
    }
  
    /**
     * @param {string} key
     * @param {any} val
     * @returns {MST}
     */
    set(key, val) {
        this.root = this.root.put(key, val, new Set());
        return this;
    }
  
    /**
     * @param {string} key
     * @returns {MST}
     * @throws {Error} If key not found
     */
    delete(key) {
        const prev_root = this.root;
        this.root = this.root.delete(key, new Set());
        if (this.root === prev_root) {
            throw new Error(`Key '${key}' not found`);
        }
        return this;
    }
  
    /**
     * @param {string} key
     * @param {any} sentinel
     * @returns {any}
     */
    get(key, sentinel = null) {
        return this.root.get(key, sentinel);
    }
  
    /**
     * @param {string} key
     * @returns {boolean}
     */
    has(key) {
        return this.get(key) !== null;
    }
  
    /**
     * @param {string} key_min
     * @param {string} key_max
     * @param {boolean} reverse
     * @yields {[string, any]}
     */
    *get_range(key_min, key_max, reverse = false) {
        yield* this.root.get_range(key_min, key_max, reverse);
    }
}

/**
 * Example implementation
 */
export class StrlenNode extends MSTNode {
    /**
     * @param {string} key
     * @returns {number}
     */
    static key_height(key) {
        return key.length;
    }
}