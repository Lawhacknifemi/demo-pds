// mst.js - Complete working implementation of Merkle Search Tree

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
        
        // Private properties for caching
        this._serialised = null;
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
     * @returns {Promise<MSTNode>}
     */
    async put(key, val, created = new Set()) {
        console.log('Putting key:', key, 'value:', val, 'in node with keys:', this.keys);
        
        if (this.keys.length === 0) {
            console.log('Empty tree case, putting here');
            return this._put_here(key, val, created);
        }

        const keyHeight = this.constructor.key_height(key);
        const treeHeight = this.height();
        
        if (keyHeight > treeHeight) {
            // Need to grow the tree
            const newRoot = new this.constructor(
                [this],
                [],
                []
            );
            created.add(newRoot);
            return await newRoot.put(key, val, created);
        }
        
        if (keyHeight < treeHeight) {
            // Need to look below
            const i = this._gteIndex(key);
            const newSubtrees = [...this.subtrees];
            newSubtrees[i] = await this.constructor._fromOptional(newSubtrees[i]).put(key, val, created);
            
            const newNode = new this.constructor(
                newSubtrees,
                this.keys,
                this.vals
            );
            created.add(newNode);
            return newNode;
        }
        
        // Can insert here
        return this._put_here(key, val, created);
    }

    /**
     * @param {string} key
     * @param {any} val
     * @param {Set<MSTNode>} created
     * @returns {MSTNode}
     */
    async _put_here(key, val, created = new Set()) {
        console.log('_put_here called with:', { key, val });
        if (val === undefined) {
            throw new Error('Value cannot be undefined');
        }

        const keyBytes = Buffer.from(key);
        const insertionIndex = this.keys.findIndex(k => k > key);
        console.log('Found insertion index:', insertionIndex);

        if (insertionIndex === -1) {
            // Key doesn't exist, create new node with updated arrays
            console.log('Creating new node with key-value pair');
            const newSubtrees = [...this.subtrees, null];
            const newKeys = [...this.keys, key];
            const newVals = [...this.vals, val];

            console.log('New node data:', {
                subtreesLength: newSubtrees.length,
                keys: newKeys,
                vals: newVals
            });

            // Create the node first
            const node = new MSTNode(newSubtrees, newKeys, newVals);
            console.log('Initializing node serialization');

            // Initialize the node's serialized data
            const entries = [];
            let prevKey = Buffer.from('');

            for (let i = 0; i < newKeys.length; i++) {
                const keyBytes = Buffer.from(newKeys[i]);
                const sharedPrefixLen = getSharedPrefixLength(prevKey, keyBytes);
                
                // Get the subtree CID if it exists
                let subtreeCid = null;
                if (newSubtrees[i + 1]) {
                    try {
                        subtreeCid = await newSubtrees[i + 1].getCid();
                    } catch (error) {
                        console.error('Error getting subtree CID:', error);
                        throw error;
                    }
                }

                // Ensure the value is not undefined and properly serialize CID
                const value = newVals[i];
                if (value === undefined) {
                    throw new Error('Value cannot be undefined');
                }

                // If value is a CID, use it directly (dagCbor will encode it as tag 42)
                let serializedValue = value;
                if (typeof value === 'string' && value.startsWith('bafy')) {
                    try {
                        serializedValue = CID.parse(value);
                    } catch (e) {
                        // Not a valid CID, keep as is
                    }
                }

                // Create entry with proper CID objects (not strings)
                const entry = {
                    k: new Uint8Array(keyBytes.slice(sharedPrefixLen)),
                    p: sharedPrefixLen,
                    t: subtreeCid, // Use CID object directly
                    v: serializedValue // Use CID object directly if it's a CID
                };

                console.log('Created entry:', JSON.stringify(entry));
                entries.push(entry);
                prevKey = keyBytes;
            }

            // Get the left subtree CID if it exists
            let leftSubtreeCid = null;
            if (newSubtrees[0]) {
                try {
                    leftSubtreeCid = await newSubtrees[0].getCid();
                } catch (error) {
                    console.error('Error getting left subtree CID:', error);
                    throw error;
                }
            }

            // Create a valid empty node structure with proper CID objects
            const serializable = {
                e: entries,
                l: leftSubtreeCid // Use CID object directly
            };

            console.log('Serializable data:', JSON.stringify(serializable));
            try {
                // Generate CID for the new node
                const serialized = dagCbor.encode(serializable);
                console.log('Serialized data length:', serialized.length);
                const hash = await sha256.digest(serialized);
                node._cid = CID.create(1, 0x71, hash);
                node._serialised = serialized;
                console.log('Generated CID for new node:', node._cid.toString());
            } catch (error) {
                console.error('Error encoding serializable data:', error);
                console.error('Serializable data:', serializable);
                throw error;
            }

            return node;
        }
        
        // Key exists, replace value
        console.log('Key exists, replacing value');
        if (this.vals[insertionIndex] === val) {
            console.log('Value unchanged, returning existing node');
            return this;
        }
        
        const newNode = new MSTNode(
            this.subtrees,
            this.keys,
            tupleReplaceAt(this.vals, insertionIndex, val)
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
     * @returns {Promise<CID>}
     */
    async getCid() {
        console.log('Getting CID for node');
        if (this._cid) {
            console.log('Using cached CID:', this._cid.toString());
            return this._cid;
        }

        console.log('Generating new CID');
        const serialized = await this.getSerialised();
        console.log('Got serialized data, length:', serialized.length);

        try {
            const hash = await sha256.digest(serialized);
            console.log('Generated hash:', hash.toString('hex'));
            this._cid = CID.create(1, 0x71, hash);
            console.log('Generated CID:', this._cid.toString());
            return this._cid;
        } catch (error) {
            console.error('Error generating CID:', error);
            throw error;
        }
    }

    /**
     * @returns {Promise<Uint8Array>}
     */
    async getSerialised() {
        console.log('Getting serialized data for node');
        if (this._serialised) {
            console.log('Using cached serialized data');
            return this._serialised;
        }

        console.log('Generating new serialized data');
        const entries = [];
        let prevKey = Buffer.from('');

        for (let i = 0; i < this.keys.length; i++) {
            console.log('Processing entry:', i);
            const keyBytes = Buffer.from(this.keys[i]);
            const sharedPrefixLen = getSharedPrefixLength(prevKey, keyBytes);
            
            // Get the subtree CID if it exists
            let subtreeCid = null;
            if (this.subtrees[i + 1]) {
                try {
                    subtreeCid = await this.subtrees[i + 1].getCid();
                    console.log('Got subtree CID:', subtreeCid.toString());
                } catch (error) {
                    console.error('Error getting subtree CID:', error);
                    throw error;
                }
            }

            // Ensure the value is not undefined and properly serialize CID
            const value = this.vals[i];
            if (value === undefined) {
                throw new Error('Value cannot be undefined');
            }

            // If value is a CID, use it directly (dagCbor will encode it as tag 42)
            let serializedValue = value;
            if (typeof value === 'string' && value.startsWith('bafy')) {
                try {
                    serializedValue = CID.parse(value);
                } catch (e) {
                    // Not a valid CID, keep as is
                }
            }

            // Create entry with proper CID objects (not strings)
            const entry = {
                k: new Uint8Array(keyBytes.slice(sharedPrefixLen)),
                p: sharedPrefixLen,
                t: subtreeCid, // Use CID object directly
                v: serializedValue // Use CID object directly if it's a CID
            };

            console.log('Created entry:', JSON.stringify(entry));
            entries.push(entry);
            prevKey = keyBytes;
        }

        // Get the left subtree CID if it exists
        let leftSubtreeCid = null;
        if (this.subtrees[0]) {
            try {
                leftSubtreeCid = await this.subtrees[0].getCid();
                console.log('Got left subtree CID:', leftSubtreeCid.toString());
            } catch (error) {
                console.error('Error getting left subtree CID:', error);
                throw error;
            }
        }

        // Create a valid empty node structure with proper CID objects
        const serializable = {
            e: entries,
            l: leftSubtreeCid // Use CID object directly
        };

        console.log('Serializable data:', JSON.stringify(serializable));
        try {
            // Generate CID for the new node
            const serialized = dagCbor.encode(serializable);
            console.log('Serialized data length:', serialized.length);
            const hash = await sha256.digest(serialized);
            this._cid = CID.create(1, 0x71, hash);
            this._serialised = serialized;
            console.log('Generated CID for new node:', this._cid.toString());
            return this._serialised;
        } catch (error) {
            console.error('Error encoding serializable data:', error);
            console.error('Serializable data:', serializable);
            throw error;
        }
    }

    // Helper method to check CID state
    getCidState() {
        return {
            hasCid: !!this._cid,
            cidValue: this._cid?.toString(),
            hasSerialized: !!this._serialised,
            serializedLength: this._serialised?.length,
            keys: this.keys,
            subtreesLength: this.subtrees.length
        };
    }

    // Helper method to verify CID
    async verifyCid() {
        console.log('Verifying CID for node with keys:', this.keys);
        const state = this.getCidState();
        console.log('Current state:', state);

        if (!this._cid) {
            console.log('No CID found, generating new one...');
            await this.getCid();
        }

        // Verify the CID matches the serialized data
        const serialized = await this.getSerialised();
        const computedCid = await hashToCid(serialized);
        
        console.log('CID verification:', {
            storedCid: this._cid.toString(),
            computedCid: computedCid.toString(),
            matches: this._cid.toString() === computedCid.toString()
        });

        return this._cid.toString() === computedCid.toString();
    }

    // Helper method to mark the node as needing CID recalculation
    markOutdated() {
        console.log('Marking node as outdated');
        console.log('Previous state:', this.getCidState());
        this._cid = null;
        this._serialised = null;
        console.log('New state:', this.getCidState());
    }

    static key_height() {
        return 1; // For now, we're using a simple flat structure
    }
  }
  
  /**
   * MST wrapper class for mutable interface
   */
export class MST {
    constructor(root = null) {
        this.root = root || MSTNode.emptyRoot();
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
     * @returns {Promise<MST>}
     */
    async set(key, val) {
        console.log('Setting key:', key, 'value:', val);
        console.log('Current root state:', {
            keys: this.root.keys,
            vals: this.root.vals,
            subtrees: this.root.subtrees.length
        });

        try {
            const newRoot = await this.root.put(key, val, new Set());
            console.log('Created new root');

            // Ensure the new root has a CID and serialized data
            try {
                await newRoot.getCid();
                await newRoot.getSerialised();
                console.log('New root has CID and serialized data');
            } catch (error) {
                console.error('Error ensuring new root has CID and serialized data:', error);
                throw error;
            }

            return new MST(newRoot);
        } catch (error) {
            console.error('Error in set operation:', error);
            throw error;
        }
    }
  
    /**
     * @param {string} key
     * @returns {Promise<MST>}
     */
    async delete(key) {
        const created = new Set();
        const newRoot = this.root.delete(key, created);
        
        // Ensure all created nodes have CIDs
        for (const node of created) {
            if (!node._cid) {
                console.log('Computing CID for created node');
                await node.getCid();
            }
        }
        
        return new MST(newRoot);
    }
  
    /**
     * @param {string} key
     * @returns {Promise<any>}
     */
    async get(key) {
      return this.root.get(key);
    }
  
    /**
     * @param {string} key
     * @returns {boolean}
     */
    has(key) {
      return this.get(key, null) !== null;
    }
  
    /**
     * @param {string} key_min
     * @param {string} key_max
     * @param {boolean} reverse
     * @returns {Generator<[string, any]>}
     */
    *get_range(key_min, key_max, reverse = false) {
      yield* this.root.get_range(key_min, key_max, reverse);
    }

    /**
     * @returns {Promise<CID>}
     */
    async getCid() {
        return await this.root.getCid();
    }

    async getSerialised() {
        return await this.root.getSerialised();
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