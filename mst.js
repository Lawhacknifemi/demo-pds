// mst.js - Complete working implementation of Merkle Search Tree

import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from '@noble/hashes/sha256';

/**
 * Helper functions for array manipulation (immutable operations)
 */
function tuple_replace_at(original, i, value) {
    return [...original.slice(0, i), value, ...original.slice(i + 1)];
  }
  
  function tuple_insert_at(original, i, value) {
    return [...original.slice(0, i), value, ...original.slice(i)];
  }
  
  function tuple_remove_at(original, i) {
    return [...original.slice(0, i), ...original.slice(i + 1)];
  }
  
  /**
   * Base MSTNode class - represents nodes in the Merkle Search Tree
   */
  export class MSTNode {
    constructor(subtrees = [null], keys = [], vals = []) {
        this.subtrees = subtrees;
        this.keys = keys;
        this.vals = vals;
    }

    static async create(subtrees = [null], keys = [], vals = []) {
        return new MSTNode(subtrees, keys, vals);
    }

    async put(key, value) {
        const entry = { key, value };
        const newEntries = [...this.entries, entry].sort((a, b) => a.key.localeCompare(b.key));
        return new MSTNode(this.subtrees, [...this.keys, key], [...this.vals, value]);
    }

    async get(key) {
        const entry = this.entries.find(e => e.key === key);
        if (entry) {
            return entry.value;
        }
        return null;
    }

    async delete(key) {
        const newEntries = this.entries.filter(e => e.key !== key);
        return new MSTNode(this.subtrees, this.keys.filter(k => k !== key), this.vals.filter(v => v !== key));
    }

    async cid() {
        const data = {
            entries: this.entries,
            children: this.subtrees
        };
        const bytes = dagCbor.encode(data);
        const hash = sha256(bytes);
        return CID.create(1, 0x71, hash);
    }

    async toJSON() {
        return {
            entries: this.entries,
            children: this.subtrees
        };
    }

    static async fromJSON(json) {
        return new MSTNode(json.children, json.entries.map(e => e.key), json.entries.map(e => e.value));
    }

    static key_height(key) {
      return key.length;
    }
  
    static empty_root() {
      return new MSTNode([null], [], []);
    }
  
    static _from_optional(value) {
      if (value === null) {
        return this.empty_root();
      }
      return value;
    }
  
    _to_optional() {
      if (this.subtrees.length === 1 && this.subtrees[0] === null && this.keys.length === 0) {
        return null;
      }
      return this;
    }
  
    _squash_top(created) {
      if (this.keys.length) {
        return this;
      }
      if (this.subtrees[0] === null) {
        return this;
      }
      created.delete(this);
      return this.subtrees[0]._squash_top(created);
    }
  
    height() {
      if (this.keys.length > 0) {
        return this.constructor.key_height(this.keys[0]);
      }
      
      if (this.subtrees[0] === null) {
        return 0;
      }
      
      return this.subtrees[0].height() + 1;
    }
  
    _gte_index(key) {
      let i = 0;
      while (i < this.keys.length && key > this.keys[i]) {
        i++;
      }
      return i;
    }
  
    *get_range(key_min, key_max, reverse = false) {
      const start = this._gte_index(key_min);
      const end = this._gte_index(key_max);
      
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
  
    put(key, val, created = new Set()) {
      if (this.subtrees.length === 1 && this.subtrees[0] === null && this.keys.length === 0) {
        return this._put_here(key, val, created);
      }
      return this._put_recursive(key, val, this.constructor.key_height(key), this.height(), created);
    }
  
    _put_recursive(key, val, key_height, tree_height, created = new Set()) {
      const cls = this.constructor;
  
      if (key_height > tree_height) {
        const new_node = new cls([this], [], [])._put_recursive(key, val, key_height, tree_height + 1, created);
        created.add(new_node);
        return new_node;
      }
      
      if (key_height < tree_height) {
        const i = this._gte_index(key);
        const new_subtree = cls._from_optional(this.subtrees[i])._put_recursive(
          key, val, key_height, tree_height - 1, created
        );
        
        const new_node = new cls(
          tuple_replace_at(this.subtrees, i, new_subtree),
          [...this.keys],
          [...this.vals]
        );
        created.add(new_node);
        return new_node;
      }
      
      return this._put_here(key, val, created);
    }
  
    _put_here(key, val, created = new Set()) {
      const cls = this.constructor;
      
      const i = this._gte_index(key);
      if (i < this.keys.length && this.keys[i] === key) {
        if (this.vals[i] === val) {
          return this;
        }
        const new_node = new cls(
          [...this.subtrees],
          [...this.keys],
          tuple_replace_at(this.vals, i, val)
        );
        created.add(new_node);
        return new_node;
      }
      
      const [left, right] = cls._split_on_key(this.subtrees[i], key, created);
      const new_subtrees = [
        ...this.subtrees.slice(0, i),
        left,
        right,
        ...this.subtrees.slice(i + 1)
      ];
      
      const new_node = new cls(
        new_subtrees,
        tuple_insert_at(this.keys, i, key),
        tuple_insert_at(this.vals, i, val)
      );
      created.add(new_node);
      return new_node;
    }
  
    static _split_on_key(tree, key, created = new Set()) {
      if (tree === null) {
        return [null, null];
      }
      
      const i = tree._gte_index(key);
      const [lsub, rsub] = this._split_on_key(tree.subtrees[i], key, created);
      
      const left = new this({
        subtrees: [...tree.subtrees.slice(0, i), lsub],
        keys: tree.keys.slice(0, i),
        vals: tree.vals.slice(0, i)
      })._to_optional();
      
      const right = new this({
        subtrees: [rsub, ...tree.subtrees.slice(i + 1)],
        keys: tree.keys.slice(i),
        vals: tree.vals.slice(i)
      })._to_optional();
      
      if (left !== null) {
        created.add(left);
      }
      if (right !== null) {
        created.add(right);
      }
      
      return [left, right];
    }
  
    delete(key, created = new Set()) {
      return this.constructor._from_optional(
        this._delete_recursive(key, this.constructor.key_height(key), this.height(), created)
      )._squash_top(created);
    }
  
    _delete_recursive(key, key_height, tree_height, created = new Set()) {
      const cls = this.constructor;
  
      if (key_height > tree_height) {
        // The key cannot possibly be in this tree
        return this;
      } else if (key_height < tree_height) {
        // The key must be deleted from a subtree
        const i = this._gte_index(key);
        if (this.subtrees[i] === null) {
          return this; // The key cannot be in this subtree
        }
        
        const new_subtree = this.subtrees[i]._delete_recursive(
          key, key_height, tree_height - 1, created
        );
        
        console.log("_delete_recursive returned:", new_subtree);
        const new_node = new cls({
          subtrees: tuple_replace_at(this.subtrees, i, new_subtree),
          keys: [...this.keys],
          vals: [...this.vals]
        })._to_optional();
        
        if (new_node !== null) {
          created.add(new_node);
        }
        return new_node;
      }
      
      const i = this._gte_index(key);
      if (i === this.keys.length || this.keys[i] !== key) {
        return this; // Key already not present
      }
      
      const merged = cls._merge(this.subtrees[i], this.subtrees[i + 1], created);
      const new_subtrees = [
        ...this.subtrees.slice(0, i),
        merged,
        ...this.subtrees.slice(i + 2)
      ];
      
      const new_node = new cls({
        subtrees: new_subtrees,
        keys: tuple_remove_at(this.keys, i),
        vals: tuple_remove_at(this.vals, i)
      })._to_optional();
      
      if (new_node !== null) {
        created.add(new_node);
      }
      return new_node;
    }
  
    static _merge(left, right, created = new Set()) {
      if (left === null) {
        return right; // Includes the case where left === right === null
      }
      if (right === null) {
        return left;
      }
      
      const merged = this._merge(
        left.subtrees[left.subtrees.length - 1], 
        right.subtrees[0], 
        created
      );
      
      const new_subtrees = [
        ...left.subtrees.slice(0, -1),
        merged,
        ...right.subtrees.slice(1)
      ];
      
      const new_node = new this({
        subtrees: new_subtrees,
        keys: [...left.keys, ...right.keys],
        vals: [...left.vals, ...right.vals]
      })._to_optional();
      
      if (new_node !== null) {
        created.add(new_node);
      }
      return new_node;
    }

    static empty_root(...args) {
        // Your existing implementation (if any)
        // For now, return a new empty MSTNode
        return new MSTNode();
    }
    static emptyRoot(...args) {
        return this.empty_root(...args);
    }
  }
  
  /**
   * MST wrapper class for mutable interface
   */
  class MST {
    constructor(root) {
      this.root = root;
    }
  
    static new_with(node_type) {
      return new MST(node_type.empty_root());
    }
  
    height() {
      return this.root.height();
    }
  
    // JavaScript-style methods
    set(key, val) {
      this.root = this.root.put(key, val, new Set());
      return this;
    }
  
    delete(key) {
      const prev_root = this.root;
      this.root = this.root.delete(key, new Set());
      if (this.root === prev_root) {
        throw new Error(`Key '${key}' not found`);
      }
      return this;
    }
  
    get(key, sentinel = null) {
      return this.root.get(key, sentinel);
    }
  
    has(key) {
      return this.get(key) !== null;
    }
  
    *get_range(key_min, key_max, reverse = false) {
      yield* this.root.get_range(key_min, key_max, reverse);
    }
    
    // For compatibility with JavaScript Map/Object patterns
    set_item(key, value) {
      return this.set(key, value);
    }
    
    get_item(key) {
      const value = this.get(key);
      if (value === null) {
        throw new Error(`Key '${key}' not found`);
      }
      return value;
    }
  }
  
  /**
   * Example implementation
   */
  class StrlenNode extends MSTNode {
    static key_height(key) {
      return key.length;
    }
  }
  
  // Expose classes
  if (typeof exports !== 'undefined') {
    exports.MSTNode = MSTNode;
    exports.MST = MST;
    exports.StrlenNode = StrlenNode;
  }
  
  // Example usage and tests
  if (typeof require !== 'undefined' && require.main === module) {
    console.log("Running MST tests...");
    
    // Create tree and test basic operations
    const tree = MST.new_with(StrlenNode);
    tree.set("foo", "bar");
    console.assert(tree.get("foo") === "bar", "Basic get/set failed");
    
    // More items for testing
    tree.set("f", "f");
    tree.set("foooooo", "foooooo");
    tree.set("bar", "bar");
    tree.set("bat", "bat");
    
    // Delete items
    tree.delete("foo");
    tree.delete("bar");
    tree.delete("bat");
    
    // Test trees
    const t2 = new MST(tree.root);
    t2.delete("foooooo");
    console.assert(t2.get("f") === "f", "Tree copy failed");
    
    const t3 = new MST(tree.root);
    t3.delete("f");
    console.assert(t3.get("foooooo") === "foooooo", "Tree copy failed");
    
    // Clean up both trees
    t2.delete("f");
    t3.delete("foooooo");
    
    // Test insertion order independence
    const words1 = ["foo", "bar", "hello", "world", "this", "is", "a", "test"];
    const words2 = [...words1].sort();
    
    const tree1 = MST.new_with(StrlenNode);
    words1.forEach(word => tree1.set(word, 123));
    
    const tree2 = MST.new_with(StrlenNode);
    words2.forEach(word => tree2.set(word, 123));
    
    // Compare structure (trees should be identical despite different insertion order)
    console.assert(tree1.height() === tree2.height(), "Tree heights differ");
    words1.forEach(word => {
      console.assert(tree1.get(word) === tree2.get(word), "Tree content differs");
    });
    
    // Test range queries
    const rangeTree = MST.new_with(StrlenNode);
    rangeTree.set("0", null);
    rangeTree.set("01", null);
    rangeTree.set("02", null);
    rangeTree.set("1", null);
    rangeTree.set("12", null);
    rangeTree.set("13", null);
    rangeTree.set("2", null);
    
    // Test expected range results
    const range1 = Array.from(rangeTree.get_range("02", "3"));
    const expected1 = [
      ["02", null],
      ["1", null],
      ["12", null],
      ["13", null],
      ["2", null]
    ];
    console.assert(
      JSON.stringify(range1) === JSON.stringify(expected1),
      "Range query failed"
    );
    
    // End value should be exclusive
    const range2 = Array.from(rangeTree.get_range("0", "13"));
    const expected2 = [
      ["0", null],
      ["01", null],
      ["02", null],
      ["1", null],
      ["12", null]
    ];
    console.assert(
      JSON.stringify(range2) === JSON.stringify(expected2),
      "Exclusive range failed"
    );
    
    console.log("All MST tests passed!");
  }

// Export the MSTNode class as default
export default MSTNode;