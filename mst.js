import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { createHash } from 'crypto';

class MSTNode {
    constructor(data) {
        this.key = data.key;
        this.value = data.value;
        this.children = data.children || [];
    }

    static emptyRoot() {
        return new MSTNode({ key: '', value: null });
    }

    height() {
        if (this.children.length === 0) return 0;
        return 1 + Math.max(...this.children.map(child => child ? child.height() : 0));
    }

    _gteIndex(key) {
        let left = 0;
        let right = this.children.length;
        while (left < right) {
            const mid = Math.floor((left + right) / 2);
            if (this.children[mid].key <= key) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        return left;
    }

    put(key, value) {
        if (this.children.length === 0) {
            // Leaf node
            if (this.key === key) {
                return new MSTNode({ ...this, value });
            }
            const newChildren = [this, new MSTNode({ key, value })];
            newChildren.sort((a, b) => a.key.localeCompare(b.key));
            return new MSTNode({ key: '', value: null, children: newChildren });
        }

        const index = this._gteIndex(key);
        if (index > 0 && this.children[index - 1].key === key) {
            // Update existing key
            const newChildren = [...this.children];
            newChildren[index - 1] = newChildren[index - 1].put(key, value);
            return new MSTNode({ ...this, children: newChildren });
        }

        // Insert new key
        const newChildren = [...this.children];
        newChildren.splice(index, 0, new MSTNode({ key, value }));
        return new MSTNode({ ...this, children: newChildren });
    }

    delete(key) {
        if (this.children.length === 0) {
            return this.key === key ? null : this;
        }

        const index = this._gteIndex(key);
        if (index > 0 && this.children[index - 1].key === key) {
            // Remove the key
            const newChildren = [...this.children];
            newChildren.splice(index - 1, 1);
            if (newChildren.length === 1) {
                return newChildren[0];
            }
            return new MSTNode({ ...this, children: newChildren });
        }

        // Key not found
        return this;
    }

    get(key) {
        if (this.children.length === 0) {
            return this.key === key ? this.value : null;
        }

        const index = this._gteIndex(key);
        if (index > 0 && this.children[index - 1].key === key) {
            return this.children[index - 1].value;
        }

        return null;
    }

    *enumerate() {
        if (this.children.length === 0) {
            if (this.key) {
                yield [this.key, this.value];
            }
        } else {
            for (const child of this.children) {
                if (child) {
                    yield* child.enumerate();
                }
            }
        }
    }
}

export { MSTNode }; 