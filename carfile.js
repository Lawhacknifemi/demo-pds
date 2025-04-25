// First, install the required packages:
// npm install multiformats dag-cbor
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
// const { CID } = require('multiformats');
// const dagCbor = require('@ipld/dag-cbor');

// LEB128 varint encoding (matches Python's varint_encode)
function varintEncode(n) {
    const result = [];
    while (n) {
        const [quotient, remainder] = [Math.floor(n / 128), n % 128];
        n = quotient;
        result.push(remainder | (n !== 0 ? 128 : 0));
    }
    return new Uint8Array(result);
}

// Serialize function (matches Python's serialise)
function serialise(roots, blocks) {
    // Create and encode header
    const header = {
        version: 1,
        roots: roots.map(root => root.toString())
    };
    const headerBytes = dagCbor.encode(header);
    
    // Calculate total size needed
    const headerSize = varintEncode(headerBytes.length).length + headerBytes.length;
    const blocksSize = blocks.reduce((acc, [cid, data]) => {
        const blockSize = varintEncode(cid.length + data.length).length + cid.length + data.length;
        return acc + blockSize;
    }, 0);
    
    // Create result buffer
    const result = new Uint8Array(headerSize + blocksSize);
    let offset = 0;
    
    // Write header length and header
    const headerLengthBytes = varintEncode(headerBytes.length);
    result.set(headerLengthBytes, offset);
    offset += headerLengthBytes.length;
    result.set(headerBytes, offset);
    offset += headerBytes.length;
    
    // Write each block
    for (const [block_cid, block_data] of blocks) {
        const block_length = block_cid.length + block_data.length;
        const lengthBytes = varintEncode(block_length);
        
        result.set(lengthBytes, offset);
        offset += lengthBytes.length;
        result.set(block_cid, offset);
        offset += block_cid.length;
        result.set(block_data, offset);
        offset += block_data.length;
    }
    
    return result;
}

export { varintEncode, serialise };

// Example usage
async function main() {
    // Create test data
    const testData = new TextEncoder().encode("Hello, World!");
    
    // Create SHA-256 hash
    const hash = await sha256.digest(testData);
    
    // Create CID (using the same approach as create_dag_cbor_cid)
    const cid = CID.create(1, 0x71, hash);
    
    // Create blocks array
    const blocks = [[cid.bytes, testData]];
    
    // Serialize
    const serialized = serialise([cid], blocks);
    
    // Print hex representation
    console.log(Buffer.from(serialized).toString('hex'));
}

// Run the example
main().catch(console.error);