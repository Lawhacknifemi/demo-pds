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

// Serialize function (matches Python's serialise exactly)
function serialise(roots, blocks) {
    // Create header with raw CID bytes
    const header = {
        version: 1,
        roots: roots.map(cid => {
            // Convert CID to raw bytes
            return cid instanceof CID ? cid.bytes : cid;
        })
    };
    const headerBytes = dagCbor.encode(header);
    
    // Start with header length and header
    let result = Buffer.concat([
        varintEncode(headerBytes.length),
        headerBytes
    ]);
    
    // Add each block
    for (const [block_cid, block_data] of blocks) {
        // Ensure block_cid is raw bytes
        const cidBytes = block_cid instanceof CID ? block_cid.bytes : block_cid;
        const blockLength = cidBytes.length + block_data.length;
        
        result = Buffer.concat([
            result,
            varintEncode(blockLength),
            cidBytes,
            block_data
        ]);
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