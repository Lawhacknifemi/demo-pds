// First, install the required packages:
// npm install multiformats @ipld/dag-cbor
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';

// leb128 - exact match to Python's varint_encode
function varint_encode(n) {
    const result = [];
    while (n) {
        const x = n % 128;
        n = Math.floor(n / 128);
        result.push(x | ((n !== 0) << 7));
    }
    return new Uint8Array(result);
}

// note: this function expects block CIDS and values to be pre-serialised, but not roots!
// exact match to Python's serialise function
function serialise(roots, blocks) {
    let result = new Uint8Array(0);
    
    const header = dagCbor.encode({
        "version": 1,
        "roots": roots
    });
    
    // Concatenate header length + header
    const headerLenBytes = varint_encode(header.length);
    result = concatUint8Arrays(result, headerLenBytes, header);
    
    // Process blocks exactly like Python version
    for (const [block_cid, block_data] of blocks) {
        const totalLen = block_cid.length + block_data.length;
        const lenBytes = varint_encode(totalLen);
        result = concatUint8Arrays(result, lenBytes, block_cid, block_data);
    }
    
    return result;
}

// Helper function to concatenate Uint8Arrays (since JS doesn't have Python's += for bytes)
function concatUint8Arrays(...arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

// Example usage matching the expected input format
async function example() {
    try {
        console.log('Running carfile.js example...');
        
        // Example CID (you would get this from your actual data)
        const exampleCid = CID.parse('bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi');
        
        // Pre-serialized block data (as expected by the function)
        const blockCidBytes = exampleCid.bytes;  // CID as bytes
        const blockDataBytes = new TextEncoder().encode('example data');  // Your actual block data
        
        console.log('Block CID bytes length:', blockCidBytes.length);
        console.log('Block data bytes length:', blockDataBytes.length);
        
        // Call serialise with exact same signature as Python
        const roots = [exampleCid];  // List of CID objects (not pre-serialized)
        const blocks = [
            [blockCidBytes, blockDataBytes]  // Iterable of [cid_bytes, data_bytes] tuples
        ];
        
        const serialized = serialise(roots, blocks);
        console.log('Serialized bytes length:', serialized.length);
        console.log('Hex:', Array.from(serialized).map(b => b.toString(16).padStart(2, '0')).join(''));
        
    } catch (error) {
        console.error('Error in example:', error);
    }
}

// Run the example when this file is executed
example();

export { varint_encode, serialise };