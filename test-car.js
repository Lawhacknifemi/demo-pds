import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { serialise } from './carfile.js';
import fs from 'fs';

async function testCarSerialization() {
    try {
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
        
        // Save to file for comparison
        fs.writeFileSync('test.car', serialized);
        
        console.log('CAR file generated successfully');
        console.log('CID:', cid.toString());
        console.log('File size:', serialized.length, 'bytes');
        console.log('First 32 bytes (hex):', serialized.slice(0, 32).toString('hex'));
        
        // Verify the structure
        const headerLength = serialized[0];
        const headerStart = 1;
        const headerEnd = headerStart + headerLength;
        const header = dagCbor.decode(serialized.slice(headerStart, headerEnd));
        
        console.log('\nHeader:', header);
        console.log('Version:', header.version);
        console.log('Roots:', header.roots.map(r => {
            // Skip the d8 2a 58 25 prefix when displaying the CID
            const cidBytes = r.slice(4);
            return CID.decode(cidBytes).toString();
        }));
        
        // Verify block
        const blockStart = headerEnd;
        const blockLength = serialized[blockStart];
        const blockData = serialized.slice(blockStart + 1, blockStart + 1 + blockLength);
        
        console.log('\nBlock data length:', blockLength);
        console.log('Block data (hex):', blockData.toString('hex'));

        // Try to read the Python-generated file
        try {
            const pythonCar = fs.readFileSync('../test-py.car');
            const pyHeaderLength = pythonCar[0];
            const pyHeaderStart = 1;
            const pyHeaderEnd = pyHeaderStart + pyHeaderLength;
            const pyHeader = dagCbor.decode(pythonCar.slice(pyHeaderStart, pyHeaderEnd));
            
            console.log('\nReading Python-generated CAR file:');
            console.log('Version:', pyHeader.version);
            console.log('Roots:', pyHeader.roots.map(r => {
                // Handle both raw bytes and CID objects
                if (r instanceof Uint8Array) {
                    const cidBytes = r.slice(4);
                    return CID.decode(cidBytes).toString();
                } else if (r instanceof CID) {
                    return r.toString();
                } else {
                    return r.toString();
                }
            }));
            
            // Verify the block data matches
            const pyBlockStart = pyHeaderEnd;
            const pyBlockLength = pythonCar[pyBlockStart];
            const pyBlockData = pythonCar.slice(pyBlockStart + 1, pyBlockStart + 1 + pyBlockLength);
            
            console.log('\nPython block data (hex):', pyBlockData.toString('hex'));
            console.log('Block data matches:', Buffer.compare(blockData, pyBlockData) === 0);
        } catch (err) {
            console.error('Error reading Python CAR file:', err);
        }
        
    } catch (err) {
        console.error('Error in test:', err);
    }
}

// Run the test
testCarSerialization().catch(console.error); 