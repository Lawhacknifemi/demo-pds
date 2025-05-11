import { readFileSync } from 'fs';
import fetch from 'node-fetch';
import config from './config.js';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import base64url from 'base64url';

// Read private key and convert from hex to binary
const privateKeyHex = readFileSync('private.key', 'utf8');
const privateKey = Buffer.from(privateKeyHex, 'hex');

// Create JWT
const payload = {
    iss: config.DID_PLC,
    aud: `did:web:${config.BGS_SERVER}`,
    exp: Math.floor(Date.now() / 1000) + 60 * 60 // 1h
};

// Make request
async function requestCrawl() {
    try {
        // Create JWT header and payload
        const header = { alg: 'ES256K', typ: 'JWT' };
        const encodedHeader = base64url(JSON.stringify(header));
        const encodedPayload = base64url(JSON.stringify(payload));
        const signingInput = `${encodedHeader}.${encodedPayload}`;

        // Hash the signing input before signing (matching Python implementation)
        const msgHash = sha256(Buffer.from(signingInput));
        
        // Sign the JWT
        const signature = await secp256k1.sign(msgHash, privateKey);
        const encodedSignature = base64url(signature.toDER());
        const jwt = `${signingInput}.${encodedSignature}`;

        console.log('Requesting crawl with JWT:', jwt);
        const response = await fetch(
            `https://${config.BGS_SERVER}/xrpc/com.atproto.sync.requestCrawl`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${jwt}`
                },
                body: JSON.stringify({
                    hostname: config.PDS_SERVER
                })
            }
        );

        console.log('Status:', response.ok, response.status);
        const content = await response.text();
        console.log('Response:', content);
    } catch (error) {
        console.error('Error:', error);
    }
}

requestCrawl(); 