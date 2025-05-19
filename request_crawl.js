import { readFileSync } from 'fs';
import fetch from 'node-fetch';
import config from './config.js';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import base64url from 'base64url';

// Read private key from PEM file as utf8
const privkeyPem = readFileSync('privkey.pem', 'utf8');
// Extract the private key bytes from the PEM
const privateKeyBase64 = privkeyPem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
const privateKeyDer = Buffer.from(privateKeyBase64, 'base64');
// The last 32 bytes of the DER are the actual private key
const privkey = privateKeyDer.slice(-32);

// Create JWT using ES256K
function createJWT(payload) {
    const header = {
        typ: 'JWT',
        alg: 'ES256K'
    };

    const encodedHeader = base64url.encode(JSON.stringify(header));
    const encodedPayload = base64url.encode(JSON.stringify(payload));
    const unsignedToken = `${encodedHeader}.${encodedPayload}`;

    // Sign the token
    const messageHash = sha256(unsignedToken);
    const signature = secp256k1.sign(messageHash, privkey);
    const encodedSignature = base64url.encode(signature.toCompactHex());

    return `${unsignedToken}.${encodedSignature}`;
}

// Make request - matching Python's requests.post behavior
async function requestCrawl() {
    try {
        const payload = {
            iss: config.DID_PLC,
            aud: `did:web:${config.BGS_SERVER}`,
            exp: Math.floor(Date.now() / 1000) + 60 * 60 // 1h
        };

        const auth = createJWT(payload);
        console.log('JWT:', auth); // Debug log

        const response = await fetch(
            `https://${config.BGS_SERVER}/xrpc/com.atproto.sync.requestCrawl`,
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${auth}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    hostname: config.PDS_SERVER
                })
            }
        );

        // Match Python's response handling
        if (!response.ok) {
            console.error('Request failed:', response.status, response.statusText);
            const text = await response.text();
            console.error('Response body:', text);
            return;
        }

        // Get response text (matching Python's r.text)
        const text = await response.text();
        console.log('Response:', text);
    } catch (error) {
        console.error('Error:', error);
    }
}

// Run the request
requestCrawl(); 