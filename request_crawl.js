import { readFileSync } from 'fs';
import fetch from 'node-fetch';
import config from './config.js';
import jwt from 'jsonwebtoken';

// Read private key from PEM file as binary
const privkey = readFileSync('privkey.pem');

// Create JWT using the same approach as Python
const auth = jwt.sign({
    iss: config.DID_PLC,
    aud: `did:web:${config.BGS_SERVER}`,
    exp: Math.floor(Date.now() / 1000) + 60 * 60 // 1h
}, privkey, { algorithm: 'ES256K' });

// Make request - matching Python's requests.post behavior
async function requestCrawl() {
    try {
        const response = await fetch(
            `https://${config.BGS_SERVER}/xrpc/com.atproto.sync.requestCrawl`,
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${auth}`
                },
                body: JSON.stringify({
                    hostname: config.PDS_SERVER
                })
            }
        );

        // Match Python's response handling
        if (!response.ok) {
            console.error('Request failed:', response.status, response.statusText);
            return;
        }

        // Get response text (matching Python's r.text)
        const text = await response.text();
        console.log('Response:', text);
    } catch (error) {
        console.error('Error:', error);
    }
}

requestCrawl(); 