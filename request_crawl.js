import { readFileSync } from 'fs';
import fetch from 'node-fetch';
import config from './config.js';
import { secp256k1 } from '@noble/curves/secp256k1';
import { SignJWT } from 'jose';
import { applyLowSMitigation } from './jwtLowSMitigation.js';

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
        // Create a JWK from the private key
        const jwk = {
            kty: 'EC',
            crv: 'secp256k1',
            d: privateKey.toString('base64url'),
            x: secp256k1.getPublicKey(privateKey, false).slice(1, 33).toString('base64url'),
            y: secp256k1.getPublicKey(privateKey, false).slice(33).toString('base64url')
        };

        // Create JWT with ES256K and apply low-s mitigation
        const jwt = await new SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256K', typ: 'JWT' })
            .sign(jwk);

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