import { readFileSync } from 'fs';
import fetch from 'node-fetch';
import config from './config.js';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import base64url from 'base64url';

// Read private key from PEM file
const privateKeyPem = readFileSync('privkey.pem', 'utf8');
// Extract the private key bytes from the PEM
const privateKeyBase64 = privateKeyPem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
const privateKeyDer = Buffer.from(privateKeyBase64, 'base64');
// The last 32 bytes of the DER are the actual private key
const privateKey = privateKeyDer.slice(-32);

// Create JWT payload
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

        // Hash the signing input
        const msgHash = sha256(Buffer.from(signingInput));
        
        // Sign the JWT
        const signature = secp256k1.sign(msgHash, privateKey);
        
        // Convert signature to raw bytes
        const r = Buffer.from(signature.r.toString(16).padStart(64, '0'), 'hex');
        const s = Buffer.from(signature.s.toString(16).padStart(64, '0'), 'hex');
        const rawSignature = Buffer.concat([r, s]);
        
        // Convert to DER format
        const derSignature = rawToDer(rawSignature);
        const encodedSignature = base64url(derSignature);
        
        const token = `${signingInput}.${encodedSignature}`;

        console.log('Requesting crawl with JWT:', token);
        const response = await fetch(
            `https://${config.BGS_SERVER}/xrpc/com.atproto.sync.requestCrawl`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
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

// Function to convert raw signature to DER format
function rawToDer(rawSignature) {
    const r = rawSignature.slice(0, 32);
    const s = rawSignature.slice(32);
    
    // Remove leading zeros
    let rStart = 0;
    while (rStart < r.length && r[rStart] === 0) rStart++;
    let sStart = 0;
    while (sStart < s.length && s[sStart] === 0) sStart++;
    
    // If all zeros, use one zero byte
    if (rStart === r.length) rStart = r.length - 1;
    if (sStart === s.length) sStart = s.length - 1;
    
    const rVal = r.slice(rStart);
    const sVal = s.slice(sStart);
    
    // Add leading zero if high bit is set
    const rPad = (rVal[0] & 0x80) !== 0 ? 1 : 0;
    const sPad = (sVal[0] & 0x80) !== 0 ? 1 : 0;
    
    const rLen = rVal.length + rPad;
    const sLen = sVal.length + sPad;
    const totalLen = 2 + rLen + 2 + sLen;
    
    const der = Buffer.alloc(2 + totalLen);
    let offset = 0;
    
    // DER header
    der[offset++] = 0x30;
    der[offset++] = totalLen;
    
    // R value
    der[offset++] = 0x02;
    der[offset++] = rLen;
    if (rPad) der[offset++] = 0;
    rVal.copy(der, offset);
    offset += rVal.length;
    
    // S value
    der[offset++] = 0x02;
    der[offset++] = sLen;
    if (sPad) der[offset++] = 0;
    sVal.copy(der, offset);
    
    return der;
}

requestCrawl(); 