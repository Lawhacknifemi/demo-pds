import { readFileSync } from 'fs';
import { createPrivateKey } from 'crypto';

/**
 * Convert a PEM private key to hex format
 * @param {string} pemPath - Path to the PEM file
 * @returns {string} - Hex-encoded private key
 */
export function pemToHex(pemPath) {
    const pemContent = readFileSync(pemPath, 'utf8');
    // Extract the base64 content between the header and footer
    const base64Content = pemContent
        .replace('-----BEGIN PRIVATE KEY-----', '')
        .replace('-----END PRIVATE KEY-----', '')
        .replace(/\s/g, '');
    
    // Convert base64 to hex
    const der = Buffer.from(base64Content, 'base64');
    return der.toString('hex');
}

/**
 * Convert a hex private key to PEM format
 * @param {string} hexKey - Hex-encoded private key
 * @returns {string} - PEM formatted private key
 */
export function hexToPem(hexKey) {
    const der = Buffer.from(hexKey, 'hex');
    const base64 = der.toString('base64');
    
    // Format the PEM string
    const pem = [
        '-----BEGIN PRIVATE KEY-----',
        base64.match(/.{1,64}/g).join('\n'),
        '-----END PRIVATE KEY-----'
    ].join('\n');
    
    return pem;
} 