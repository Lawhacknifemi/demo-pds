import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { Buffer } from 'buffer';
import { createSign, createHash } from 'crypto';

// Constants for curve orders (matching Python's format)
const CURVE_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

/**
 * Converts a Buffer to a BigInt
 * @param {Buffer} buf - The buffer to convert
 * @returns {BigInt} - The resulting BigInt
 */
function bufferToBigInt(buf) {
    let hex = Array.from(buf)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    return BigInt('0x' + hex);
}

/**
 * Converts a BigInt to a fixed-length Buffer
 * @param {BigInt} num - The number to convert
 * @param {number} length - The desired buffer length
 * @returns {Buffer} - The resulting buffer
 */
function bigIntToBuffer(num, length) {
    return Buffer.from(num.toString(16).padStart(length * 2, '0'), 'hex');
}

/**
 * Applies low-S mitigation to a signature.
 * @param {Object} signature - The signature object from secp256k1
 * @returns {Object} - The mitigated signature
 */
function applyLowSMitigation(signature) {
    const { r, s } = signature;
    if (s > CURVE_ORDER / 2n) {
        return { r, s: CURVE_ORDER - s };
    }
    return signature;
}

/**
 * Creates a raw signature matching Python's implementation.
 * @param {Buffer} privateKey - The private key buffer
 * @param {Buffer} data - The data to sign
 * @returns {Buffer} - The raw signature (r||s)
 */
function rawSign(privkey, data) {
    // Pre-hash the message like Python does
    const msgHash = sha256(data);
    
    // Sign the hash
    const signature = secp256k1.sign(msgHash, privkey);
    
    // Apply low-S mitigation
    const mitigated = applyLowSMitigation(signature);
    
    // Convert to raw bytes format matching Python's output
    const rBytes = mitigated.r.toString(16).padStart(64, '0');
    const sBytes = mitigated.s.toString(16).padStart(64, '0');
    
    // Combine r and s into a single buffer, each exactly 32 bytes
    return Buffer.from(rBytes + sBytes, 'hex');
}

/**
 * Converts a signature from DER format to raw r||s format
 * @param {Buffer} derSignature - The DER signature
 * @returns {Buffer} - The raw signature
 */
function derToRaw(derSignature) {
    // DER format:
    // 30 len 02 rlen r 02 slen s
    let offset = 2; // Skip 30 and total length
    
    // Get r
    offset++; // Skip 02
    const rLen = derSignature[offset++];
    const r = derSignature.slice(offset, offset + rLen);
    offset += rLen;
    
    // Get s
    offset++; // Skip 02
    const sLen = derSignature[offset++];
    const s = derSignature.slice(offset, offset + sLen);
    
    // Convert to fixed 32-byte values with proper padding
    const rPadded = Buffer.alloc(32, 0);
    const sPadded = Buffer.alloc(32, 0);
    
    // Remove any leading zero added for positive integers
    const rVal = r[0] === 0 ? r.slice(1) : r;
    const sVal = s[0] === 0 ? s.slice(1) : s;
    
    rVal.copy(rPadded, 32 - rVal.length);
    sVal.copy(sPadded, 32 - sVal.length);
    
    return Buffer.concat([rPadded, sPadded]);
}

/**
 * Converts a signature from raw r||s format to DER format
 * @param {Buffer} rawSignature - The raw signature
 * @returns {Buffer} - The DER signature
 */
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

async function hashToCid(data, codec = "dag-cbor") {
    const hash = await createHash('sha256').update(data).digest();
    return {
        version: 1,
        codec,
        digest: hash
    };
}

export { rawSign, applyLowSMitigation, CURVE_ORDER, derToRaw, rawToDer, hashToCid }; 