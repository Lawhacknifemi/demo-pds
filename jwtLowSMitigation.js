import crypto from 'crypto';
import { createSign } from 'crypto';

// P-256 curve parameters
const P256_N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');

/**
 * Converts a DER-encoded signature to raw format (64 bytes)
 * @param {Buffer} derSignature - The DER-encoded signature
 * @returns {Buffer} - The raw signature (64 bytes)
 */
function derToRaw(derSignature) {
    let offset = 0;
    if (derSignature[offset++] !== 0x30) throw new Error('Invalid DER signature');
    const totalLength = derSignature[offset++];
    
    // Parse r
    if (derSignature[offset++] !== 0x02) throw new Error('Invalid DER signature');
    const rLength = derSignature[offset++];
    const r = derSignature.slice(offset, offset + rLength);
    offset += rLength;
    
    // Parse s
    if (derSignature[offset++] !== 0x02) throw new Error('Invalid DER signature');
    const sLength = derSignature[offset++];
    const s = derSignature.slice(offset, offset + sLength);
    
    // Pad r and s to 32 bytes each
    const rPadded = Buffer.alloc(32);
    const sPadded = Buffer.alloc(32);
    r.copy(rPadded, 32 - r.length);
    s.copy(sPadded, 32 - s.length);
    
    // Concatenate r and s
    return Buffer.concat([rPadded, sPadded]);
}

/**
 * Applies low-s mitigation to a DER-encoded signature
 * @param {Buffer} derSignature - The DER-encoded signature
 * @returns {Buffer} - The modified DER-encoded signature
 */
export function applyLowSMitigation(derSignature) {
    try {
        // Parse the DER signature
        let offset = 0;
        if (derSignature[offset++] !== 0x30) throw new Error('Invalid DER signature');
        const totalLength = derSignature[offset++];
        
        // Parse r
        if (derSignature[offset++] !== 0x02) throw new Error('Invalid DER signature');
        const rLength = derSignature[offset++];
        const r = derSignature.slice(offset, offset + rLength);
        offset += rLength;
        
        // Parse s
        if (derSignature[offset++] !== 0x02) throw new Error('Invalid DER signature');
        const sLength = derSignature[offset++];
        const s = derSignature.slice(offset, offset + sLength);
        
        // Convert s to a big integer
        const sBigInt = BigInt('0x' + s.toString('hex'));
        
        // If s > n/2, replace s with n - s
        if (sBigInt > P256_N / 2n) {
            const newS = P256_N - sBigInt;
            // Convert back to buffer
            const newSHex = newS.toString(16).padStart(sLength * 2, '0');
            const newSBuffer = Buffer.from(newSHex, 'hex');
            
            // Reconstruct the DER signature
            const newDer = Buffer.alloc(derSignature.length);
            derSignature.copy(newDer, 0, 0, offset - sLength);
            newSBuffer.copy(newDer, offset - sLength);
            derSignature.copy(newDer, offset, offset + sLength);
            
            return newDer;
        }
    } catch (error) {
        console.error('Error processing signature:', error);
        throw error;
    }
    
    return derSignature;
}

/**
 * Patches the JWT signing function to use low-s signatures
 * @param {Object} jwt - The JWT library instance
 */
export function patchJWTForLowS(jwt) {
    // Store the original sign function
    const originalSign = jwt.sign;
    
    // Create a new sign function that applies low-s mitigation
    jwt.sign = function(payload, key, options = {}) {
        if (options.algorithm && options.algorithm.startsWith('ES')) {
            // Create the header
            const header = {
                alg: options.algorithm,
                typ: 'JWT'
            };
            
            // Encode header and payload
            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            
            // Create the signing input
            const signingInput = `${encodedHeader}.${encodedPayload}`;
            
            // Create the signer
            const signer = createSign('SHA256');
            signer.update(signingInput);
            
            // Get the original signature in base64 format
            const signature = signer.sign(key, 'base64');
            
            // Convert base64 to buffer
            const signatureBuffer = Buffer.from(signature, 'base64');
            
            // Apply low-s mitigation to the DER signature
            const mitigatedSignature = applyLowSMitigation(signatureBuffer);
            
            // Construct the final JWT
            return `${signingInput}.${mitigatedSignature.toString('base64url')}`;
        }
        
        // For non-ECDSA algorithms, use the original sign function
        return originalSign.call(this, payload, key, options);
    };
} 