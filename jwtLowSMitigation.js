// Compatible JWT Low-S Signature Patch (matching Python implementation)
import jwt from 'jsonwebtoken'; // or your preferred JWT library

// Constants for curve orders (matching Python's format)
const CURVE_ORDER = {
  'secp256r1': BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'),
  'prime256v1': BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'), // Same as secp256r1
  'secp256k1': BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141')
};

/**
 * Decodes a DER signature to extract r and s values
 * @param {Buffer} derSig - The DER-encoded signature
 * @returns {Object} - Object containing r and s as BigInts
 */
function decodeDssSignature(derSig) {
  let offset = 0;
  
  // Verify the sequence tag
  if (derSig[offset++] !== 0x30) throw new Error('Invalid DER signature: not a sequence');
  
  // Get sequence length (skip)
  const seqLength = derSig[offset++];
  
  // Parse r
  if (derSig[offset++] !== 0x02) throw new Error('Invalid DER signature: r value not an integer');
  const rLength = derSig[offset++];
  const rValue = derSig.slice(offset, offset + rLength);
  offset += rLength;
  
  // Parse s
  if (derSig[offset++] !== 0x02) throw new Error('Invalid DER signature: s value not an integer');
  const sLength = derSig[offset++];
  const sValue = derSig.slice(offset, offset + sLength);
  
  // Convert to BigInt
  const r = bufferToBigInt(rValue);
  const s = bufferToBigInt(sValue);
  
  return { r, s };
}

/**
 * Encodes r and s values into a DER signature
 * @param {BigInt} r - The r value
 * @param {BigInt} s - The s value
 * @returns {Buffer} - The DER-encoded signature
 */
function encodeDssSignature(r, s) {
  // Convert to Buffers
  const rBuf = bigIntToBuffer(r);
  const sBuf = bigIntToBuffer(s);
  
  // Prepare r buffer (ensure positive integer format)
  const rPositive = (rBuf[0] & 0x80) ? Buffer.concat([Buffer.from([0]), rBuf]) : rBuf;
  const sPositive = (sBuf[0] & 0x80) ? Buffer.concat([Buffer.from([0]), sBuf]) : sBuf;
  
  // Calculate lengths
  const rLength = rPositive.length;
  const sLength = sPositive.length;
  const sequenceLength = 2 + rLength + 2 + sLength;
  
  // Create the DER signature
  const derSignature = Buffer.alloc(2 + sequenceLength);
  let offset = 0;
  
  // Sequence tag and length
  derSignature[offset++] = 0x30;
  derSignature[offset++] = sequenceLength;
  
  // r value
  derSignature[offset++] = 0x02;
  derSignature[offset++] = rLength;
  rPositive.copy(derSignature, offset);
  offset += rLength;
  
  // s value
  derSignature[offset++] = 0x02;
  derSignature[offset++] = sLength;
  sPositive.copy(derSignature, offset);
  
  return derSignature;
}

/**
 * Convert Buffer to BigInt
 * @param {Buffer} buf - Buffer to convert
 * @returns {BigInt} - The resulting BigInt
 */
function bufferToBigInt(buf) {
  return BigInt('0x' + buf.toString('hex'));
}

/**
 * Convert BigInt to Buffer with minimal representation
 * @param {BigInt} num - BigInt to convert
 * @returns {Buffer} - The resulting Buffer
 */
function bigIntToBuffer(num) {
  // Convert to hex and remove '0x' prefix
  let hex = num.toString(16);
  // Ensure even length
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

/**
 * Apply low-S mitigation to a signature
 * Direct equivalent of the Python apply_low_s_mitigation function
 * @param {Buffer} signature - The DER signature
 * @param {string} curve - Curve name (secp256r1, secp256k1, etc.)
 * @returns {Buffer} - Mitigated DER signature
 */
function applyLowSMitigation(signature, curve) {
  // Get the curve order
  const curveName = typeof curve === 'string' ? curve : 'secp256r1';
  const n = CURVE_ORDER[curveName];
  
  if (!n) {
    throw new Error(`Unsupported curve: ${curveName}`);
  }
  
  // Decode the signature to get r and s
  const { r, s } = decodeDssSignature(signature);
  
  // Apply low-S mitigation: if s > n/2, replace with n-s
  if (s > n / 2n) {
    const newS = n - s;
    return encodeDssSignature(r, newS);
  }
  
  return signature;
}

/**
 * Patch the JWT library to use low-S signatures
 * @param {Object} jwtLib - The JWT library to patch
 */
export function patchJWT(jwtLib = jwt) {
  // Store reference to original sign function
  const originalSign = jwtLib.sign;
  
  // Replace sign function for ECDSA algorithms
  jwtLib.sign = function(payload, key, options, callback) {
    // Handle callback style
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    options = options || {};
    
    // Non-ECDSA algorithms pass through unchanged
    if (!options.algorithm || !options.algorithm.startsWith('ES')) {
      return originalSign.call(this, payload, key, options, callback);
    }
    
    // Get curve name based on algorithm
    let curveName;
    switch (options.algorithm) {
      case 'ES256':
        curveName = 'secp256r1'; 
        break;
      case 'ES256K':
        curveName = 'secp256k1';
        break;
      // Add more curve mappings as needed
      default:
        curveName = 'secp256r1'; // Default
    }
    
    try {
      // Call original sign function
      const token = originalSign.call(this, payload, key, options);
      
      // Parse the token
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }
      
      // Extract and decode the signature
      const signatureBase64 = parts[2];
      const signature = Buffer.from(signatureBase64, 'base64url');
      
      // Apply low-S mitigation
      const mitigatedSignature = applyLowSMitigation(signature, curveName);
      
      // Replace the signature in the token
      const mitigatedSignatureBase64 = mitigatedSignature.toString('base64url');
      const mitigatedToken = `${parts[0]}.${parts[1]}.${mitigatedSignatureBase64}`;
      
      if (callback) {
        callback(null, mitigatedToken);
        return;
      }
      return mitigatedToken;
    } catch (error) {
      if (callback) {
        callback(error);
        return;
      }
      throw error;
    }
  };
  
  return jwtLib;
}

// Usage example:
// import jwt from 'jsonwebtoken';
// patchJWT(jwt);
// const token = jwt.sign({data: 'example'}, privateKey, { algorithm: 'ES256' });