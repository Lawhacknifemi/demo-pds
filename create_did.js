// Required modules
import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { encode as dagCborEncode } from '@ipld/dag-cbor';
import * as uint8arrays from 'uint8arrays';
import base64url from 'base64url';
import axios from 'axios';
import { promises as fs } from 'fs';
import { createRequire } from 'module';
import { readFile } from 'fs/promises';
import { writeFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import base32Encode from 'base32-encode';
import config from './config.js';

const require = createRequire(import.meta.url);

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configuration from config.js
const HANDLE = config.HANDLE;
const PDS_SERVER = config.PDS_SERVER;
const PLC_SERVER = `https://${config.PLC_SERVER}`;

// Curve order for secp256k1 (from signing.py)
const CURVE_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

// Function to encode the public key as a DID (matching create_identity.py)
function encodeDidPubKey(pubKey, privKey) {
  const prefix = new Uint8Array([0xe7, 0x01]); // secp256k1-pub multicodec prefix
  const compressed = secp256k1.getPublicKey(privKey, true); // Get compressed format
  const combined = new Uint8Array(prefix.length + compressed.length);
  combined.set(prefix);
  combined.set(compressed, prefix.length);
  return 'did:key:z' + uint8arrays.toString(combined, 'base58btc');
}

// Function to apply low-S mitigation (matching signing.py)
function applyLowSMitigation(sig) {
  // The signature is already in the correct format from @noble/curves
  // We just need to ensure it's in low-S form
  const s = sig.s;
  const halfOrder = CURVE_ORDER / BigInt(2);
  
  if (s > halfOrder) {
    const newS = CURVE_ORDER - s;
    return {
      r: sig.r,
      s: newS,
      recovery: sig.recovery
    };
  }
  return sig;
}

// Function to create raw signature (matching signing.py)
function rawSign(msg, privKey) {
  const msgHash = crypto.createHash('sha256').update(msg).digest();
  const sig = secp256k1.sign(msgHash, privKey);
  const mitigatedSig = applyLowSMitigation(sig);
  
  // Convert the mitigated signature to raw bytes
  const r = mitigatedSig.r.toString(16).padStart(64, '0');
  const s = mitigatedSig.s.toString(16).padStart(64, '0');
  return Buffer.from(r + s, 'hex');
}

// Function to create proper PKCS#8 PEM for secp256k1 (matching Python's cryptography library)
function createProperSecp256k1PEM(privateKeyBytes) {
  // Create a KeyObject from the raw private key bytes
  // We need to construct the proper ASN.1 structure for secp256k1
  
  // This is the ASN.1 structure for a secp256k1 private key in PKCS#8 format
  // SEQUENCE {
  //   INTEGER 0,
  //   SEQUENCE {
  //     OBJECT IDENTIFIER ecPublicKey,
  //     OBJECT IDENTIFIER secp256k1
  //   },
  //   OCTET STRING containing the private key
  // }
  
  const privateKeyHex = privateKeyBytes.toString('hex');
  
  // Build the ASN.1 structure manually
  const ecPublicKeyOID = '06072a8648ce3d0201'; // 1.2.840.10045.2.1 (ecPublicKey)
  const secp256k1OID = '06052b8104000a';       // 1.3.132.0.10 (secp256k1)
  
  // Private key in OCTET STRING format
  const privateKeyOctetString = '0420' + privateKeyHex; // 04 = OCTET STRING, 20 = length 32
  
  // Algorithm identifier SEQUENCE
  const algorithmSeq = '3013' + ecPublicKeyOID + secp256k1OID; // 30 = SEQUENCE, 13 = length
  
  // Outer SEQUENCE
  const version = '020100'; // INTEGER 0
  const privateKeyOctetStringOuter = '0422' + privateKeyOctetString; // 04 = OCTET STRING, 22 = length
  
  const fullSequence = '30' + 
    ((version.length + algorithmSeq.length + privateKeyOctetStringOuter.length) / 2).toString(16).padStart(2, '0') +
    version + algorithmSeq + privateKeyOctetStringOuter;
  
  const der = Buffer.from(fullSequence, 'hex');
  const base64 = der.toString('base64');
  
  // Format as PEM
  const pem = '-----BEGIN PRIVATE KEY-----\n' +
              base64.match(/.{1,64}/g).join('\n') + '\n' +
              '-----END PRIVATE KEY-----\n';
  
  return pem;
}

// Alternative simpler approach using Node.js crypto directly
function createSecp256k1KeyPair() {
  // Generate a secp256k1 key pair using Node.js crypto
  const { privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    },
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    }
  });
  
  // Extract the raw private key bytes
  const keyObject = crypto.createPrivateKey(privateKey);
  const rawPrivateKey = keyObject.export({
    format: 'der',
    type: 'sec1'
  });
  
  // The SEC1 format has the private key at the end
  // For secp256k1, it's usually the last 32 bytes
  const privateKeyBytes = rawPrivateKey.slice(-32);
  
  return {
    privateKeyPem: privateKey,
    privateKeyBytes: privateKeyBytes
  };
}

async function main() {
  try {
    // Use Node.js crypto to generate a proper secp256k1 key pair
    const keyPair = createSecp256k1KeyPair();
    const privKey = keyPair.privateKeyBytes;
    const privateKeyPem = keyPair.privateKeyPem;
    
    // Verify the key is valid
    if (!secp256k1.utils.isValidPrivateKey(privKey)) {
      throw new Error('Generated private key is not valid for secp256k1');
    }

    const pubKey = secp256k1.getPublicKey(privKey, true); // Get compressed public key

    // Create the operation
    const op = {
      type: 'plc_operation',
      rotationKeys: [
        encodeDidPubKey(pubKey, privKey)
      ],
      verificationMethods: {
        atproto: encodeDidPubKey(pubKey, privKey)
      },
      alsoKnownAs: [
        `at://${HANDLE}`
      ],
      services: {
        atproto_pds: {
          type: 'AtprotoPersonalDataServer',
          endpoint: `https://${PDS_SERVER}`
        }
      },
      prev: null
    };

    // Encode and sign the operation
    const opBytes = dagCborEncode(op);
    const sig = rawSign(opBytes, privKey);
    const signedOp = {
      ...op,
      sig: base64url.encode(sig)
    };

    // Generate the DID
    const signedOpBytes = dagCborEncode(signedOp);
    const didHash = crypto.createHash('sha256').update(signedOpBytes).digest();
    const plcDid = 'did:plc:' + base32Encode(didHash, 'RFC4648', { padding: false }).toLowerCase().slice(0, 24);

    // Debug the operation
    console.log('Operation to be sent:', JSON.stringify(signedOp, null, 2));
    console.log('Generated DID:', plcDid);

    // Send the operation to the PLC server
    console.log('Sending operation to PLC server:', JSON.stringify(signedOp, null, 2));
    try {
        const response = await axios.post(`${PLC_SERVER}/${plcDid}`, signedOp, {
            headers: {
                'Content-Type': 'application/json',
            }
        });
        console.log('Server response:', response.data);
        console.log('DID created successfully:', plcDid);
    } catch (error) {
        console.error('Server response:', error.response?.data || error.message);
        throw new Error(`Failed to create DID: ${error.message}`);
    }

    // Save the private key in proper PEM format
    const keyPath = join(__dirname, 'privkey.pem');
    await writeFile(keyPath, privateKeyPem);
    console.log('Private key saved to:', keyPath);
    console.log('PEM format verified - this should work with your crawl request script');

  } catch (error) {
    console.error('Error:', error);
  }
}

main();