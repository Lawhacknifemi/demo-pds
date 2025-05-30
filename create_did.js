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
import forge from 'node-forge';
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

// Function to convert raw private key to PEM format
function privateKeyToPEM(privateKey) {
    // Create a new key pair using node-forge
    const keypair = forge.pki.ed25519.generateKeyPair();
    
    // Convert the private key to ASN.1 format
    const asn1 = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, forge.util.hexToBytes('00')),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.10045.2.1').getBytes()),
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.10045.3.1.7').getBytes())
        ]),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, forge.util.hexToBytes('04' + privateKey.toString('hex')))
    ]);

    // Convert to PEM format
    const der = forge.asn1.toDer(asn1).getBytes();
    const base64 = forge.util.encode64(der);
    const pem = '-----BEGIN PRIVATE KEY-----\n' +
                base64.match(/.{1,64}/g).join('\n') + '\n' +
                '-----END PRIVATE KEY-----\n';

    return pem;
}

async function main() {
  try {
    // Generate a new key pair
    let privKey;
    do {
      privKey = crypto.randomBytes(32);
    } while (!secp256k1.utils.isValidPrivateKey(privKey));

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

    // Save the private key in PEM format
    const keyPath = join(__dirname, 'privkey.pem');
    const pemKey = privateKeyToPEM(privKey);
    await writeFile(keyPath, pemKey);
    console.log('Private key saved to:', keyPath);

  } catch (error) {
    console.error('Error:', error);
  }
}

main();