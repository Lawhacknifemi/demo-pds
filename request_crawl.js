import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import * as secp from '@noble/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import base64url from 'base64url';
import config from './config.js';
import { logger } from './logger.js';

// Enable sync signing
secp.etc.hmacSha256Sync = (key, ...messages) =>
  hmac(sha256, key, secp.etc.concatBytes(...messages));

function base64urlEncode(obj) {
  return base64url.encode(Buffer.from(JSON.stringify(obj)));
}

function extractPrivateKeyFromPEM(pemData) {
  const pemContent = pemData
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace('-----BEGIN EC PRIVATE KEY-----', '')
    .replace('-----END EC PRIVATE KEY-----', '')
    .replace(/\s/g, '');

  const derBuffer = Buffer.from(pemContent, 'base64');

  if (derBuffer.length >= 32) {
    return derBuffer.slice(-32);
  }

  throw new Error('Could not extract private key from PEM format');
}

async function requestCrawl() {
  try {
    const pemData = readFileSync('privkey.pem', 'utf8');
    const privKeyBytes = extractPrivateKeyFromPEM(pemData);

    const now = Math.floor(Date.now() / 1000);

    const header = { alg: 'ES256K', typ: 'JWT' };
    const payload = {
      iss: config.DID_PLC,
      aud: `did:web:${config.BGS_SERVER}`,
      exp: now + 60 * 60,
    };

    const encodedHeader = base64urlEncode(header);
    const encodedPayload = base64urlEncode(payload);
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const msgHash = createHash('sha256').update(signingInput).digest();
    const signature = secp.sign(msgHash, privKeyBytes);
    const signatureBytes = signature.toCompactRawBytes();
    const signatureB64Url = base64url.encode(signatureBytes);


    const jwt = `${signingInput}.${signatureB64Url}`;

    const response = await fetch(
      `https://${config.BGS_SERVER}/xrpc/com.atproto.sync.requestCrawl`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({ hostname: config.PDS_SERVER }),
      }
    );

    const responseText = await response.text();

    console.log(response.ok, response.status);
    console.log(responseText);

    if (!response.ok) {
      throw new Error(
        `Request failed: ${response.status} ${response.statusText}\nResponse: ${responseText}`
      );
    }

    logger.info('Successfully requested crawl from BGS server!');
  } catch (error) {
    logger.error('Failed to request crawl:', {
      message: error.message,
      stack: error.stack,
    });
    process.exit(1);
  }
}

requestCrawl();
