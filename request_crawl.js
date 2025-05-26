import jwt from 'jsonwebtoken';
import { readFile } from 'fs/promises';
import config from './config.js';
import { logger } from './logger.js';
import fetch from 'node-fetch';

async function requestCrawl() {
    try {
        logger.info('Requesting crawl from BGS server...');
        const privkey = await readFile('privkey.pem');
        const now = Math.floor(Date.now() / 1000);
        
        const auth = jwt.sign({
            iss: config.DID_PLC,
            aud: `did:web:${config.BGS_SERVER}`,
            exp: now + 60 * 60 // 1h
        }, privkey, { algorithm: 'ES256K' });

        const response = await fetch(
            `https://${config.BGS_SERVER}/xrpc/com.atproto.sync.requestCrawl`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth}`
                },
                body: JSON.stringify({ hostname: config.PDS_SERVER })
            }
        );

        if (!response.ok) {
            throw new Error(`Failed to request crawl: ${response.statusText}`);
        }

        logger.info('Successfully requested crawl from BGS server');
    } catch (error) {
        logger.error('Error requesting crawl:', error);
        process.exit(1);
    }
}

requestCrawl(); 