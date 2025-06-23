import WebSocket from 'ws';
import fs from 'fs';

const FIREHOSE_URL = 'ws://localhost:3000/xrpc/com.atproto.sync.subscribeRepos';
const OUTPUT_FILE = 'firehose-msg.car';

let messageCount = 0;

console.log(`Connecting to firehose at ${FIREHOSE_URL}...`);
const ws = new WebSocket(FIREHOSE_URL);

ws.on('open', () => {
  console.log('Connected to firehose. Will ignore the first message (test), and save the next binary message...');
});

ws.on('message', (data, isBinary) => {
  messageCount++;
  if (messageCount === 1) {
    console.log('Ignored first message (test connection message).');
    return;
  }
  if (isBinary || Buffer.isBuffer(data)) {
    fs.writeFileSync(OUTPUT_FILE, data);
    console.log(`Saved binary firehose message to ${OUTPUT_FILE}`);
    ws.close();
    process.exit(0);
  } else {
    console.log('Received non-binary message (ignored):', data.toString());
  }
});

ws.on('close', () => {
  console.log('WebSocket connection closed.');
});

ws.on('error', (err) => {
  console.error('WebSocket error:', err);
}); 