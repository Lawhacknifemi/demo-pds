import { WebSocket } from 'ws';

const WS_URL = 'ws://localhost:31337/xrpc/com.atproto.sync.subscribeRepos';
const MAX_RETRIES = 5;
const RETRY_DELAY = 2000; // 2 seconds

let retryCount = 0;

function connect() {
    console.log(`Connecting to WebSocket server (attempt ${retryCount + 1}/${MAX_RETRIES})...`);
    const ws = new WebSocket(WS_URL);

    ws.on('open', () => {
        console.log('Connected to WebSocket server');
        retryCount = 0; // Reset retry count on successful connection
    });

    ws.on('message', (data) => {
        console.log('\nReceived firehose message:');
        try {
            const message = data.toString();
            console.log('Raw message:', message);
            // You can add more detailed parsing here if needed
        } catch (err) {
            console.error('Error parsing message:', err);
        }
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
    });

    ws.on('close', () => {
        console.log('WebSocket connection closed');
        
        // Attempt to reconnect if we haven't exceeded max retries
        if (retryCount < MAX_RETRIES) {
            retryCount++;
            console.log(`Retrying connection in ${RETRY_DELAY/1000} seconds...`);
            setTimeout(connect, RETRY_DELAY);
        } else {
            console.error('Max retry attempts reached. Please check if the server is running.');
            process.exit(1);
        }
    });

    return ws;
}

// Start the connection
let ws = connect();

// Keep the connection alive
process.on('SIGINT', () => {
    console.log('Closing WebSocket connection...');
    ws.close();
    process.exit(0);
});

console.log('Test client running. Press Ctrl+C to exit.'); 