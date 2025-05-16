import WebSocket from 'ws';
import config from './config.js';

const ws = new WebSocket(`ws://${config.PDS_SERVER}:10000/xrpc/com.atproto.sync.subscribeRepos`);

ws.on('open', () => {
    console.log('Connected to WebSocket');
});

ws.on('message', (data) => {
    console.log('Received message:', data.toString());
});

ws.on('error', (error) => {
    console.error('WebSocket error:', error);
});

ws.on('close', () => {
    console.log('Disconnected from WebSocket');
}); 