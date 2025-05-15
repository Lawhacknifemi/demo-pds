import fetch from 'node-fetch';

const PDS_URL = 'http://localhost:31337';

async function createSession() {
    console.log('Creating session...');
    const response = await fetch(`${PDS_URL}/xrpc/com.atproto.server.createSession`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            identifier: 'test.bsky.social',
            password: 'test123'
        })
    });
    
    const data = await response.json();
    console.log('Session created:', data);
    return data.accessJwt;
}

async function createPost(jwt) {
    console.log('\nCreating test post...');
    const response = await fetch(`${PDS_URL}/xrpc/com.atproto.repo.createRecord`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${jwt}`
        },
        body: JSON.stringify({
            repo: 'did:plc:test',
            collection: 'app.bsky.feed.post',
            record: {
                $type: 'app.bsky.feed.post',
                text: 'Test post for WebSocket verification',
                createdAt: new Date().toISOString()
            }
        })
    });
    
    const data = await response.json();
    console.log('Post created:', data);
    return data;
}

async function main() {
    try {
        const jwt = await createSession();
        await createPost(jwt);
        console.log('\nTest post created. Check the WebSocket client for the firehose message.');
    } catch (err) {
        console.error('Error:', err);
    }
}

main(); 