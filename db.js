export async function initDb() {
    const db = await open({
        filename: 'pds.db',
        driver: sqlite3.Database
    });

    // Create tables
    await db.exec(`
        CREATE TABLE IF NOT EXISTS records (
            uri TEXT PRIMARY KEY,
            cid TEXT NOT NULL,
            commit TEXT NOT NULL,
            rev INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS blocks (
            cid TEXT PRIMARY KEY,
            data BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS commits (
            did TEXT NOT NULL,
            cid TEXT NOT NULL,
            rev INTEGER NOT NULL,
            PRIMARY KEY (did, rev)
        );

        CREATE TABLE IF NOT EXISTS repos (
            did TEXT PRIMARY KEY,
            root TEXT NOT NULL,
            rev INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS updates (
            hostname TEXT PRIMARY KEY,
            last_update INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_records_cid ON records(cid);
        CREATE INDEX IF NOT EXISTS idx_records_commit ON records(commit);
        CREATE INDEX IF NOT EXISTS idx_records_rev ON records(rev);
        CREATE INDEX IF NOT EXISTS idx_commits_did ON commits(did);
        CREATE INDEX IF NOT EXISTS idx_commits_rev ON commits(rev);
    `);

    return db;
} 