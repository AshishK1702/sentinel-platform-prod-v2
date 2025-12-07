require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const { Client } = require('pg');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 5000;;

app.use(cors());
app.use(express.json());

// Helper to format Date for MySQL (YYYY-MM-DD HH:mm:ss)
const toMySQLDate = (isoString) => {
    if (!isoString) return null;
    return new Date(isoString).toISOString().slice(0, 19).replace('T', ' ');
};

// --- 1. DATABASE CONNECTIVITY ENDPOINT ---
app.post('/api/connect-db', async (req, res) => {
    const { type, host, port, user, password, database, last_timestamp } = req.body;

    // Convert frontend ISO timestamp to MySQL format
    const formattedTimestamp = last_timestamp ? toMySQLDate(last_timestamp) : null;

    if (last_timestamp) {
        console.log(`📡 Polling for logs newer than: ${formattedTimestamp} (Original: ${last_timestamp})`);
    } else {
        console.log(`🚀 Initial Load: Fetching last 10,000 logs...`);
    }

    try {
        let results = [];
        let query = '';
        let params = [];

        if (formattedTimestamp) {
            // LIVE MODE: Fetch only new logs
            query = 'SELECT * FROM security_logs WHERE created_at > ? ORDER BY created_at ASC';
            params = [formattedTimestamp];
        } else {
            // INITIAL LOAD: Fetch logs DESCENDING then reverse
            query = 'SELECT * FROM security_logs ORDER BY created_at DESC LIMIT 10000';
        }
        
        if (type === 'mysql') {
            const connection = await mysql.createConnection({ 
                host, 
                port: parseInt(port) || 3306, 
                user, 
                password, 
                database,
                // Important: Treat dates as strings to prevent automatic timezone shifting
                dateStrings: true 
            });

            const [rows] = await connection.execute(query, params);
            results = rows;
            await connection.end();
        } 
        else if (type === 'postgresql') {
            const client = new Client({ host, port: parseInt(port) || 5432, user, password, database });
            await client.connect();
            
            const pgQuery = formattedTimestamp 
                ? 'SELECT * FROM security_logs WHERE created_at > $1 ORDER BY created_at ASC'
                : 'SELECT * FROM security_logs ORDER BY created_at DESC LIMIT 10000';
                
            const queryRes = await client.query(pgQuery, params);
            results = queryRes.rows;
            await client.end();
        }

        // Normalize data
        const logs = results.map(r => ({
            raw: r.message || JSON.stringify(r),
            // Ensure we return a valid ISO string to frontend
            timestamp: r.created_at ? new Date(r.created_at).toISOString() : new Date().toISOString(),
            source: `Live DB (${host})`
        }));

        // If initial load, reverse to chronological order
        if (!formattedTimestamp) {
            logs.reverse();
        }

        if (logs.length > 0) console.log(`✅ Found ${logs.length} new logs.`);
        
        res.json({ success: true, count: logs.length, logs });

    } catch (error) {
        console.error("❌ Database Error:", error.message);
        res.status(500).json({ 
            success: false, 
            message: error.message,
            hint: error.code === 'ER_NO_SUCH_TABLE' ? `Table 'security_logs' missing in '${database}'.` : "Check credentials."
        });
    }
});

// --- 2. AUTOMATION / FIREWALL ENDPOINT ---
app.post('/api/block-ip', (req, res) => {
    const { ip } = req.body;
    console.log("🔒 Blocking IP:", ip);

    if (!ip || !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) {
        return res.status(400).json({ message: "Invalid IP" });
    }

    exec(`echo "Blocked ${ip}"`, (error, stdout) => {
        if (error) return res.status(500).json({ success: false });
        res.json({ success: true, message: `IP ${ip} blocked.` });
    });
});

app.listen(PORT, () => {
    console.log(`Sentinel Live Server active on port ${PORT}`);
});