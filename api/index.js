require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const Ze = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Middleware
app.use(cors({ 
    origin: true, 
    credentials: true 
}));
app.use(express.json());
app.use(cookieParser());

// Initialize Supabase Client
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_KEY || '';
const supabase = (supabaseUrl && supabaseKey) ? createClient(supabaseUrl, supabaseKey, {
    auth: {
        persistSession: false,
        autoRefreshToken: false
    }
}) : null;

if (!supabase) {
    console.error('[CRITICAL] Supabase client could not be initialized. Check SUPABASE_URL and SUPABASE_KEY env vars.');
} else {
    console.log('[INFO] Supabase client initialized successfully.');
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function decryptPayload(payload, keyBase64) {
    try {
        const parts = payload.split(':');
        const iv = Buffer.from(parts[0], 'base64');
        const encrypted = parts[1];
        const key = Buffer.from(keyBase64, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encrypted, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    } catch (e) {
        console.error('[DECRYPT ERROR]', e.message);
        throw e;
    }
}

function encryptResponse(dataObj, keyBase64) {
    try {
        const iv = crypto.randomBytes(16);
        const key = Buffer.from(keyBase64, 'base64');
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(JSON.stringify(dataObj), 'utf8', 'base64');
        encrypted += cipher.final('base64');
        return { encrypted: true, payload: iv.toString('base64') + ':' + encrypted };
    } catch (e) {
        console.error('[ENCRYPT ERROR]', e.message);
        return { encrypted: false, ...dataObj };
    }
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

// Standard Session Init for Web
app.post('/api/session/init', Ze(async (req, res) => {
    const { fingerprint, action } = req.body;
    const sessionId = crypto.randomUUID();
    const key = crypto.randomBytes(32).toString('base64');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    if (!supabase) {
        console.warn('[SESSION] No Supabase client, using local session');
        return res.json({ session_id: sessionId, key: key, _local: true });
    }

    try {
        const { error } = await supabase.from('sessions').insert([{
            id: sessionId,
            key: key,
            fingerprint: fingerprint || 'unknown',
            action: action || 'login_page',
            expires_at: expiresAt.toISOString()
        }]);

        if (error) {
            console.error('[SESSION DB ERROR]', error.message);
            // Fallback to local session so the site doesn't break
            return res.json({ session_id: sessionId, key: key, _local: true, warning: 'db_error' });
        }
    } catch (err) {
        console.error('[SESSION FATAL ERROR]', err.message);
        return res.json({ session_id: sessionId, key: key, _local: true });
    }

    res.json({ session_id: sessionId, key: key });
}));

// Web Login (Encrypted)
app.post('/api/auth/login', Ze(async (req, res) => {
    const sessionId = req.headers['x-session-id'];
    const encryptedPayload = req.body.payload;

    if (!sessionId) return res.status(401).json({ error: 'Session ID missing' });

    // Fetch session
    let sessionKey = null;
    if (supabase) {
        const { data: session, error: sessionError } = await supabase
            .from('sessions')
            .select('key')
            .eq('id', sessionId)
            .gt('expires_at', new Date().toISOString())
            .maybeSingle();
        
        if (session) sessionKey = session.key;
    }

    if (!sessionKey) return res.status(401).json({ error: 'Session expired or invalid. Please reload.' });

    try {
        const { username, password } = decryptPayload(encryptedPayload, sessionKey);

        if (!username || !password) {
            return res.json(encryptResponse({ error: 'Username and password required' }, sessionKey));
        }

        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .maybeSingle();

        if (userError || !user) {
            return res.json(encryptResponse({ success: false, error: 'Invalid username or password' }, sessionKey));
        }

        const validPass = await bcrypt.compare(password, user.password_hash);
        if (!validPass) {
            return res.json(encryptResponse({ success: false, error: 'Invalid username or password' }, sessionKey));
        }

        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET || 'super_secret_jwt_key', { expiresIn: '24h' });
        
        res.json(encryptResponse({ 
            success: true, 
            user: { username: user.username, uid: user.uid }, 
            token 
        }, sessionKey));

    } catch (e) {
        console.error('[LOGIN ERROR]', e);
        res.status(400).json({ error: 'Security verification failed' });
    }
}));

/**
 * GAME MOD LOGIN ENDPOINT
 * This endpoint is designed for the game client (native) which might not
 * want to handle the complex AES-CBC session logic.
 */
app.post('/api/mod/login', Ze(async (req, res) => {
    const { username, password, hardware_id } = req.body;

    if (!username || !password) {
        return res.status(400).json({ status: 'error', message: 'Missing credentials' });
    }

    try {
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .maybeSingle();

        if (userError || !user) {
            return res.status(401).json({ status: 'error', message: 'Account not found' });
        }

        const validPass = await bcrypt.compare(password, user.password_hash);
        if (!validPass) {
            return res.status(401).json({ status: 'error', message: 'Incorrect password' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET || 'super_secret_jwt_key', { expiresIn: '7d' });

        console.log(`[MOD LOGIN] Success: ${username} (UID: ${user.uid})`);
        
        res.json({
            status: 'success',
            token: token,
            user: {
                username: user.username,
                uid: user.uid
            }
        });
    } catch (err) {
        console.error('[MOD LOGIN FATAL]', err);
        res.status(500).json({ status: 'error', message: 'Internal server error' });
    }
}));

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', supabase: !!supabase, time: new Date().toISOString() });
});

// Serve Static Files
app.use(express.static(path.join(__dirname, '..')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Error Handling
app.use((err, req, res, next) => {
    console.error('[FATAL]', err);
    res.status(500).json({ 
        error: 'Internal Server Error', 
        message: err.message 
    });
});

module.exports = app;
