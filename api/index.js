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

// Helpers
function decryptPayload(payload, keyBase64) {
    const parts = payload.split(':');
    const iv = Buffer.from(parts[0], 'base64');
    const encrypted = parts[1];
    const key = Buffer.from(keyBase64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}

function encryptResponse(dataObj, keyBase64) {
    const iv = crypto.randomBytes(16);
    const key = Buffer.from(keyBase64, 'base64');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(JSON.stringify(dataObj), 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return { encrypted: true, payload: iv.toString('base64') + ':' + encrypted };
}

// API Routes
app.post('/api/session/init', Ze(async (req, res) => {
    if (!supabase) {
        return res.status(500).json({ error: 'Database connection not configured' });
    }
    
    const { fingerprint, action } = req.body;
    const sessionId = crypto.randomUUID();
    const key = crypto.randomBytes(32).toString('base64');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes (user requested)

    const { error } = await supabase.from('sessions').insert([{
        id: sessionId,
        key: key,
        fingerprint: fingerprint || 'unknown',
        action: action || 'login_page',
        expires_at: expiresAt.toISOString()
    }]);

    if (error) {
        console.error('[SESSION ERROR]', error);
        return res.status(500).json({ 
            error: 'Database error', 
            message: error.message,
            code: error.code,
            details: error.details
        });
    }

    res.json({ session_id: sessionId, key: key });
}));

app.post('/api/auth/login', Ze(async (req, res) => {
    if (!supabase) return res.status(500).json({ error: 'Database not available' });
    
    const sessionId = req.headers['x-session-id'];
    const { payload: encryptedPayload } = req.body;

    if (!sessionId) return res.status(401).json({ error: 'Session ID required' });

    const { data: session, error: sessionError } = await supabase
        .from('sessions')
        .select('*')
        .eq('id', sessionId)
        .gt('expires_at', new Date().toISOString())
        .single();

    if (sessionError || !session) {
        return res.status(401).json({ error: 'Invalid or expired session' });
    }

    let data;
    try {
        data = decryptPayload(encryptedPayload, session.key);
    } catch (e) {
        return res.status(400).json({ error: 'Security failure' });
    }

    const { username, password } = data;

    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username)
        .maybeSingle();

    if (error || !user) {
        return res.status(401).json(encryptResponse({ error: 'Invalid credentials' }, session.key));
    }

    const validPass = await bcrypt.compare(password, user.password_hash);
    if (!validPass) {
        return res.status(401).json(encryptResponse({ error: 'Invalid credentials' }, session.key));
    }

    const token = jwt.sign(
        { id: user.id, username: user.username, uid: user.uid },
        process.env.JWT_SECRET || 'super_secret_jwt_key',
        { expiresIn: '24h' }
    );

    // Set Cookie
    res.cookie('auth_token', token, {
        httpOnly: true,
        secure: true, 
        sameSite: 'None', 
        maxAge: 24 * 60 * 60 * 1000,
        path: '/'
    });

    // Delete session after use
    await supabase.from('sessions').delete().eq('id', sessionId);

    res.json(encryptResponse({ success: true, user: { username: user.username, uid: user.uid }, token }, session.key));
}));

// Serve Static Files
app.use(express.static(path.join(__dirname, '..')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Error Handling
app.use((err, req, res, next) => {
    console.error('[LOGIN API ERROR]', err);
    res.status(500).json({ 
        error: 'Internal Server Error', 
        message: err.message 
    });
});

module.exports = app;

