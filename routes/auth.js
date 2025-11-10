const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const User = require('../models/User');
const { generateAccessToken, generateRefreshToken } = require('../utils/tokens');

const router = express.Router();

const SALT_ROUNDS = 12;
const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    domain: process.env.COOKIE_DOMAIN || undefined,
    path: '/api/auth/refresh'
};

// SIGNUP
router.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'User already exists' });

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const user = new User({ email, passwordHash });
    await user.save();
    return res.status(201).json({ message: 'User created' });
});

// LOGIN
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip;
    const ua = req.get('User-Agent') || '';

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const accessToken = generateAccessToken(user);
    const { token: refreshPlain, expiresAt } = generateRefreshToken(user);

    // store hashed refresh token
    const tokenHash = crypto.createHash('sha256').update(refreshPlain).digest('hex');
    user.refreshTokens.push({ tokenHash, expiresAt, ip, userAgent: ua });
    await user.save();

    res.cookie('refreshToken', refreshPlain, { ...COOKIE_OPTIONS, maxAge: expiresAt - Date.now() });
    return res.json({ accessToken });
});

// REFRESH
router.post('/refresh', async (req, res) => {
    const refreshPlain = req.cookies.refreshToken;
    if (!refreshPlain) return res.status(401).json({ error: 'No refresh token' });

    const tokenHash = crypto.createHash('sha256').update(refreshPlain).digest('hex');
    const user = await User.findOne({ 'refreshTokens.tokenHash': tokenHash });
    if (!user) {
        // possible reuse/replay — require login
        return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // find token doc
    const tokenDoc = user.refreshTokens.find(t => t.tokenHash === tokenHash);
    if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
        // remove expired token
        user.refreshTokens = user.refreshTokens.filter(t => t.tokenHash !== tokenHash);
        await user.save();
        return res.status(401).json({ error: 'Expired refresh token' });
    }

    // rotate: remove used refresh token and issue a fresh one
    user.refreshTokens = user.refreshTokens.filter(t => t.tokenHash !== tokenHash);

    const { token: newRefreshPlain, expiresAt } = generateRefreshToken(user);
    const newTokenHash = crypto.createHash('sha256').update(newRefreshPlain).digest('hex');
    user.refreshTokens.push({ tokenHash: newTokenHash, expiresAt, ip: req.ip, userAgent: req.get('User-Agent') });

    await user.save();

    const accessToken = generateAccessToken(user);
    res.cookie('refreshToken', newRefreshPlain, { ...COOKIE_OPTIONS, maxAge: expiresAt - Date.now() });
    return res.json({ accessToken });
});

// LOGOUT
router.post('/logout', async (req, res) => {
    const refreshPlain = req.cookies.refreshToken;
    if (refreshPlain) {
        const tokenHash = crypto.createHash('sha256').update(refreshPlain).digest('hex');
        await User.updateOne({}, { $pull: { refreshTokens: { tokenHash } } }); // in prod, tie to user
    }
    res.clearCookie('refreshToken', { path: '/api/auth/refresh' });
    return res.json({ message: 'Logged out' });
});

module.exports = router;
