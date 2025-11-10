const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const generateAccessToken = (user) => {
    const payload = { sub: user._id.toString(), roles: user.roles };
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRES || '15m' });
};

const generateRefreshToken = (user) => {
    // create a random string token (not JWT) — we'll store hashed version server-side
    const token = crypto.randomBytes(64).toString('hex');
    const expiresIn = process.env.REFRESH_TOKEN_EXPIRES || '30d';
    const expiresAt = new Date(Date.now() + msFromString(expiresIn));
    return { token, expiresAt };
};

const msFromString = (s) => {
    // basic parser: '15m','30d' (expand if needed)
    if (s.endsWith('m')) return parseInt(s) * 60 * 1000;
    if (s.endsWith('h')) return parseInt(s) * 60 * 60 * 1000;
    if (s.endsWith('d')) return parseInt(s) * 24 * 60 * 60 * 1000;
    return parseInt(s);
};

module.exports = { generateAccessToken, generateRefreshToken };
