const jwt = require('jsonwebtoken');

const requireAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization format' });

    const token = parts[1];
    try {
        const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = { id: payload.sub, roles: payload.roles };
        return next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

const requireRole = (role) => (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (!req.user.roles || !req.user.roles.includes(role)) return res.status(403).json({ error: 'Forbidden' });
    return next();
};

module.exports = { requireAuth, requireRole };
