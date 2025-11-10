const express = require('express');
const { requireAuth, requireRole } = require('../middleware/auth');
const User = require('../models/User');

const router = express.Router();

router.get('/me', requireAuth, async (req, res) => {
    const user = await User.findById(req.user.id).select('-passwordHash -refreshTokens');
    return res.json({ user });
});

// admin-only example
router.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
    res.json({ secret: 'admin area' });
});

module.exports = router;
