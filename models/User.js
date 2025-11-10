const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const refreshTokenSchema = new Schema({
    tokenHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true },
    ip: String,
    userAgent: String
});

const userSchema = new Schema({
    email: { type: String, required: true, unique: true, lowercase: true },
    passwordHash: { type: String, required: true },
    roles: { type: [String], default: ['user'] },
    refreshTokens: [refreshTokenSchema]
});

module.exports = mongoose.model('User', userSchema);
