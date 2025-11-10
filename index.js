require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const authRoutes = require('./routes/auth');
const protectedRoutes = require('./routes/protected');

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: true, // restrict in production
    credentials: true
}));
app.use(rateLimit({ windowMs: 60 * 1000, max: 120 }));

app.use('/api/auth', authRoutes);
app.use('/api', protectedRoutes);

const PORT = process.env.PORT || 4000;
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Mongo connected');
        app.listen(PORT, () => console.log('Server listening', PORT));
    })
    .catch(err => { console.error(err); process.exit(1); });
