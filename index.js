const express = require('express');       // load express module
const nedb = require("nedb-promises");    // load nedb module
const bcrypt = require('bcrypt');         // load bcrypt for password hashing
const crypto = require('crypto');         // load crypto for generating auth tokens
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();                    // init app
const db = nedb.create('users.jsonl');    // init db
const port = 3000;

app.use(express.static('public'));        // enable static routing to "./public" folder
app.use(express.json());                  // parse JSON request bodies

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per windowMs
    message: 'Too many authentication attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false
});

// Email validation regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Helper function to generate authentication token
function generateAuthToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Helper function to sanitize user object (remove sensitive data)
function sanitizeUser(user) {
    if (!user) return null;
    const sanitized = { ...user };
    delete sanitized.password;
    delete sanitized.passwordHash;
    return sanitized;
}

// Get all users (without sensitive data)
app.get('/users', async (req, res) => {
    try {
        const users = await db.find({});
        res.send(users.map(sanitizeUser));
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

// Register new user
app.post('/users', async (req, res) => {
    try {
        const { username, password, email, name } = req.body;
        
        // Validate required fields
        if (!username || !password || !email || !name) {
            return res.status(400).send({ error: 'Missing required fields.' });
        }

        // Validate email format
        if (!emailRegex.test(email)) {
            return res.status(400).send({ error: 'Invalid email format.' });
        }

        // Check if username already exists
        const existingUser = await db.findOne({ username });
        if (existingUser) {
            return res.status(400).send({ error: 'Username already exists.' });
        }

        // Check if email already exists
        const existingEmail = await db.findOne({ email });
        if (existingEmail) {
            return res.status(400).send({ error: 'Email already registered.' });
        }

        // Hash password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        // Generate auth token
        const authenticationToken = generateAuthToken();

        // Create new user
        const newUser = {
            username,
            passwordHash,
            email,
            name,
            authenticationToken,
            createdAt: new Date()
        };

        const insertedUser = await db.insert(newUser);
        res.status(201).send(sanitizeUser(insertedUser));
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).send({ error: 'Internal server error.' });
    }
});

// Authenticate user
app.post('/users/auth', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).send({ error: 'Username and password are required.' });
        }

        const user = await db.findOne({ username });
        if (!user) {
            return res.status(401).send({ error: 'Invalid username or password.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.passwordHash);
        if (!passwordMatch) {
            return res.status(401).send({ error: 'Invalid username or password.' });
        }

        // Generate new auth token
        const authenticationToken = generateAuthToken();
        await db.update(
            { username },
            { $set: { authenticationToken } }
        );

        const updatedUser = await db.findOne({ username });
        res.send(sanitizeUser({ ...updatedUser, authenticationToken }));
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

// Update user profile
app.patch('/users/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const { authenticationToken, ...updates } = req.body;

        const user = await db.findOne({ username, authenticationToken });
        if (!user) {
            return res.status(401).send({ error: 'Invalid authentication.' });
        }

        // Don't allow updating password through this route
        delete updates.password;
        delete updates.passwordHash;
        delete updates.username;  // Don't allow username changes

        const numUpdated = await db.update(
            { username, authenticationToken },
            { $set: updates }
        );

        if (numUpdated === 0) {
            return res.status(400).send({ error: 'Failed to update user.' });
        }

        res.send({ ok: true });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

// Delete user
app.delete('/users/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const { authenticationToken } = req.body;

        const user = await db.findOne({ username, authenticationToken });
        if (!user) {
            return res.status(401).send({ error: 'Invalid authentication.' });
        }

        const numRemoved = await db.remove({ username, authenticationToken });
        if (numRemoved === 0) {
            return res.status(400).send({ error: 'Failed to delete user.' });
        }

        res.send({ ok: true });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

// Logout user
app.post('/users/:username/logout', async (req, res) => {
    try {
        const { username } = req.params;
        const { authenticationToken } = req.body;

        const user = await db.findOne({ username, authenticationToken });
        if (!user) {
            return res.status(401).send({ error: 'Invalid authentication.' });
        }

        await db.update(
            { username },
            { $set: { authenticationToken: null } }
        );

        res.send({ ok: true });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

// Validate email format
function validateEmail(email) {
    return emailRegex.test(email);
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication token required' });
    }

    // Verify the token exists in the database
    db.findOne({ authenticationToken: token })
        .then(user => {
            if (!user) {
                return res.status(403).json({ error: 'Invalid or expired token' });
            }
            req.user = user;
            next();
        })
        .catch(err => {
            res.status(500).json({ error: 'Internal server error' });
        });
}

// API Routes
app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const existingUser = await db.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = {
            email,
            password: hashedPassword,
            createdAt: new Date()
        };

        await db.insert(user);
        const token = jwt.sign({ email }, JWT_SECRET);
        res.status(201).json({ token });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = await db.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ email }, JWT_SECRET);
        res.json({ token });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { newPassword } = req.body;
        const { email } = req.user;

        const updateData = {};
        if (newPassword) {
            updateData.password = await bcrypt.hash(newPassword, 10);
        }

        const numUpdated = await db.update(
            { email },
            { $set: updateData }
        );

        if (numUpdated === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'Profile updated successfully' });
    } catch (err) {
        console.error('Profile update error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { email } = req.user;
        const numRemoved = await db.remove({ email });

        if (numRemoved === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'Account deleted successfully' });
    } catch (err) {
        console.error('Account deletion error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const users = await db.find({}, { password: 0 });
        res.json(users);
    } catch (err) {
        console.error('User list error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Default route - must be last
app.all('*', (req, res) => {
    res.status(404).json({ error: 'Invalid URL' });
});

// start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
