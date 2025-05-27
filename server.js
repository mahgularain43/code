import express from 'express';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import compression from 'compression';
import User from './models/user.js';

dotenv.config();
const app = express();

app.use(helmet()); // Apply security headers
app.use(compression()); // Compress all responses
app.use(cors({
    origin: 'http://localhost:5173', // Allow requests from your frontend
    credentials: true,
}));
app.use(bodyParser.json()); // Parse JSON bodies

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/userDatabase';

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Middleware to authenticate JWT tokens
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1]; // Expecting "Bearer TOKEN"

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden if token is invalid
        req.user = user;
        next();
    });
};

// Endpoint to register a new user
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body; // Only include these fields

    try {
      if (!username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({ username, email, password: hashedPassword });
      await newUser.save();

      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      console.error('Signup error:', error.stack); // Log the full error
      res.status(500).json({ message: 'Error registering user', error: error.message });
    }
});

// Endpoint for user login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        console.log(`Login attempt for email: ${email}`); // Debugging log

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            console.log('User not found');
            return res.status(404).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Invalid credentials');
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log('Login successful');
        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Example of a protected route
app.get('/api/protected', authenticateToken, (req, res) => {
    res.status(200).json({ message: "Access granted to protected data", user: req.user });
});

// Root endpoint
app.get('/', (req, res) => {
  res.send('Server is up and running');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
