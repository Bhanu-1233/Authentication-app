// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
// CORS Configuration - Production
const allowedOrigins = [
  'http://localhost:3000', 
  'http://localhost:3001', 
  'http://127.0.0.1:3000',
  'https://fullstack-login-logout-flow.netlify.app' // Your Netlify frontend URL
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin); // Debugging
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Session configuration for production
app.use(session({
  secret: process.env.SESSION_SECRET || 'someSuperSecretValue',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,           // HTTPS required
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'none'        // Required for cross-site cookies
  }
}));

// Initialize SQLite database
const dbPath = process.env.DATABASE_PATH || './auth.db';
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database at:', dbPath);
    // Create users table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) {
        console.error('Error creating users table:', err);
      } else {
        console.log('Users table ready');
      }
    });
  }
});

// Helper function to validate email
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Test endpoint to check if server is running
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Backend server is running!', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Register endpoint
app.post('/api/register', async (req, res) => {
  console.log('Register request received:', req.body);
  
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      console.log('Missing email or password');
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (!isValidEmail(email)) {
      console.log('Invalid email format:', email);
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (password.length < 6) {
      console.log('Password too short');
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    // Check if user already exists
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Database error during user lookup:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (user) {
        console.log('User already exists:', email);
        return res.status(400).json({ error: 'User already exists with this email' });
      }

      try {
        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        console.log('Password hashed successfully');

        // Insert new user
        db.run('INSERT INTO users (email, password) VALUES (?, ?)', 
          [email, hashedPassword], 
          function(err) {
            if (err) {
              console.error('Database error during user creation:', err);
              return res.status(500).json({ error: 'Failed to create user' });
            }
            
            console.log('User created successfully:', email, 'ID:', this.lastID);
            res.status(201).json({ 
              message: 'User registered successfully',
              userId: this.lastID 
            });
          }
        );
      } catch (hashError) {
        console.error('Password hashing error:', hashError);
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/login', (req, res) => {
  console.log('Login request received:', req.body);
  
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      console.log('Missing email or password');
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user in database
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Database error during login:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (!user) {
        console.log('User not found:', email);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      try {
        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
          console.log('Invalid password for user:', email);
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Create session
        req.session.userId = user.id;
        req.session.email = user.email;

        console.log('User logged in successfully:', email);
        res.json({ 
          message: 'Login successful',
          user: {
            id: user.id,
            email: user.email
          }
        });
      } catch (compareError) {
        console.error('Password comparison error:', compareError);
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Check authentication status
app.get('/api/me', (req, res) => {
  console.log('Auth check request, session:', req.session);
  
  if (req.session.userId) {
    db.get('SELECT id, email FROM users WHERE id = ?', [req.session.userId], (err, user) => {
      if (err) {
        console.error('Database error during auth check:', err);
        return res.status(401).json({ error: 'Not authenticated' });
      }
      
      if (!user) {
        console.log('User not found during auth check');
        return res.status(401).json({ error: 'Not authenticated' });
      }
      
      console.log('Auth check successful for user:', user.email);
      res.json({ user });
    });
  } else {
    console.log('No session found');
    res.status(401).json({ error: 'Not authenticated' });
  }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
  console.log('Logout request received');
  
  req.session.destroy((err) => {
    if (err) {
      console.error('Session destruction error:', err);
      return res.status(500).json({ error: 'Could not log out' });
    }
    
    res.clearCookie('connect.sid');
    console.log('User logged out successfully');
    res.json({ message: 'Logout successful' });
  });
});

// Protected dashboard endpoint
app.get('/api/dashboard', (req, res) => {
  console.log('Dashboard request, session:', req.session);
  
  if (!req.session.userId) {
    console.log('Unauthorized dashboard access attempt');
    return res.status(401).json({ error: 'Authentication required' });
  }

  res.json({ 
    message: 'Welcome to the dashboard!',
    user: {
      id: req.session.userId,
      email: req.session.email
    },
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler - FIXED: Use proper Express syntax
app.use((req, res) => {
  console.log('404 - Route not found:', req.originalUrl);
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 API endpoints:`);
  console.log(`   GET  /api/health - Health check`);
  console.log(`   GET  /api/test - Server status`);
  console.log(`   POST /api/register - User registration`);
  console.log(`   POST /api/login - User login`);
  console.log(`   GET  /api/me - Check authentication`);
  console.log(`   POST /api/logout - User logout`);
  console.log(`   GET  /api/dashboard - Protected dashboard`);
});

module.exports = app;