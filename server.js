require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const passport = require('passport');
const session = require('express-session');
const verifyToken = require('./middleware/auth');

require('./config/passport');

const app = express();

// Allow requests from all domains (development only)
app.use(cors({
  origin: ['http://127.0.0.1:5500', 'http://localhost:5500', 'https://lawsimplicity.com'],
  credentials: true
}));


// Middleware
app.use(express.json());
app.use(session({
  secret: process.env.JWT_SECRET || 'fallbacksecret',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Connect MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Routes
app.use('/api/auth', require('./routes/auth'));

// JWT-Protected Route Example
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({ message: 'Protected content accessed!', user: req.user });
});

// OAuth: Google
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  (req, res, next) => {
    passport.authenticate('google', { session: false }, (err, user, info) => {
      if (err) return res.redirect('https://lawsimplicity.com/auth/error.html?reason=server_error');

      // If Passport returns a custom message (like account_exists_with_password)
      if (!user && info && info.message === 'account_exists_with_password') {
        return res.redirect('https://lawsimplicity.com/auth/error.html?reason=account_exists_with_password');
      }

      if (!user) return res.redirect('https://lawsimplicity.com/auth/error.html?reason=authentication_failed');

      // Successful login – send token to frontend
      const token = user.token;
      res.redirect(`https://lawsimplicity.com/index.html?token=${token}`);
    })(req, res, next);
  }
);




// Success & Fail Views
app.get('/success', (req, res) => {
  res.send('<h2>Login Successful!</h2><p>You can now close this window or return to the app.</p>');
});

app.get('/login', (req, res) => {
  res.send('<h2>Login Failed</h2><p>Please try again.</p>');
});
app.get('/api/run-render', async (req, res) => {
  try {
    res.status(200).json({ status: 'hello' });
  } catch (error) {
    res.status(500).json({ error: 'Error' });
  }
});


// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
