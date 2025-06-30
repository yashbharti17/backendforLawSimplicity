const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;

// Sign up
const crypto = require('crypto');
const nodemailer = require('nodemailer');

router.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const verifyToken = crypto.randomBytes(32).toString('hex');

    const user = await User.create({ name, email, password: hashed, verifyToken });

    // Send verification email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const verifyURL = `http://localhost:3000/api/auth/verify-email?token=${verifyToken}`;

    await transporter.sendMail({
      to: email,
      subject: 'Verify your LawSimplicity account',
      html: `<p>Hi ${name},</p><p>Please verify your email by clicking this link:</p><a href="${verifyURL}">${verifyURL}</a>`
    });

    res.json({ message: 'Verification email sent. Please check your inbox.' });

  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

//verify-email
router.get('/verify-email', async (req, res) => {
  const { token } = req.query;

  try {
    const user = await User.findOne({ verifyToken: token });
    if (!user) return res.status(400).send('Invalid or expired token');

    user.verified = true;
    user.verifyToken = null;
    await user.save();

    res.send('<h2>Email verified successfully! You can now log in.</h2>');
  } catch (err) {
    res.status(500).send('Verification failed');
  }
});



// Sign in
router.post('/signin', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'User not found' });

    if (!user.verified) {
      return res.status(403).json({ error: 'Please verify your email before signing in.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user._id, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});



// Forgot Password
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'User not found' });

  const resetToken = crypto.randomBytes(32).toString('hex');
  user.resetToken = resetToken;
  user.resetTokenExpiry = Date.now() + 1000 * 60 * 30; // 30 minutes
  await user.save();

  const resetURL = `http://localhost:5500/auth/reset-password.html?token=${resetToken}`;

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  await transporter.sendMail({
    to: email,
    subject: 'Reset Your Password – LawSimplicity',
    html: `<p>Click below to reset your password:</p><a href="${resetURL}">${resetURL}</a>`
  });

  res.json({ message: 'Reset link sent to your email' });
});

// Reset Password
router.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;
  const user = await User.findOne({
    resetToken: token,
    resetTokenExpiry: { $gt: Date.now() }
  });

  if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

  const hashed = await bcrypt.hash(password, 10);
  user.password = hashed;
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;
  await user.save();

  res.json({ message: 'Password reset successful. You can now log in.' });
});

module.exports = router;
