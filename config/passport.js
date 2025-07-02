const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET || 'fallbacksecret';

// Serialize & Deserialize
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => User.findById(id).then(user => done(null, user)));

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_ID,
  clientSecret: process.env.GOOGLE_SECRET,
  callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;

    // Check if a user with this email exists (from password signup)
    const existingUser = await User.findOne({ email });

    // If user exists with password-based login, block OAuth login
    if (existingUser && (!existingUser.oauthProvider || existingUser.oauthProvider === 'local')) {
      return done(null, false, { message: 'account_exists_with_password' });
    }

    // Find or create OAuth user
    let user = await User.findOne({ oauthId: profile.id, oauthProvider: 'google' });
    if (!user) {
      user = await User.create({
        name: profile.displayName,
        email,
        oauthProvider: 'google',
        oauthId: profile.id,
        verified: true
      });
    }

    const token = jwt.sign({ id: user._id, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
    user.token = token;
    done(null, user);

  } catch (err) {
    done(err, null);
  }
}));

// LinkedIn OAuth Strategy
passport.use(new LinkedInStrategy({
  clientID: process.env.LINKEDIN_ID,
  clientSecret: process.env.LINKEDIN_SECRET,
  callbackURL: '/auth/linkedin/callback',
  scope: ['r_emailaddress', 'r_liteprofile'],
}, async (accessToken, tokenSecret, profile, done) => {
  try {
    const email = profile.emails[0].value;

    const existingUser = await User.findOne({ email });
    if (existingUser && (!existingUser.oauthProvider || existingUser.oauthProvider === 'local')) {
      return done(null, false, { message: 'account_exists_with_password' });
    }

    let user = await User.findOne({ oauthId: profile.id, oauthProvider: 'linkedin' });
    if (!user) {
      user = await User.create({
        name: profile.displayName,
        email,
        oauthProvider: 'linkedin',
        oauthId: profile.id,
        verified: true
      });
    }

    const token = jwt.sign({ id: user._id, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
    user.token = token;
    done(null, user);

  } catch (err) {
    done(err, null);
  }
}));
