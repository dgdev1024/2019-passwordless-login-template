/**
 * @file src/routes/user.js
 *
 * API routing for our registered user functions.
 */

// Imports
const express = require('express');
const user = require('../controllers/user');
const loginToken = require('../controllers/login-token');
const emailToken = require('../controllers/email-token');
const auth = require('../lib/auth');

// Express Router
const router = express.Router();

// Routes
router.post('/request-login', loginToken.request);
router.post('/verify-login', loginToken.authenticate);
router.get('/logout', auth.requireLoginToken, user.logout);
router.get('/logout-all', auth.requireLoginToken, user.logoutAll);
router.delete('/delete', auth.requireLoginToken, user.remove);

router.post(
  '/request-change-email',
  auth.requireLoginToken,
  emailToken.request
);
router.get(
  '/verify-change-email',
  auth.requireLoginToken,
  emailToken.authenticate
);

// Exports
module.exports = router;
