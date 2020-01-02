/**
 * @file src/lib/auth.js
 *
 * Functions and login strategies for handling user authentication.
 */

// Imports
const passportLocal = require('passport-local');
const jwt = require('jsonwebtoken');
const loginTokenModel = require('../models/login-token');
const userModel = require('../models/user');
const base64 = require('./base64');
const { asyncMiddleware, asyncPassportLocal } = require('./async-wrap');
const { raiseError } = require('./error');

// Login strategy for finishing our passwordless login.
const localLoginStrategy = new passportLocal.Strategy(
  {
    usernameField: 'emailAddress',
    passwordField: 'encodedAuth',
    session: false
  },
  asyncPassportLocal(async (emailAddress, encodedAuth) => {
    // Decode our authentication.
    let authentication = null;
    try {
      authentication = JSON.parse(base64.decodeString(encodedAuth));
    } catch (err) {
      return raiseError(401, 'The authentication provided is invalid.');
    }

    // Make sure the decoded authentication object contains a code and a nonce.
    if (!authentication.code || !authentication.nonce) {
      return raiseError(401, 'The authentication provided is invalid.');
    }

    // Make sure the email address given resolves to a valid login token.
    const token = await loginTokenModel.findOne({ emailAddress });
    if (!token) {
      return raiseError(404, 'The authentication provided is invalid.');
    }

    // Check the submitted code and nonce against the token's code and nonce.
    const valid = token.check(authentication.code, authentication.nonce);

    // In production mode, regardless of the outcome of the authentication
    // attempt, destroy the token.
    if (process.env.NODE_ENV === 'production') {
      await token.remove();
    }

    if (!valid) {
      return raiseError(401, 'The authentication provided is invalid.');
    }

    // In development mode, we destroy the token AFTER successful authentiction.
    if (process.env.NODE_ENV === 'development') {
      await token.remove();
    }

    // Check to see if a user with the given email address exists. If it does not,
    // then create one.
    let user = await userModel.findOne({ emailAddress });
    if (user) {
      return { user };
    } else {
      user = new userModel();
      user.emailAddress = emailAddress;
      user = await user.save();

      return { user };
    }
  })
);

/**
 * Middleware function for checking to see if a user is logged in before
 * performing an action that requires user authentication.
 *
 * @param {Request} req
 */
const checkLoginToken = async req => {
  // Get the bearer header from the request.
  const bearerHeader = req.headers['authorization'];

  // If the header is not present, then the end-user is not logged in.
  if (typeof bearerHeader === 'undefined') {
    return raiseError(401, 'You are not logged in.');
  }

  // Split the retrieved header at the space and look for the second
  // element. Make sure that it is present!
  const rawToken = bearerHeader.split(' ')[1];
  if (typeof rawToken === 'undefined') {
    return raiseError(401, 'You are not logged in.');
  }

  // Verify the token and get a payload.
  let payload = null;
  try {
    payload = jwt.verify(rawToken, process.env.JWT_SECRET);

    // Make sure our payload contains a valid user ID, expiry claim, and
    // JWT ID nonce.
    if (!payload.id || !payload.exp || !payload.jti) {
      return raiseError(401, 'You are not logged in.');
    }
  } catch (err) {
    if (err.name && err.name === 'TokenExpiredError') {
      const user = await userModel.findById(payload.id);
      if (user) {
        user.removeLoginNonce(payload.jti);
        await user.save();
        return raiseError(401, 'Your login has expired. Please log in again.');
      }
    } else if (err.name && err.name === 'JsonWebTokenError') {
      return raiseError(401, 'You are not logged in.');
    }

    throw err;
  }

  // Attempt to authenticate the login by resolving the ID found in the
  // JWT payload to a user in the database.
  const user = await userModel.findById(payload.id);
  if (!user || user.verified === false) {
    return raiseError(401, 'You are not logged in.');
  }

  if (user.getLoginNonceIndex(payload.jti) === -1) {
    return raiseError(401, 'You are not logged in.');
  }

  // Authentication successful. Send the user, ID, and JWT nonce along to the
  // next middleware function.
  req.login = {
    id: user._id.toString(),
    nonce: payload.jti,
    user
  };
};

// Exports
module.exports = {
  localLoginStrategy,
  checkLoginToken: asyncMiddleware(checkLoginToken),
  requireLoginToken: asyncMiddleware(checkLoginToken, { nextOnError: false })
};
