/**
 * @file src/controllers/login-token.js
 *
 * Controller functions for our login tokens.
 */

// Imports
const passport = require('passport');
const loginTokenModel = require('../models/login-token');
const emailTokenModel = require('../models/email-token');
const { asyncEndpoint } = require('../lib/async-wrap');
const { localLoginStrategy } = require('../lib/auth');
const base64 = require('../lib/base64');
const { raiseError } = require('../lib/error');
const sendEmail = require('../lib/send-email');
const validate = require('../lib/validate');

// Pull in the Passport local login strategy.
passport.use('local-login', localLoginStrategy);

/**
 * Requests a new login token.
 * 
 * @param {Request} req
 */
const request = async req => {
  // Get and validate the user's email address from the request body.
  const { emailAddress } = req.body;
  const validationErrors = [
    validate.emailAddress(emailAddress)
  ].filter(v => !!v);
  if (validationErrors.length > 0) {
    return raiseError(400, 'There were issues validating your input.', validationErrors);
  }

  // Make sure there isn't already a login token requested for this user.
  const existingToken = await loginTokenModel.findOne({ emailAddress });
  if (existingToken) {
    return raiseError(409, 'This email address is temporarly unavailable.', [
      ['emailAddress', 'This email address is temporarly unavailable.']
    ]);
  }

  // Make sure another user isn't trying to change their account email to
  // the address given.
  const existingEmailToken = await emailTokenModel.findOne({
    newEmailAddress: emailAddress
  });
  if (existingEmailToken) {
    return raiseError(409, 'This email address is temporarly unavailable.', [
      ['emailAddress', 'This email address is temporarly unavailable.']
    ]);
  }

  // Create the login token.
  let token = new loginTokenModel();
  const authentication = token.generate();
  token.emailAddress = emailAddress;
  token = await token.save();

  // Create the return object.
  const ret = {
    emailAddress,
    nonce: base64.encodeString(authentication.nonce)
  };

  // In development mode, create and encode a JSON string with both the
  // code and nonce, and send that over, too.
  if (process.env.NODE_ENV === 'development') {
    ret.encoded = base64.encodeString(
      JSON.stringify(authentication)
    );
  }

  // TODO: Send the user an email with the authentication code.
  try {
    await sendEmail.verifyLogin(emailAddress, {
      code: authentication.code
    });
  } catch (err) {
    await token.remove();
    throw err;
  }

  return {
    ...ret,
    message: 'Check your email for the login verification link.'
  };
};

/**
 * Uses Passport's local login strategy to authenticate a login token.
 * 
 * @param {Request} req
 * @param {Response} res
 */
const authenticate = (req, res) => {
  passport.authenticate('local-login', (err, user, info) => {
    if (err) {
      return res.status(err.status || 500).json({ error: err });
    }

    if (!user) {
      return res.status(info.status || 500).json(info);
    }

    user
      .generateLoginToken()
      .then(token => {
        return res.status(200).json({ token });
      })
      .catch(err => {
        return res.status(err.status || 500).json({ error: err });
      });
  })(req, res);
};

// Exports
module.exports = {
  request: asyncEndpoint(request),
  authenticate
};
