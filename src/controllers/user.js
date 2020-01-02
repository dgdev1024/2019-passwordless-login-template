/**
 * @file src/controllers/user.js
 *
 * Controller functions for our registered user.
 */

// Imports
const emailTokenModel = require('../models/email-token');
const { asyncEndpoint } = require('../lib/async-wrap');
const { raiseError } = require('../lib/error');
const log = require('../lib/log');


/**
 * Attempts to log an authenticated user out on a single device.
 *
 * @param {Request} req
 */
const logout = async req => {
  const { user, nonce } = req.login;
  user.removeLoginNonce(nonce);
  await user.save();

  return { message: 'You are now logged out.' };
};

/**
 * Attempts to log an authenticated user out on all devices.
 *
 * @param {Request} req
 */
const logoutAll = async req => {
  const { user } = req.login;
  user.removeAllLoginNonces();
  await user.save();

  return { message: 'You are now logged out.' };
};

/**
 * Deletes the account of the authenticated user, thereby logging
 * that user out.
 *
 * @param {Request} req
 */
const remove = async req => {
  const { user } = req.login;
  const { consent } = req.body;

  if (typeof consent !== 'boolean' || consent === false) {
    return raiseError(400, 'Account deletion requires explicit consent.');
  }

  await emailTokenModel.deleteMany({ emailAddress: user.emailAddress });
  await user.remove();
  return { message: 'Your account has been deleted.' };
};

// Exports
module.exports = {
  logout: asyncEndpoint(logout),
  logoutAll: asyncEndpoint(logoutAll),
  remove: asyncEndpoint(remove)
};
