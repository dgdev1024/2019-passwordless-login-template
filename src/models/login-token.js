/**
 * @file src/models/login-token.js
 *
 * Database model for a token allowing a user to create and/or log in to their
 * account.
 */

// Imports
const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const csprng = require('csprng');

// Schema
const schema = new mongoose.Schema({
  // The email address of the user requesting the login.
  emailAddress: { type: String, required: true, unique: true },

  // The authentication code and nonce needed to log in.
  authCodeHash: { type: String, required: true, unique: true },
  authNonceHash: { type: String, required: true, unique: true },

  // The token's expiry.
  authExpiry: {
    type: Date,
    default: Date.now,
    expires: parseInt(process.env.TOKEN_EXPIRY)
  }
});

// Methods
schema.methods.generate = function () {
  const code = csprng();
  const nonce = csprng();

  const codeSalt = bcryptjs.genSaltSync();
  const nonceSalt = bcryptjs.genSaltSync();

  this.authCodeHash = bcryptjs.hashSync(code, codeSalt);
  this.authNonceHash = bcryptjs.hashSync(nonce, nonceSalt);

  return { code, nonce };
};

schema.methods.check = function (code, nonce) {
  return (
    bcryptjs.compareSync(code, this.authCodeHash) &&
    bcryptjs.compareSync(nonce, this.authNonceHash)
  )
};

// Exports
module.exports = mongoose.model('login-token', schema);
