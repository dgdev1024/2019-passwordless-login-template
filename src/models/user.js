/**
 * @file src/models/user.js
 *
 * The database model for our registered users.
 */

// Imports
const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const csprng = require('csprng');
const jwt = require('jsonwebtoken');

// Schema
const schema = new mongoose.Schema({
  // Note: Add more fields here as you need them.

  // The user's email address.
  emailAddress: { type: String, required: true, unique: true },

  // A container of login nonces. Each nonce represents a device on which
  // the user is logged in to the application.
  loginNonces: [{ type: String }]
});

// Methods
schema.methods.generateLoginNonce = function () {
  // Generate the nonce, then salt-and-hash it.
  const nonce = csprng();
  const nonceSalt = bcryptjs.genSaltSync();
  const nonceHash = bcryptjs.hashSync(nonce, nonceSalt);

  // Add the login nonce to our active nonces.
  this.loginNonces.push(nonceHash);

  return nonce;
};

schema.methods.getLoginNonceIndex = function (nonce) {
  const index = this.loginNonces.findIndex(hash =>
    bcryptjs.compareSync(nonce, hash)
  );
  return index;
};

schema.methods.removeLoginNonce = function (nonce) {
  const index = this.getLoginNonceIndex(nonce);
  if (index !== -1) {
    this.loginNonces.splice(index, 1);
    return true;
  }

  return false;
};

schema.methods.removeAllLoginNonces = function () {
  this.loginNonces = [];
};

schema.methods.generateLoginToken = async function () {
  let date = new Date();
  date.setDate(date.getDate() + 2);

  const loginNonce = this.generateLoginNonce();
  await this.save();

  return jwt.sign(
    {
      id: this._id.toString(),
      exp: Math.floor(date.getTime() / 1000),
      jti: loginNonce
    },
    process.env.JWT_SECRET
  );
};

// Exports
module.exports = mongoose.model('user', schema);
