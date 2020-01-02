/**
 * @file src/lib/base64.js
 * 
 * Functions for encoding and decoding base64 strings.
 */

/**
 * Encodes a UTF-8 string into base64.
 * 
 * @param {String} str The UTF-8 string.
 * @return {String} The encoded base64 string.
 */
const encodeString = str => Buffer.from(str).toString('base64');

/**
 * Decodes a base64 string into UTF-8.
 * 
 * @param {String} str The base64 string.
 * @return {String} The decoded UTF-8 string.
 */
const decodeString = str => Buffer.from(str, 'base64').toString('utf8');

// Export
module.exports = {
  encodeString,
  decodeString
};
