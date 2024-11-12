// lib.js

// Importing crypto library to generate random values
import { randomBytes } from 'crypto';  // Using the ES module import syntax

/**
 * Converts a plaintext string into a buffer for use in SubtleCrypto functions.
 * @param {string} str - A plaintext string
 * @returns {Buffer} A buffer representation for use in SubtleCrypto functions
 */
export function stringToBuffer(str) {
    return Buffer.from(str);
}

/**
 * Converts a buffer object representing string data back into a string
 * @param {BufferSource} buf - A buffer containing string data
 * @returns {string} The original string
 */
export function bufferToString(buf) {
    return Buffer.from(buf).toString();
}

/**
 * Converts a buffer to a Base64 string which can be used as a key in a map and
 * can be easily serialized.
 * @param {BufferSource} buf - A buffer-like object
 * @returns {string} A Base64 string representing the bytes in the buffer
 */
export function encodeBuffer(buf) {
    return Buffer.from(buf).toString('base64');
}

/**
 * Converts a Base64 string back into a buffer
 * @param {string} base64 - A Base64 string representing a buffer
 * @returns {Buffer} A Buffer object
 */
export function decodeBuffer(base64) {
    if (!base64) {
        throw new TypeError("Encoded string cannot be undefined or null.");
    }
    return Buffer.from(base64, "base64");
}

/**
 * Generates a buffer of random bytes
 * @param {number} len - The number of random bytes
 * @returns {Uint8Array} A buffer of `len` random bytes
 */
export function getRandomBytes(len) {
    return randomBytes(len);
}
