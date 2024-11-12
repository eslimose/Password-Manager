// Import necessary modules
import { subtle } from 'crypto';  // "crypto" module doesn't support webcrypto in ESM, use 'crypto' directly.
import { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } from './lib.js';  // Add .js extension for ES modules
import { JSONFile } from 'lowdb';  // Import JSONFile from the 'lowdb/node' submodule




// Main PasswordManager class
class PasswordManager {
    constructor(hmacKey, aesKey, db) {
        this.hmacKey = hmacKey;
        this.aesKey = aesKey;
        this.db = db;
    }

    // Initialize the password manager with a master password
    static async init(password) {
        const salt = getRandomBytes(16); // Generate a 128-bit salt

        // Import the password as key material for PBKDF2
        const keyMaterial = await subtle.importKey(
            "raw",
            stringToBuffer(password),
            "PBKDF2",
            false,
            ["deriveBits", "deriveKey"]
        );

        // Derive HMAC key using PBKDF2
        const hmacKey = await subtle.deriveKey(
            { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
            keyMaterial,
            { name: "HMAC", hash: "SHA-256", length: 256 },
            true,
            ["sign"]
        );

        // Derive AES key using PBKDF2
        const aesKey = await subtle.deriveKey(
            { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        
        // Read the database to ensure it's initialized
        await db.read();
        db.data ||= { passwords: [] }; // Initialize the passwords array if empty

        return new PasswordManager(hmacKey, aesKey, db);
    }

    // Store or update a password for a given domain
    async set(name, value) {
        // Generate a hashed name using HMAC (sign the name)
        const hashedName = await subtle.sign(
            { name: "HMAC", hash: "SHA-256" },
            this.hmacKey,
            stringToBuffer(name)
        );

        // Generate a 96-bit IV for AES-GCM
        const iv = getRandomBytes(12);

        // Encrypt the value using AES-GCM with IV
        const encryptedValue = await subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            this.aesKey,
            stringToBuffer(value)
        );

        // Generate a signature to prevent swap attacks using HMAC
        const signature = await subtle.sign(
            { name: "HMAC", hash: "SHA-256" },
            this.hmacKey,
            stringToBuffer(name + value)
        );

        // Find if the password already exists in the DB
        const index = this.db.data.passwords.findIndex(p => p.name === bufferToString(hashedName));
        
        if (index === -1) {
            // If not found, add a new entry
            this.db.data.passwords.push({
                name: bufferToString(hashedName),
                iv: encodeBuffer(iv),
                value: encodeBuffer(encryptedValue),
                signature: bufferToString(signature)
            });
        } else {
            // If found, update the existing entry
            this.db.data.passwords[index] = {
                name: bufferToString(hashedName),
                iv: encodeBuffer(iv),
                value: encodeBuffer(encryptedValue),
                signature: bufferToString(signature)
            };
        }

        // Write changes to the database (JSON file)
        await this.db.write();

        return true;
    }

    // Retrieve and decrypt the password for a given domain
    async get(name) {
        // Generate a hashed name using HMAC (sign the name)
        const hashedName = await subtle.sign(
            { name: "HMAC", hash: "SHA-256" },
            this.hmacKey,
            stringToBuffer(name)
        );

        // Find the password entry in the database
        const entry = this.db.data.passwords.find(p => p.name === bufferToString(hashedName));
        
        if (!entry) return null;

        const { iv, value, signature } = entry;

        // Decrypt the value
        const decryptedValue = await subtle.decrypt(
            { name: "AES-GCM", iv: decodeBuffer(iv) },
            this.aesKey,
            decodeBuffer(value)
        );
        const valueString = bufferToString(decryptedValue);

        // Verify signature to defend against swap attacks
        const expectedSignature = await subtle.sign(
            { name: "HMAC", hash: "SHA-256" },
            this.hmacKey,
            stringToBuffer(name + valueString)
        );

        if (bufferToString(expectedSignature) !== signature) {
            throw new Error("Swap attack detected!");
        }

        return valueString;
    }

    // Remove an entry from the database if it exists
    async remove(name) {
        const hashedName = await subtle.sign(
            { name: "HMAC", hash: "SHA-256" },
            this.hmacKey,
            stringToBuffer(name)
        );

        const index = this.db.data.passwords.findIndex(p => p.name === bufferToString(hashedName));

        if (index === -1) {
            return false;
        }

        // Remove the password from the array
        this.db.data.passwords.splice(index, 1);

        // Write changes to the database (JSON file)
        await this.db.write();

        return true;
    }
}

export default PasswordManager;  // Use export default for ES modules
