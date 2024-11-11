// Import necessary modules
const { subtle } = require('crypto').webcrypto;
const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require('./lib');

// Main PasswordManager class
class PasswordManager {
    constructor(hmacKey, aesKey, kvs = {}) {
        this.hmacKey = hmacKey;
        this.aesKey = aesKey;
        this.kvs = kvs;
    }

    // Initialize the password manager with a master password
    static async init(password) {
        const salt = getRandomBytes(16); // Generate a 128-bit salt

        // Import the password as a key material for PBKDF2
        const keyMaterial = await subtle.importKey(
            "raw",
            stringToBuffer(password),
            "PBKDF2",
            false,
            ["deriveBits", "deriveKey"]
        );

        // Derive the master key using PBKDF2
        const masterKey = await subtle.deriveKey(
            { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
            keyMaterial,
            { name: "HMAC", hash: "SHA-256", length: 256 },
            true,
            ["sign", "verify"]
        );

        // Derive HMAC and AES keys from the master key
        const hmacKey = await subtle.importKey(
            "raw",
            await subtle.sign("HMAC", masterKey, stringToBuffer("HMAC key")),
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );

        const aesKey = await subtle.importKey(
            "raw",
            await subtle.sign("HMAC", masterKey, stringToBuffer("AES key")),
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"]
        );

        return new PasswordManager(hmacKey, aesKey, {});
    }

    // Load the password manager from a serialized representation
    static async load(password, representation, trustedDataCheck) {
        const data = JSON.parse(representation);
        if (!data || !data.salt || !data.kvs) {
            throw new Error('Invalid serialized data');
        }

        const salt = decodeBuffer(data.salt);

        // Derive the master key using PBKDF2
        const keyMaterial = await subtle.importKey(
            "raw",
            stringToBuffer(password),
            "PBKDF2",
            false,
            ["deriveBits", "deriveKey"]
        );

        const derivedKey = await subtle.deriveKey(
            { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
            keyMaterial,
            { name: "HMAC", hash: "SHA-256", length: 256 },
            true,
            ["sign", "verify"]
        );

        // Verify integrity if trustedDataCheck is provided
        if (trustedDataCheck !== undefined) {
            const currentHash = await subtle.digest("SHA-256", stringToBuffer(representation));
            if (bufferToString(currentHash) !== trustedDataCheck) {
                throw new Error("Tampering detected!");
            }
        }

        // Set up HMAC and AES keys
        const hmacKey = await subtle.importKey(
            "raw",
            derivedKey,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );

        const aesKey = await subtle.importKey(
            "raw",
            derivedKey,
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"]
        );

        return new PasswordManager(hmacKey, aesKey, data.kvs);
    }

    // Serialize the KVS and generate a SHA-256 hash for integrity
    async dump() {
        const serializedData = JSON.stringify({ kvs: this.kvs });
        const hashBuffer = await subtle.digest("SHA-256", stringToBuffer(serializedData));
        const hashString = bufferToString(hashBuffer); // Convert hash to string for storage
        return [serializedData, hashString];
    }

    // Store or update a password for a given domain
    async set(name, value) {
        const hashedName = await subtle.sign("HMAC", this.hmacKey, stringToBuffer(name));
        const iv = getRandomBytes(12); // AES-GCM requires a 96-bit IV

        // Encrypt the password using AES-GCM
        const encryptedValue = await subtle.encrypt(
            { name: "AES-GCM", iv },
            this.aesKey,
            stringToBuffer(value)
        );

        // Generate signature to prevent swap attacks
        const signature = await subtle.sign(
            "HMAC",
            this.hmacKey,
            stringToBuffer(name + value)
        );

        // Store encrypted value along with IV and signature
        this.kvs[bufferToString(hashedName)] = {
            iv: encodeBuffer(iv),
            value: encodeBuffer(encryptedValue),
            signature: bufferToString(signature)
        };
    }

    // Retrieve and decrypt the password for a given domain
    async get(name) {
        const hashedName = await subtle.sign("HMAC", this.hmacKey, stringToBuffer(name));
        const record = this.kvs[bufferToString(hashedName)];
        if (!record) return null;

        // Verify signature to defend against swap attacks
        const decryptedValue = await subtle.decrypt(
            { name: "AES-GCM", iv: decodeBuffer(record.iv) },
            this.aesKey,
            decodeBuffer(record.value)
        );
        const valueString = bufferToString(decryptedValue);

        const expectedSignature = await subtle.sign(
            "HMAC",
            this.hmacKey,
            stringToBuffer(name + valueString)
        );

        if (bufferToString(expectedSignature) !== record.signature) {
            throw new Error("Swap attack detected!");
        }

        return valueString;
    }

    // Remove an entry from the KVS if it exists
    async remove(name) {
        const hashedName = await subtle.sign("HMAC", this.hmacKey, stringToBuffer(name));
        const exists = this.kvs.hasOwnProperty(bufferToString(hashedName));
        if (exists) delete this.kvs[bufferToString(hashedName)];
        return exists;
    }
}

module.exports = PasswordManager;
