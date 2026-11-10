
"use strict";

const crypto = require("crypto");

/*
 * AES-256-GCM Encryption
 *
 * Alice:
 *   Medical Record
 *        ↓
 *   AES-256-GCM
 *        ↓
 *   Ciphertext + IV + Auth Tag
 *
 * The AES key is NOT stored with the ciphertext.
 * It should be passed to Shamir Secret Sharing.
 */

// ---------------------------------------------------------
// Generate AES-256 encryption key
// ---------------------------------------------------------

function generateKey() {
    return crypto.randomBytes(32); // 256-bit key
}


// ---------------------------------------------------------
// Encrypt medical record
// ---------------------------------------------------------

function encryptMedicalRecord(plaintext, key = null) {

    if (!plaintext) {
        throw new Error(
            "Medical record cannot be empty."
        );
    }

    // Generate a new key if one is not supplied.
    if (!key) {
        key = generateKey();
    }

    // Convert hexadecimal key to Buffer if required.
    if (typeof key === "string") {
        key = Buffer.from(key, "hex");
    }

    if (!Buffer.isBuffer(key)) {
        throw new Error(
            "Encryption key must be a Buffer or hexadecimal string."
        );
    }

    if (key.length !== 32) {
        throw new Error(
            "AES-256 requires a 32-byte key."
        );
    }

    // AES-GCM requires a unique IV.
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(
        "aes-256-gcm",
        key,
        iv
    );

    const encrypted =
        Buffer.concat([
            cipher.update(
                String(plaintext),
                "utf8"
            ),
            cipher.final()
        ]);

    // Authentication tag protects against ciphertext modification.
    const authTag =
        cipher.getAuthTag();

    return {

        ciphertext:
            encrypted.toString("hex"),

        iv:
            iv.toString("hex"),

        authTag:
            authTag.toString("hex"),

        algorithm:
            "AES-256-GCM",

        key:
            key.toString("hex")
    };
}


// ---------------------------------------------------------
// Encrypt JSON medical record
// ---------------------------------------------------------

function encryptJSON(record, key = null) {

    const plaintext =
        JSON.stringify(record);

    return encryptMedicalRecord(
        plaintext,
        key
    );
}


// ---------------------------------------------------------
// Export
// ---------------------------------------------------------

module.exports = {
    generateKey,
    encryptMedicalRecord,
    encryptJSON
};


// ---------------------------------------------------------
// Test when executed directly
// ---------------------------------------------------------

if (require.main === module) {

    console.log("");
    console.log(
        "============================================================"
    );
    console.log(
        "                 AES ENCRYPTION TEST"
    );
    console.log(
        "============================================================"
    );

    const medicalRecord = {
        patient: "Alice",
        recordId: "REC-001",
        diagnosis: "Diabetes",
        treatment: "Diabetes treatment",
        dataScope: [
            "prescription",
            "diagnostic images"
        ]
    };

    try {

        const result =
            encryptJSON(medicalRecord);

        console.log("");
        console.log(
            "Medical record encrypted successfully."
        );

        console.log(
            "Algorithm:",
            result.algorithm
        );

        console.log(
            "Ciphertext:",
            result.ciphertext
        );

        console.log(
            "IV:",
            result.iv
        );

        console.log(
            "Authentication tag:",
            result.authTag
        );

        console.log(
            "Key generated successfully."
        );

        console.log("");
        console.log(
            "IMPORTANT: The key should now be"
        );

        console.log(
            "passed to Shamir Secret Sharing."
        );

        console.log(
            "============================================================"
        );

    } catch (error) {

        console.error(
            "Encryption failed:",
            error.message
        );
    }
}

