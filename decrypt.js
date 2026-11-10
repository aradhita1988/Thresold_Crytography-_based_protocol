/**
 * ============================================================
 * crypto/decrypt.js
 * ============================================================
 *
 * Alice / Hospital medical-record decryption.
 *
 * Algorithm:
 *      AES-256-GCM
 *
 * The AES key is reconstructed by:
 *
 *      crypto/lagrange.js
 *
 * before this module is called.
 *
 * IMPORTANT:
 *
 * This file does NOT perform Shamir reconstruction.
 *
 * It only uses the reconstructed AES-256 key to decrypt
 * the encrypted medical record.
 *
 * ============================================================
 */

const crypto = require("crypto");


// ============================================================
// Constants
// ============================================================

const ALGORITHM = "aes-256-gcm";

const KEY_LENGTH = 32;

const IV_LENGTH = 12;

const AUTH_TAG_LENGTH = 16;


// ============================================================
// Validate Key
// ============================================================

function validateKey(key) {

    if (typeof key === "string") {

        try {

            key = Buffer.from(
                key,
                "hex"
            );

        } catch (error) {

            throw new Error(
                "Invalid hexadecimal encryption key"
            );
        }
    }


    if (!Buffer.isBuffer(key)) {

        throw new Error(
            "Decryption key must be a Buffer or hexadecimal string"
        );
    }


    if (key.length !== KEY_LENGTH) {

        throw new Error(
            "AES-256 key must be exactly 32 bytes"
        );
    }


    return key;
}


// ============================================================
// Validate Hexadecimal Data
// ============================================================

function hexToBuffer(
    value,
    fieldName
) {

    if (
        typeof value !== "string"
        ||
        value.length === 0
    ) {

        throw new Error(
            `${fieldName} is required`
        );
    }


    if (
        value.length % 2 !== 0
    ) {

        throw new Error(
            `${fieldName} has invalid hexadecimal length`
        );
    }


    if (
        !/^[0-9a-fA-F]+$/.test(value)
    ) {

        throw new Error(
            `${fieldName} contains invalid hexadecimal characters`
        );
    }


    return Buffer.from(
        value,
        "hex"
    );
}


// ============================================================
// Decrypt Medical Record
// ============================================================

/**
 * Decrypt AES-256-GCM encrypted data.
 *
 * @param {Object} encryptedData
 * @param {Buffer|string} key
 *
 * encryptedData:
 *
 * {
 *     algorithm,
 *     ciphertext,
 *     iv,
 *     authTag
 * }
 *
 * Returns:
 *
 * Buffer containing plaintext.
 */

function decryptMedicalRecord(

    encryptedData,

    key

) {

    // --------------------------------------------------------
    // Validate encrypted data
    // --------------------------------------------------------

    if (!encryptedData) {

        throw new Error(
            "Encrypted data is required"
        );
    }


    if (
        encryptedData.algorithm
        &&
        encryptedData.algorithm !==
        ALGORITHM
    ) {

        throw new Error(
            `Unsupported encryption algorithm: ${encryptedData.algorithm}`
        );
    }


    // --------------------------------------------------------
    // Validate key
    // --------------------------------------------------------

    key =
        validateKey(key);


    // --------------------------------------------------------
    // Convert encrypted values
    // --------------------------------------------------------

    const ciphertext =
        hexToBuffer(
            encryptedData.ciphertext,
            "Ciphertext"
        );


    const iv =
        hexToBuffer(
            encryptedData.iv,
            "IV"
        );


    const authTag =
        hexToBuffer(
            encryptedData.authTag,
            "Authentication tag"
        );


    // --------------------------------------------------------
    // Validate IV
    // --------------------------------------------------------

    if (
        iv.length !== IV_LENGTH
    ) {

        throw new Error(
            `AES-GCM IV must be ${IV_LENGTH} bytes`
        );
    }


    // --------------------------------------------------------
    // Validate authentication tag
    // --------------------------------------------------------

    if (
        authTag.length !==
        AUTH_TAG_LENGTH
    ) {

        throw new Error(
            `Authentication tag must be ${AUTH_TAG_LENGTH} bytes`
        );
    }


    // --------------------------------------------------------
    // Create decipher
    // --------------------------------------------------------

    const decipher =
        crypto.createDecipheriv(

            ALGORITHM,

            key,

            iv,

            {
                authTagLength:
                    AUTH_TAG_LENGTH
            }
        );


    // --------------------------------------------------------
    // Set authentication tag
    // --------------------------------------------------------

    decipher.setAuthTag(
        authTag
    );


    // --------------------------------------------------------
    // Decrypt
    // --------------------------------------------------------

    try {

        const decrypted =
            Buffer.concat([

                decipher.update(
                    ciphertext
                ),

                decipher.final()
            ]);


        return decrypted;

    } catch (error) {

        throw new Error(
            "Decryption failed: invalid key or corrupted/authentication-failed ciphertext"
        );
    }
}


// ============================================================
// Decrypt to UTF-8 Text
// ============================================================

function decryptToText(

    encryptedData,

    key

) {

    const plaintext =
        decryptMedicalRecord(
            encryptedData,
            key
        );


    return plaintext.toString(
        "utf8"
    );
}


// ============================================================
// Decrypt JSON Medical Record
// ============================================================

/**
 * Useful when Alice stores the medical record as JSON.
 *
 * Example:
 *
 * {
 *     patient: "Alice",
 *     diagnosis: "Diabetes",
 *     prescription: "Metformin"
 * }
 */

function decryptJSON(

    encryptedData,

    key

) {

    const plaintext =
        decryptToText(
            encryptedData,
            key
        );


    try {

        return JSON.parse(
            plaintext
        );

    } catch (error) {

        throw new Error(
            "Decrypted data is not valid JSON"
        );
    }
}


// ============================================================
// Decrypt with AAD
// ============================================================

/**
 * AES-GCM supports Additional Authenticated Data.
 *
 * AAD is authenticated but not encrypted.
 *
 * Example:
 *
 * {
 *     recordId: 1,
 *     patient: "Alice"
 * }
 *
 * If AAD is modified, authentication fails.
 */

function decryptMedicalRecordWithAAD(

    encryptedData,

    key,

    aad

) {

    // --------------------------------------------------------
    // Validate key
    // --------------------------------------------------------

    key =
        validateKey(key);


    // --------------------------------------------------------
    // Convert ciphertext
    // --------------------------------------------------------

    const ciphertext =
        hexToBuffer(
            encryptedData.ciphertext,
            "Ciphertext"
        );


    const iv =
        hexToBuffer(
            encryptedData.iv,
            "IV"
        );


    const authTag =
        hexToBuffer(
            encryptedData.authTag,
            "Authentication tag"
        );


    if (
        iv.length !== IV_LENGTH
    ) {

        throw new Error(
            "Invalid AES-GCM IV"
        );
    }


    if (
        authTag.length !==
        AUTH_TAG_LENGTH
    ) {

        throw new Error(
            "Invalid AES-GCM authentication tag"
        );
    }


    // --------------------------------------------------------
    // Prepare AAD
    // --------------------------------------------------------

    let aadBuffer;


    if (Buffer.isBuffer(aad)) {

        aadBuffer =
            aad;

    } else if (
        typeof aad === "object"
    ) {

        aadBuffer =
            Buffer.from(
                JSON.stringify(aad),
                "utf8"
            );

    } else {

        aadBuffer =
            Buffer.from(
                String(aad),
                "utf8"
            );
    }


    // --------------------------------------------------------
    // Create decipher
    // --------------------------------------------------------

    const decipher =
        crypto.createDecipheriv(

            ALGORITHM,

            key,

            iv,

            {
                authTagLength:
                    AUTH_TAG_LENGTH
            }
        );


    // --------------------------------------------------------
    // Authenticate AAD
    // --------------------------------------------------------

    decipher.setAAD(
        aadBuffer
    );


    // --------------------------------------------------------
    // Set authentication tag
    // --------------------------------------------------------

    decipher.setAuthTag(
        authTag
    );


    // --------------------------------------------------------
    // Decrypt
    // --------------------------------------------------------

    try {

        return Buffer.concat([

            decipher.update(
                ciphertext
            ),

            decipher.final()
        ]);

    } catch (error) {

        throw new Error(
            "AAD authentication failed or invalid encryption key"
        );
    }
}


// ============================================================
// Decrypt JSON with AAD
// ============================================================

function decryptJSONWithAAD(

    encryptedData,

    key,

    aad

) {

    const plaintext =
        decryptMedicalRecordWithAAD(

            encryptedData,

            key,

            aad
        );


    try {

        return JSON.parse(
            plaintext.toString("utf8")
        );

    } catch (error) {

        throw new Error(
            "Decrypted data is not valid JSON"
        );
    }
}


// ============================================================
// Verify Encryption Object
// ============================================================

function validateEncryptedRecord(
    encryptedData
) {

    if (!encryptedData) {

        return false;
    }


    if (
        !encryptedData.ciphertext
    ) {

        return false;
    }


    if (
        !encryptedData.iv
    ) {

        return false;
    }


    if (
        !encryptedData.authTag
    ) {

        return false;
    }


    try {

        const iv =
            Buffer.from(
                encryptedData.iv,
                "hex"
            );


        const tag =
            Buffer.from(
                encryptedData.authTag,
                "hex"
            );


        return (

            iv.length === IV_LENGTH
            &&
            tag.length === AUTH_TAG_LENGTH
        );

    } catch (error) {

        return false;
    }
}


// ============================================================
// Calculate Decryption Input Overhead
// ============================================================

/**
 * Calculates the byte size of encrypted components.
 *
 * Useful for your communication-overhead experiment.
 */

function calculateDecryptionOverhead(

    encryptedData

) {

    if (
        !validateEncryptedRecord(
            encryptedData
        )
    ) {

        throw new Error(
            "Invalid encrypted record"
        );
    }


    const ciphertextBytes =
        Buffer.from(
            encryptedData.ciphertext,
            "hex"
        ).length;


    const ivBytes =
        Buffer.from(
            encryptedData.iv,
            "hex"
        ).length;


    const authTagBytes =
        Buffer.from(
            encryptedData.authTag,
            "hex"
        ).length;


    return {

        ciphertextBytes,

        ivBytes,

        authTagBytes,

        totalEncryptedBytes:
            ciphertextBytes +
            ivBytes +
            authTagBytes
    };
}


// ============================================================
// Decryption Latency
// ============================================================

/**
 * Measures local AES decryption execution time.
 *
 * This is NOT blockchain latency.
 *
 * It is useful for:
 *
 *     Computational Cost
 *     Execution Time
 */

function measureDecryptionLatency(

    encryptedData,

    key

) {

    const start =
        process.hrtime.bigint();


    const plaintext =
        decryptMedicalRecord(

            encryptedData,

            key
        );


    const end =
        process.hrtime.bigint();


    const latencyNanoseconds =
        end - start;


    const latencyMilliseconds =
        Number(
            latencyNanoseconds
        ) / 1e6;


    return {

        plaintext,

        latencyMilliseconds,

        latencyNanoseconds
    };
}


// ============================================================
// Demonstration Test
// ============================================================

/**
 * Run:
 *
 *     node crypto/decrypt.js
 *
 * to test encryption + decryption locally.
 *
 * This section does NOT execute when the module is imported.
 */

if (require.main === module) {

    const {
        generateAESKey,
        encryptMedicalRecord
    } = require("./encrypt");


    console.log(
        "\n========================================"
    );

    console.log(
        "AES-256-GCM Encryption/Decryption Test"
    );

    console.log(
        "========================================\n"
    );


    // --------------------------------------------------------
    // Generate Alice's AES key
    // --------------------------------------------------------

    const key =
        generateAESKey();


    console.log(
        "AES Key:",
        key.toString("hex")
    );


    // --------------------------------------------------------
    // Medical record
    // --------------------------------------------------------

    const medicalRecord = {

        patient:
            "Alice",

        recordId:
            1,

        diagnosis:
            "Diabetes",

        prescription:
            "Metformin",

        dataScope:
            "prescription",

        notes:
            "Regular monitoring required"
    };


    console.log(
        "\nOriginal Record:"
    );

    console.log(
        medicalRecord
    );


    // --------------------------------------------------------
    // Encrypt
    // --------------------------------------------------------

    const encrypted =
        encryptMedicalRecord(

            medicalRecord,

            key
        );


    console.log(
        "\nEncrypted Record:"
    );

    console.log(
        encrypted
    );


    // --------------------------------------------------------
    // Measure decryption
    // --------------------------------------------------------

    const result =
        measureDecryptionLatency(

            encrypted,

            key
        );


    console.log(
        "\nDecryption Latency:",
        result.latencyMilliseconds,
        "ms"
    );


    // --------------------------------------------------------
    // Convert decrypted data to JSON
    // --------------------------------------------------------

    const decrypted =
        JSON.parse(
            result.plaintext.toString(
                "utf8"
            )
        );


    console.log(
        "\nDecrypted Record:"
    );

    console.log(
        decrypted
    );


    // --------------------------------------------------------
    // Overhead
    // --------------------------------------------------------

    const overhead =
        calculateDecryptionOverhead(
            encrypted
        );


    console.log(
        "\nEncryption Overhead:"
    );

    console.log(
        overhead
    );


    console.log(
        "\n========================================"
    );

    console.log(
        "Test completed successfully."
    );

    console.log(
        "========================================\n"
    );
}


// ============================================================
// Export
// ============================================================

module.exports = {

    ALGORITHM,

    KEY_LENGTH,

    IV_LENGTH,

    AUTH_TAG_LENGTH,

    decryptMedicalRecord,

    decryptToText,

    decryptJSON,

    decryptMedicalRecordWithAAD,

    decryptJSONWithAAD,

    validateEncryptedRecord,

    calculateDecryptionOverhead,

    measureDecryptionLatency
};