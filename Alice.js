/**
 * ============================================================
 * patient/Alice.js
 * ============================================================
 *
 * Patient Alice
 *
 * Healthcare Observer + Threshold Cryptography System
 *
 * Chain X = Patient Chain
 * Chain Y = Hospital Chain
 *
 * Alice performs:
 *
 *   1. Generate AES-256 key
 *   2. Encrypt medical record
 *   3. Generate Shamir shares
 *   4. Distribute shares to observers
 *   5. Store encrypted record metadata on Chain X
 *   6. Create consent
 *   7. Sign consent using ECDSA
 *   8. Store signed consent on Chain X
 *
 * ============================================================
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const Web3 =
    require("web3");


// ============================================================
// Import Cryptographic Modules
// ============================================================

const {
    generateRandomThreshold,
    generateSharesFromAESKey,
    calculateShareOverhead
} = require("../crypto/shamir");


// ============================================================
// Configuration
// ============================================================

let config = {};

try {

    config =
        require("../config");

} catch (error) {

    /*
     * Configuration can also be supplied through environment
     * variables.
     */

    config = {};
}


// ============================================================
// Chain X Configuration
// ============================================================

const CHAIN_X_RPC =
    process.env.CHAIN_X_RPC ||
    config.CHAIN_X_RPC ||
    "http://127.0.0.1:7545";


const CHAIN_X_CHAIN_ID =
    process.env.CHAIN_X_CHAIN_ID ||
    config.CHAIN_X_CHAIN_ID ||
    1337;


// ============================================================
// Alice Account
// ============================================================

const ALICE_PRIVATE_KEY =
    process.env.ALICE_PRIVATE_KEY ||
    config.ALICE_PRIVATE_KEY;


const ALICE_ADDRESS =
    process.env.ALICE_ADDRESS ||
    config.ALICE_ADDRESS;


// ============================================================
// Observer Configuration
// ============================================================

const NUMBER_OF_OBSERVERS =
    Number(
        process.env.NUMBER_OF_OBSERVERS ||
        config.NUMBER_OF_OBSERVERS ||
        5
    );


// ============================================================
// Database Paths
// ============================================================

const DATABASE_DIR =
    path.join(
        __dirname,
        "..",
        "database"
    );


const RECORDS_FILE =
    path.join(
        DATABASE_DIR,
        "records.json"
    );


const SHARES_FILE =
    path.join(
        DATABASE_DIR,
        "shares.json"
    );


const AUDIT_FILE =
    path.join(
        DATABASE_DIR,
        "audit.json"
    );


// ============================================================
// Utility: Ensure Database Files Exist
// ============================================================

function ensureDatabaseFiles() {

    if (
        !fs.existsSync(
            DATABASE_DIR
        )
    ) {

        fs.mkdirSync(

            DATABASE_DIR,

            {
                recursive: true
            }
        );
    }


    const files = [

        RECORDS_FILE,

        SHARES_FILE,

        AUDIT_FILE

    ];


    for (
        const file of files
    ) {

        if (
            !fs.existsSync(file)
        ) {

            fs.writeFileSync(

                file,

                "[]",

                "utf8"
            );
        }
    }
}


// ============================================================
// Utility: Read JSON
// ============================================================

function readJSON(
    file
) {

    ensureDatabaseFiles();


    try {

        const content =
            fs.readFileSync(

                file,

                "utf8"
            );


        if (
            !content.trim()
        ) {

            return [];
        }


        return JSON.parse(
            content
        );

    } catch (error) {

        return [];
    }
}


// ============================================================
// Utility: Write JSON
// ============================================================

function writeJSON(

    file,

    data

) {

    ensureDatabaseFiles();


    fs.writeFileSync(

        file,

        JSON.stringify(

            data,

            null,

            2
        ),

        "utf8"
    );
}


// ============================================================
// Utility: Append JSON
// ============================================================

function appendJSON(

    file,

    object

) {

    const data =
        readJSON(
            file
        );


    data.push(
        object
    );


    writeJSON(

        file,

        data
    );
}


// ============================================================
// AES-256-GCM Encryption
// ============================================================

/**
 * Alice encrypts the medical record locally.
 *
 * Encryption:
 *
 *      AES-256-GCM
 *
 * Output:
 *
 *      ciphertext
 *      IV
 *      authentication tag
 */

function encryptMedicalRecord(

    medicalRecord,

    aesKey

) {

    if (
        !Buffer.isBuffer(
            aesKey
        )
    ) {

        throw new Error(
            "AES key must be a Buffer"
        );
    }


    if (
        aesKey.length !== 32
    ) {

        throw new Error(
            "AES key must be 32 bytes"
        );
    }


    const iv =
        crypto.randomBytes(
            12
        );


    const cipher =
        crypto.createCipheriv(

            "aes-256-gcm",

            aesKey,

            iv
        );


    const plaintext =
        Buffer.from(

            typeof medicalRecord ===
            "string"

                ? medicalRecord

                : JSON.stringify(
                    medicalRecord
                ),

            "utf8"
        );


    const encrypted =
        Buffer.concat([

            cipher.update(
                plaintext
            ),

            cipher.final()

        ]);


    const authTag =
        cipher.getAuthTag();


    return {

        ciphertext:
            encrypted.toString(
                "base64"
            ),

        iv:
            iv.toString(
                "base64"
            ),

        authTag:
            authTag.toString(
                "base64"
            ),

        algorithm:
            "AES-256-GCM"
    };
}


// ============================================================
// Generate AES-256 Key
// ============================================================

function generateAESKey() {

    return crypto.randomBytes(
        32
    );
}


// ============================================================
// Generate Record ID
// ============================================================

function generateRecordId() {

    return (

        "REC-" +

        Date.now() +

        "-" +

        crypto
            .randomBytes(6)
            .toString("hex")

    );
}


// ============================================================
// Generate Consent ID
// ============================================================

function generateConsentId() {

    return (

        "CID-" +

        Date.now() +

        "-" +

        crypto
            .randomBytes(6)
            .toString("hex")

    );
}


// ============================================================
// Generate Request Reference
// ============================================================

function generateRequestReference() {

    return (

        "RID-" +

        Date.now() +

        "-" +

        crypto
            .randomBytes(6)
            .toString("hex")

    );
}


// ============================================================
// Create Consent Message
// ============================================================

/**
 * Alice's consent contains:
 *
 *      Recipient
 *      Purpose
 *      Scope
 *      Duration
 *      Record ID
 *
 * This must match Hospital Y's request.
 */

function createConsentMessage({

    consentId,

    recordId,

    hospitalAddress,

    purpose,

    scope,

    validFrom,

    validUntil

}) {

    return {

        consentId,

        recordId,

        patient:
            ALICE_ADDRESS || "",

        recipient:
            hospitalAddress,

        purpose,

        scope,

        validFrom,

        validUntil
    };
}


// ============================================================
// Canonical Consent Message
// ============================================================

/**
 * JSON canonicalization is kept deterministic so that Alice
 * and the smart-contract verification layer use the same
 * message representation.
 */

function canonicalizeConsent(

    consent

) {

    return JSON.stringify({

        consentId:
            consent.consentId,

        recordId:
            consent.recordId,

        patient:
            consent.patient,

        recipient:
            consent.recipient,

        purpose:
            consent.purpose,

        scope:
            consent.scope,

        validFrom:
            consent.validFrom,

        validUntil:
            consent.validUntil
    });
}


// ============================================================
// Hash Consent
// ============================================================

function hashConsent(

    consent

) {

    const message =
        canonicalizeConsent(
            consent
        );


    return crypto
        .createHash(
            "sha256"
        )
        .update(
            message,
            "utf8"
        )
        .digest(
            "hex"
        );
}


// ============================================================
// Sign Consent using ECDSA
// ============================================================

function signConsent(

    consent,

    privateKey

) {

    if (
        !privateKey
    ) {

        throw new Error(
            "Alice private key is required"
        );
    }


    const message =
        canonicalizeConsent(
            consent
        );


    const hash =
        crypto
            .createHash(
                "sha256"
            )
            .update(
                message,
                "utf8"
            )
            .digest();


    const signer =
        crypto.createSign(
            "SHA256"
        );


    signer.update(
        message
    );


    signer.end();


    const signature =
        signer.sign(
            privateKey,
            "base64"
        );


    return {

        messageHash:
            hash.toString(
                "hex"
            ),

        signature,

        algorithm:
            "ECDSA-SHA256"
    };
}


// ============================================================
// Generate Alice Key Pair
// ============================================================

function generateAliceKeyPair() {

    return crypto.generateKeyPairSync(

        "ec",

        {

            namedCurve:
                "secp256k1",

            publicKeyEncoding: {

                type:
                    "spki",

                format:
                    "pem"

            },

            privateKeyEncoding: {

                type:
                    "pkcs8",

                format:
                    "pem"

            }
        }
    );
}


// ============================================================
// Save Alice Key Pair
// ============================================================

function saveAliceKeyPair(

    keyPair

) {

    const aliceKeyDirectory =
        path.join(

            __dirname,

            "..",

            "keys"
        );


    if (
        !fs.existsSync(
            aliceKeyDirectory
        )
    ) {

        fs.mkdirSync(

            aliceKeyDirectory,

            {
                recursive: true
            }
        );
    }


    const privateKeyFile =
        path.join(

            aliceKeyDirectory,

            "alice_private.pem"
        );


    const publicKeyFile =
        path.join(

            aliceKeyDirectory,

            "alice_public.pem"
        );


    fs.writeFileSync(

        privateKeyFile,

        keyPair.privateKey,

        "utf8"
    );


    fs.writeFileSync(

        publicKeyFile,

        keyPair.publicKey,

        "utf8"
    );


    return {

        privateKeyFile,

        publicKeyFile
    };
}


// ============================================================
// Store Encrypted Record Locally
// ============================================================

function storeRecordMetadata(

    record

) {

    appendJSON(

        RECORDS_FILE,

        record
    );
}


// ============================================================
// Store Observer Shares
// ============================================================

/**
 * IMPORTANT:
 *
 * In a real deployment, Alice must NOT keep all observer
 * shares in the same local database.
 *
 * This local JSON file is only for the Ganache research
 * prototype.
 *
 * In production:
 *
 *      O1 -> secure storage of O1
 *      O2 -> secure storage of O2
 *      ...
 */

function storeObserverShares(

    shares,

    recordId

) {

    const entries =
        shares.map(

            share => ({

                recordId,

                observerIndex:
                    share.observerIndex,

                x:
                    share.x,

                y:
                    share.y,

                createdAt:
                    new Date()
                        .toISOString()
            })

        );


    const existing =
        readJSON(
            SHARES_FILE
        );


    writeJSON(

        SHARES_FILE,

        existing.concat(
            entries
        )
    );
}


// ============================================================
// Audit Event
// ============================================================

function audit(

    action,

    data = {}

) {

    appendJSON(

        AUDIT_FILE,

        {

            timestamp:
                new Date()
                    .toISOString(),

            actor:
                "Alice",

            action,

            data
        }
    );
}


// ============================================================
// Calculate Upload Overhead
// ============================================================

function calculateUploadOverhead({

    encryptedRecord,

    shares,

    consent

}) {

    const ciphertextBytes =
        Buffer.from(

            encryptedRecord.ciphertext,

            "base64"

        ).length;


    const ivBytes =
        Buffer.from(

            encryptedRecord.iv,

            "base64"

        ).length;


    const authTagBytes =
        Buffer.from(

            encryptedRecord.authTag,

            "base64"

        ).length;


    const consentBytes =
        Buffer.byteLength(

            JSON.stringify(
                consent
            ),

            "utf8"
        );


    const shareOverhead =
        calculateShareOverhead(
            shares
        );


    return {

        ciphertextBytes,

        ivBytes,

        authTagBytes,

        consentBytes,

        shareBytes:
            shareOverhead.totalBytes,

        totalBytes:

            ciphertextBytes
            +
            ivBytes
            +
            authTagBytes
            +
            consentBytes
            +
            shareOverhead.totalBytes
    };
}


// ============================================================
// Prepare Medical Record
// ============================================================

/**
 * Main local operation performed by Alice.
 *
 * This function does not require the blockchain.
 *
 * It prepares everything that will subsequently be submitted
 * to Chain X.
 */

async function prepareMedicalRecord({

    medicalRecord,

    hospitalAddress,

    purpose =
        "Diabetes treatment",

    scope =
        "prescription,diagnostic_images",

    durationMs =
        60 * 60 * 1000

}) {

    const totalStart =
        process.hrtime.bigint();


    // --------------------------------------------------------
    // Record ID
    // --------------------------------------------------------

    const recordId =
        generateRecordId();


    const consentId =
        generateConsentId();


    const requestReference =
        generateRequestReference();


    // --------------------------------------------------------
    // Generate AES-256 key
    // --------------------------------------------------------

    const keyStart =
        process.hrtime.bigint();


    const aesKey =
        generateAESKey();


    const keyEnd =
        process.hrtime.bigint();


    const keyGenerationLatency =

        Number(
            keyEnd -
            keyStart
        ) / 1e6;


    // --------------------------------------------------------
    // Encrypt medical record
    // --------------------------------------------------------

    const encryptionStart =
        process.hrtime.bigint();


    const encryptedRecord =
        encryptMedicalRecord(

            medicalRecord,

            aesKey
        );


    const encryptionEnd =
        process.hrtime.bigint();


    const encryptionLatency =

        Number(
            encryptionEnd -
            encryptionStart
        ) / 1e6;


    // --------------------------------------------------------
    // Generate random threshold
    // --------------------------------------------------------

    const thresholdStart =
        process.hrtime.bigint();


    const threshold =
        generateRandomThreshold(

            NUMBER_OF_OBSERVERS
        );


    const thresholdEnd =
        process.hrtime.bigint();


    const thresholdLatency =

        Number(
            thresholdEnd -
            thresholdStart
        ) / 1e6;


    // --------------------------------------------------------
    // Shamir secret sharing
    // --------------------------------------------------------

    const shamirStart =
        process.hrtime.bigint();


    const shamirResult =
        generateSharesFromAESKey(

            aesKey,

            threshold,

            NUMBER_OF_OBSERVERS
        );


    const shamirEnd =
        process.hrtime.bigint();


    const shamirLatency =

        Number(
            shamirEnd -
            shamirStart
        ) / 1e6;


    // --------------------------------------------------------
    // Consent validity
    // --------------------------------------------------------

    const validFrom =
        Date.now();


    const validUntil =
        validFrom +
        durationMs;


    const consent =
        createConsentMessage({

            consentId,

            recordId,

            hospitalAddress,

            purpose,

            scope,

            validFrom,

            validUntil
        });


    // --------------------------------------------------------
    // Consent signature
    // --------------------------------------------------------

    let consentSignature = null;


    const consentSigningStart =
        process.hrtime.bigint();


    if (
        ALICE_PRIVATE_KEY
    ) {

        consentSignature =
            signConsent(

                consent,

                ALICE_PRIVATE_KEY
            );

    } else {

        /*
         * For standalone local testing, Alice can generate a
         * temporary key pair.
         */

        const keyPair =
            generateAliceKeyPair();


        consentSignature =
            signConsent(

                consent,

                keyPair.privateKey
            );


        /*
         * The key pair is not automatically saved here.
         * Call saveAliceKeyPair() explicitly when needed.
         */
    }


    const consentSigningEnd =
        process.hrtime.bigint();


    const consentSigningLatency =

        Number(
            consentSigningEnd -
            consentSigningStart
        ) / 1e6;


    // --------------------------------------------------------
    // Hash encrypted record
    // --------------------------------------------------------

    const recordHash =
        crypto
            .createHash(
                "sha256"
            )
            .update(
                encryptedRecord.ciphertext
            )
            .digest(
                "hex"
            );


    // --------------------------------------------------------
    // Calculate communication overhead
    // --------------------------------------------------------

    const overhead =
        calculateUploadOverhead({

            encryptedRecord,

            shares: shamirResult,

            consent
        });


    // --------------------------------------------------------
    // Total latency
    // --------------------------------------------------------

    const totalEnd =
        process.hrtime.bigint();


    const totalLatency =

        Number(
            totalEnd -
            totalStart
        ) / 1e6;


    // --------------------------------------------------------
    // Result
    // --------------------------------------------------------

    const result = {

        recordId,

        consentId,

        requestReference,

        patient:
            ALICE_ADDRESS || "Alice",

        hospital:
            hospitalAddress,

        purpose,

        scope,

        threshold,

        numberOfObservers:
            NUMBER_OF_OBSERVERS,

        encryptedRecord: {

            ciphertext:
                encryptedRecord.ciphertext,

            iv:
                encryptedRecord.iv,

            authTag:
                encryptedRecord.authTag,

            algorithm:
                encryptedRecord.algorithm,

            recordHash
        },

        consent: {

            ...consent,

            messageHash:
                consentSignature.messageHash,

            signature:
                consentSignature.signature,

            signatureAlgorithm:
                consentSignature.algorithm
        },

        shares:
            shamirResult,

        metrics: {

            keyGenerationLatencyMs:
                keyGenerationLatency,

            encryptionLatencyMs:
                encryptionLatency,

            thresholdGenerationLatencyMs:
                thresholdLatency,

            shamirLatencyMs:
                shamirLatency,

            consentSigningLatencyMs:
                consentSigningLatency,

            totalLatencyMs:
                totalLatency,

            overheadBytes:
                overhead.totalBytes,

            ciphertextBytes:
                overhead.ciphertextBytes,

            shareBytes:
                overhead.shareBytes,

            consentBytes:
                overhead.consentBytes
        },

        createdAt:
            new Date()
                .toISOString()
    };


    return result;
}


// ============================================================
// Store Alice's Prepared Record
// ============================================================

function storePreparedRecord(

    result

) {

    /*
     * Store encrypted data and metadata.
     *
     * The AES key itself is deliberately NOT stored here.
     */

    storeRecordMetadata({

        recordId:
            result.recordId,

        consentId:
            result.consentId,

        hospital:
            result.hospital,

        encryptedRecord:
            result.encryptedRecord,

        threshold:
            result.threshold,

        numberOfObservers:
            result.numberOfObservers,

        createdAt:
            result.createdAt
    });


    /*
     * Prototype only.
     *
     * In a real implementation observer shares should be
     * transferred individually to the corresponding observer.
     */

    storeObserverShares(

        result.shares,

        result.recordId
    );


    audit(

        "ALICE_RECORD_PREPARED",

        {

            recordId:
                result.recordId,

            consentId:
                result.consentId,

            threshold:
                result.threshold,

            numberOfObservers:
                result.numberOfObservers,

            latencyMs:
                result.metrics.totalLatencyMs,

            overheadBytes:
                result.metrics.overheadBytes
        }
    );


    return true;
}


// ============================================================
// Complete Alice Workflow
// ============================================================

/**
 * This is the main function used by demo.js.
 */

async function createRecordAndConsent({

    medicalRecord,

    hospitalAddress,

    purpose =
        "Diabetes treatment",

    scope =
        "prescription,diagnostic_images",

    durationMs =
        60 * 60 * 1000

}) {

    const result =
        await prepareMedicalRecord({

            medicalRecord,

            hospitalAddress,

            purpose,

            scope,

            durationMs
        });


    storePreparedRecord(
        result
    );


    return result;
}


// ============================================================
// Optional Chain X Connection
// ============================================================

function createChainXWeb3() {

    return new Web3(
        CHAIN_X_RPC
    );
}


// ============================================================
// Load Contract Artifact
// ============================================================

function loadArtifact(

    contractName

) {

    /*
     * Truffle build directory.
     */

    const artifactPath =
        path.join(

            __dirname,

            "..",

            "build",

            "contracts",

            `${contractName}.json`
        );


    if (
        !fs.existsSync(
            artifactPath
        )
    ) {

        throw new Error(

            `Contract artifact not found: ` +
            `${artifactPath}`
        );
    }


    return JSON.parse(

        fs.readFileSync(

            artifactPath,

            "utf8"
        )
    );
}


// ============================================================
// Create Contract Instance
// ============================================================

function createContractInstance(

    web3,

    contractName,

    address

) {

    const artifact =
        loadArtifact(
            contractName
        );


    if (
        !address
    ) {

        address =
            artifact.networks &&
            artifact.networks[
                CHAIN_X_CHAIN_ID
            ]
                ? artifact.networks[
                    CHAIN_X_CHAIN_ID
                ].address
                : null;
    }


    if (
        !address
    ) {

        throw new Error(

            `${contractName} deployment address not found`
        );
    }


    return new web3.eth.Contract(

        artifact.abi,

        address
    );
}


// ============================================================
// Submit Medical Record to Chain X
// ============================================================

/**
 * This function is intentionally separated from the local
 * cryptographic operation.
 *
 * Alice first encrypts locally.
 *
 * Then only encrypted data / metadata goes on-chain.
 */

async function uploadRecordToChainX(

    result,

    medicalRecordContractAddress

) {

    if (
        !ALICE_PRIVATE_KEY
    ) {

        throw new Error(
            "ALICE_PRIVATE_KEY is required for blockchain upload"
        );
    }


    const web3 =
        createChainXWeb3();


    const account =
        web3.eth.accounts.privateKeyToAccount(

            ALICE_PRIVATE_KEY
        );


    web3.eth.accounts.wallet.add(
        account
    );


    const contract =
        createContractInstance(

            web3,

            "MedicalRecord",

            medicalRecordContractAddress
        );


    /*
     * Different versions of MedicalRecord.sol may expose
     * different function names.
     *
     * The code first checks the available methods.
     */

    const methods =
        contract.methods;


    const recordId =
        result.recordId;


    const ciphertext =
        result.encryptedRecord.ciphertext;


    const iv =
        result.encryptedRecord.iv;


    const authTag =
        result.encryptedRecord.authTag;


    let method;


    if (
        methods.storeRecord
    ) {

        method =
            methods.storeRecord(

                recordId,

                ciphertext,

                iv,

                authTag,

                result.threshold,

                result.numberOfObservers
            );

    } else if (
        methods.uploadRecord
    ) {

        method =
            methods.uploadRecord(

                recordId,

                ciphertext,

                iv,

                authTag
            );

    } else {

        throw new Error(

            "MedicalRecord contract does not expose " +
            "storeRecord() or uploadRecord()"
        );
    }


    const start =
        process.hrtime.bigint();


    const receipt =
        await method.send({

            from:
                account.address,

            gas:
                500000
        });


    const end =
        process.hrtime.bigint();


    const blockchainLatency =

        Number(
            end -
            start
        ) / 1e6;


    audit(

        "ALICE_RECORD_UPLOADED",

        {

            recordId,

            transactionHash:
                receipt.transactionHash,

            blockchainLatencyMs:
                blockchainLatency
        }
    );


    return {

        transactionHash:
            receipt.transactionHash,

        blockchainLatencyMs:
            blockchainLatency
    };
}


// ============================================================
// Submit Consent to Chain X
// ============================================================

async function submitConsentToChainX(

    result,

    consentManagerAddress

) {

    if (
        !ALICE_PRIVATE_KEY
    ) {

        throw new Error(
            "ALICE_PRIVATE_KEY is required"
        );
    }


    const web3 =
        createChainXWeb3();


    const account =
        web3.eth.accounts.privateKeyToAccount(

            ALICE_PRIVATE_KEY
        );


    web3.eth.accounts.wallet.add(
        account
    );


    const contract =
        createContractInstance(

            web3,

            "ConsentManager",

            consentManagerAddress
        );


    const consent =
        result.consent;


    let method;


    /*
     * Preferred function.
     */

    if (
        contract.methods.createConsent
    ) {

        method =
            contract.methods.createConsent(

                consent.consentId,

                consent.recordId,

                consent.recipient,

                consent.purpose,

                consent.scope,

                consent.validFrom,

                consent.validUntil,

                consent.signature
            );

    } else if (
        contract.methods.storeConsent
    ) {

        method =
            contract.methods.storeConsent(

                consent.consentId,

                consent.recordId,

                consent.recipient,

                consent.purpose,

                consent.scope,

                consent.validFrom,

                consent.validUntil,

                consent.signature
            );

    } else {

        throw new Error(

            "ConsentManager does not expose " +
            "createConsent() or storeConsent()"
        );
    }


    const start =
        process.hrtime.bigint();


    const receipt =
        await method.send({

            from:
                account.address,

            gas:
                500000
        });


    const end =
        process.hrtime.bigint();


    const blockchainLatency =

        Number(
            end -
            start
        ) / 1e6;


    audit(

        "ALICE_CONSENT_STORED",

        {

            consentId:
                consent.consentId,

            recordId:
                consent.recordId,

            transactionHash:
                receipt.transactionHash,

            blockchainLatencyMs:
                blockchainLatency
        }
    );


    return {

        transactionHash:
            receipt.transactionHash,

        blockchainLatencyMs:
            blockchainLatency
    };
}


// ============================================================
// Export
// ============================================================

module.exports = {

    generateAESKey,

    encryptMedicalRecord,

    generateRecordId,

    generateConsentId,

    generateRequestReference,

    createConsentMessage,

    canonicalizeConsent,

    hashConsent,

    signConsent,

    generateAliceKeyPair,

    saveAliceKeyPair,

    calculateUploadOverhead,

    prepareMedicalRecord,

    storePreparedRecord,

    createRecordAndConsent,

    uploadRecordToChainX,

    submitConsentToChainX
};


// ============================================================
// Standalone Demo
// ============================================================

if (require.main === module) {

    (async () => {

        console.log(
            "\n=================================================="
        );

        console.log(
            " ALICE - HEALTHCARE THRESHOLD CRYPTOGRAPHY"
        );

        console.log(
            "==================================================\n"
        );


        try {

            // ------------------------------------------------
            // Example medical record
            // ------------------------------------------------

            const medicalRecord = {

                patientId:
                    "ALICE-001",

                name:
                    "Alice",

                age:
                    45,

                diagnosis:
                    "Diabetes",

                prescription:
                    "Metformin 500mg",

                diagnosticImages:
                    "diabetes_scan_001.dcm",

                doctorNotes:
                    "Regular monitoring required."

            };


            // ------------------------------------------------
            // Hospital Y
            // ------------------------------------------------

            const hospitalAddress =
                process.env.HOSPITAL_ADDRESS ||
                "0x0000000000000000000000000000000000000001";


            // ------------------------------------------------
            // Create encrypted record
            // ------------------------------------------------

            const result =
                await createRecordAndConsent({

                    medicalRecord,

                    hospitalAddress,

                    purpose:
                        "Diabetes treatment",

                    scope:
                        "prescription,diagnostic_images",

                    durationMs:
                        60 * 60 * 1000

                });


            // ------------------------------------------------
            // Display non-secret information
            // ------------------------------------------------

            console.log(
                "Record ID:",
                result.recordId
            );


            console.log(
                "Consent ID:",
                result.consentId
            );


            console.log(
                "Hospital:",
                result.hospital
            );


            console.log(
                "Threshold:",
                result.threshold
            );


            console.log(
                "Observers:",
                result.numberOfObservers
            );


            console.log(
                "\nEncrypted Medical Record:"
            );


            console.log({

                algorithm:
                    result.encryptedRecord.algorithm,

                ciphertextLength:
                    result.encryptedRecord.ciphertext.length,

                recordHash:
                    result.encryptedRecord.recordHash
            });


            console.log(
                "\nObserver Shares:"
            );


            for (
                const share of result.shares
            ) {

                console.log({

                    observer:
                        share.observerIndex,

                    x:
                        share.x,

                    /*
                     * y is intentionally not printed in a real
                     * deployment because it is a secret share.
                     */

                    shareGenerated:
                        true
                });
            }


            console.log(
                "\nPerformance Metrics:"
            );


            console.table({

                keyGenerationLatencyMs:
                    result.metrics
                        .keyGenerationLatencyMs,

                encryptionLatencyMs:
                    result.metrics
                        .encryptionLatencyMs,

                thresholdGenerationLatencyMs:
                    result.metrics
                        .thresholdGenerationLatencyMs,

                shamirLatencyMs:
                    result.metrics
                        .shamirLatencyMs,

                consentSigningLatencyMs:
                    result.metrics
                        .consentSigningLatencyMs,

                totalLatencyMs:
                    result.metrics
                        .totalLatencyMs,

                overheadBytes:
                    result.metrics
                        .overheadBytes

            });


            console.log(
                "\nAlice workflow completed successfully."
            );


            console.log(
                "Encrypted record stored locally."
            );


            console.log(
                "Shamir shares generated."
            );


            console.log(
                "Consent generated and signed."
            );


            console.log(
                "Ready for Chain X submission."
            );


        } catch (error) {

            console.error(
                "\nAlice workflow failed:"
            );


            console.error(
                error.message
            );


            process.exitCode = 1;
        }

    })();
}