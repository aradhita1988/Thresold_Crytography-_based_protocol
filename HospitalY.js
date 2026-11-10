/**
 * ============================================================
 * hospital/HospitalY.js
 * ============================================================
 *
 * Hospital Y - Access Request Module
 *
 * Chain Y = Hospital Chain
 *
 * Implements:
 *
 * 1. Hospital identity
 * 2. Access request creation
 * 3. ECDSA request signing
 * 4. Request hashing
 * 5. Request submission to Chain Y
 * 6. Latency measurement
 * 7. Communication overhead measurement
 *
 * ============================================================
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const Web3 = require("web3");


// ============================================================
// Configuration
// ============================================================

let config = {};

try {

    config = require("../config");

} catch (error) {

    config = {};

}


// ============================================================
// Chain Y
// ============================================================

const CHAIN_Y_RPC =
    process.env.CHAIN_Y_RPC ||
    config.CHAIN_Y_RPC ||
    "http://127.0.0.1:7546";


const CHAIN_Y_CHAIN_ID =
    Number(
        process.env.CHAIN_Y_CHAIN_ID ||
        config.CHAIN_Y_CHAIN_ID ||
        1338
    );


// ============================================================
// Hospital Identity
// ============================================================

const HOSPITAL_ID =
    process.env.HOSPITAL_ID ||
    config.HOSPITAL_ID ||
    "HOSPITAL-Y-001";


const HOSPITAL_PRIVATE_KEY =
    process.env.HOSPITAL_PRIVATE_KEY ||
    config.HOSPITAL_PRIVATE_KEY ||
    null;


const HOSPITAL_ADDRESS =
    process.env.HOSPITAL_ADDRESS ||
    config.HOSPITAL_ADDRESS ||
    null;


// ============================================================
// Database
// ============================================================

const DATABASE_DIR =
    path.join(
        __dirname,
        "..",
        "database"
    );


const AUDIT_FILE =
    path.join(
        DATABASE_DIR,
        "audit.json"
    );


const REQUEST_FILE =
    path.join(
        DATABASE_DIR,
        "hospital_requests.json"
    );


// ============================================================
// Ensure Database
// ============================================================

function ensureDatabase() {

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


    if (
        !fs.existsSync(
            AUDIT_FILE
        )
    ) {

        fs.writeFileSync(
            AUDIT_FILE,
            "[]",
            "utf8"
        );
    }


    if (
        !fs.existsSync(
            REQUEST_FILE
        )
    ) {

        fs.writeFileSync(
            REQUEST_FILE,
            "[]",
            "utf8"
        );
    }

}


// ============================================================
// Read JSON
// ============================================================

function readJSON(file) {

    ensureDatabase();


    try {

        const data =
            fs.readFileSync(
                file,
                "utf8"
            );


        return data.trim()
            ? JSON.parse(data)
            : [];

    } catch (error) {

        return [];

    }

}


// ============================================================
// Write JSON
// ============================================================

function writeJSON(
    file,
    data
) {

    ensureDatabase();


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
// Append JSON
// ============================================================

function appendJSON(
    file,
    object
) {

    const data =
        readJSON(file);


    data.push(object);


    writeJSON(
        file,
        data
    );

}


// ============================================================
// Audit
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
                "Hospital Y",

            action,

            data

        }

    );

}


// ============================================================
// Generate Hospital Key Pair
// ============================================================

/**
 * secp256k1 is used because it is compatible with
 * Ethereum-style accounts and signatures.
 */

function generateHospitalKeyPair() {

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
// Save Hospital Key Pair
// ============================================================

function saveHospitalKeyPair(
    keyPair
) {

    const keyDirectory =
        path.join(
            __dirname,
            "..",
            "keys"
        );


    if (
        !fs.existsSync(
            keyDirectory
        )
    ) {

        fs.mkdirSync(
            keyDirectory,
            {
                recursive: true
            }
        );

    }


    const privateKeyPath =
        path.join(
            keyDirectory,
            "hospital_private.pem"
        );


    const publicKeyPath =
        path.join(
            keyDirectory,
            "hospital_public.pem"
        );


    fs.writeFileSync(
        privateKeyPath,
        keyPair.privateKey,
        "utf8"
    );


    fs.writeFileSync(
        publicKeyPath,
        keyPair.publicKey,
        "utf8"
    );


    return {

        privateKeyPath,

        publicKeyPath

    };

}


// ============================================================
// Generate Request ID
// ============================================================

function generateRequestId() {

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
// Generate Request Nonce
// ============================================================

function generateNonce() {

    return crypto
        .randomBytes(16)
        .toString("hex");

}


// ============================================================
// Create Access Request
// ============================================================

/**
 * Hospital Y sends:
 *
 *      Patient
 *      Purpose
 *      Scope
 *      Duration
 *      Record ID
 *      Request ID
 *
 */

function createAccessRequest({

    recordId,

    patientAddress,

    purpose,

    scope,

    durationMs,

    hospitalId =
        HOSPITAL_ID

}) {

    if (
        !recordId
    ) {

        throw new Error(
            "recordId is required"
        );

    }


    if (
        !patientAddress
    ) {

        throw new Error(
            "patientAddress is required"
        );

    }


    if (
        !purpose
    ) {

        throw new Error(
            "purpose is required"
        );

    }


    if (
        !scope
    ) {

        throw new Error(
            "scope is required"
        );

    }


    if (
        !Number.isFinite(
            durationMs
        )
        ||
        durationMs <= 0
    ) {

        throw new Error(
            "durationMs must be positive"
        );

    }


    const createdAt =
        Date.now();


    const expiresAt =
        createdAt +
        durationMs;


    return {

        rid:
            generateRequestId(),

        nonce:
            generateNonce(),

        hospitalId,

        hospitalAddress:
            HOSPITAL_ADDRESS || "",

        patientAddress,

        recordId,

        purpose,

        scope,

        requestedAt:
            createdAt,

        requestedUntil:
            expiresAt

    };

}


// ============================================================
// Canonical Request
// ============================================================

/**
 * Deterministic representation used for signing.
 */

function canonicalizeRequest(
    request
) {

    return JSON.stringify({

        rid:
            request.rid,

        nonce:
            request.nonce,

        hospitalId:
            request.hospitalId,

        hospitalAddress:
            request.hospitalAddress,

        patientAddress:
            request.patientAddress,

        recordId:
            request.recordId,

        purpose:
            request.purpose,

        scope:
            request.scope,

        requestedAt:
            request.requestedAt,

        requestedUntil:
            request.requestedUntil

    });

}


// ============================================================
// Hash Request
// ============================================================

function hashRequest(
    request
) {

    const canonical =
        canonicalizeRequest(
            request
        );


    return crypto
        .createHash(
            "sha256"
        )
        .update(
            canonical,
            "utf8"
        )
        .digest(
            "hex"
        );

}


// ============================================================
// Sign Request
// ============================================================

/**
 * ECDSA-SHA256 signature.
 *
 * Hospital Y signs the access request before sending it
 * to Chain Y.
 */

function signAccessRequest(
    request,
    privateKey
) {

    if (
        !privateKey
    ) {

        throw new Error(
            "Hospital private key is required"
        );

    }


    const canonical =
        canonicalizeRequest(
            request
        );


    const signer =
        crypto.createSign(
            "SHA256"
        );


    signer.update(
        canonical
    );


    signer.end();


    const signature =
        signer.sign(
            privateKey,
            "base64"
        );


    const requestHash =
        hashRequest(
            request
        );


    return {

        requestHash,

        signature,

        algorithm:
            "ECDSA-SHA256"

    };

}


// ============================================================
// Verify Request Signature
// ============================================================

function verifyAccessRequest(
    request,
    signature,
    publicKey
) {

    if (
        !publicKey
        ||
        !signature
    ) {

        return false;
    }


    const canonical =
        canonicalizeRequest(
            request
        );


    const verifier =
        crypto.createVerify(
            "SHA256"
        );


    verifier.update(
        canonical
    );


    verifier.end();


    try {

        return verifier.verify(

            publicKey,

            signature,

            "base64"

        );

    } catch (error) {

        return false;

    }

}


// ============================================================
// Calculate Request Overhead
// ============================================================

/**
 * Communication overhead is measured in bytes.
 */

function calculateRequestOverhead(
    request,
    signature
) {

    const requestBytes =
        Buffer.byteLength(

            canonicalizeRequest(
                request
            ),

            "utf8"

        );


    const signatureBytes =
        Buffer.byteLength(

            signature || "",

            "utf8"

        );


    return {

        requestBytes,

        signatureBytes,

        totalBytes:
            requestBytes +
            signatureBytes

    };

}


// ============================================================
// Prepare Signed Access Request
// ============================================================

async function prepareAccessRequest({

    recordId,

    patientAddress,

    purpose,

    scope,

    durationMs

}) {

    const start =
        process.hrtime.bigint();


    // --------------------------------------------------------
    // Create request
    // --------------------------------------------------------

    const request =
        createAccessRequest({

            recordId,

            patientAddress,

            purpose,

            scope,

            durationMs

        });


    const requestCreationEnd =
        process.hrtime.bigint();


    const requestCreationLatency =

        Number(

            requestCreationEnd -
            start

        ) / 1e6;


    // --------------------------------------------------------
    // Sign request
    // --------------------------------------------------------

    let privateKey =
        HOSPITAL_PRIVATE_KEY;


    let generatedKeyPair =
        null;


    /*
     * For local prototype testing, if no hospital private
     * key exists, generate one.
     */

    if (
        !privateKey
    ) {

        generatedKeyPair =
            generateHospitalKeyPair();


        privateKey =
            generatedKeyPair.privateKey;

    }


    const signingStart =
        process.hrtime.bigint();


    const signed =
        signAccessRequest(

            request,

            privateKey

        );


    const signingEnd =
        process.hrtime.bigint();


    const signingLatency =

        Number(

            signingEnd -
            signingStart

        ) / 1e6;


    // --------------------------------------------------------
    // Verify signature locally
    // --------------------------------------------------------

    let signatureVerified =
        false;


    if (
        generatedKeyPair
    ) {

        signatureVerified =
            verifyAccessRequest(

                request,

                signed.signature,

                generatedKeyPair.publicKey

            );

    }


    // --------------------------------------------------------
    // Overhead
    // --------------------------------------------------------

    const overhead =
        calculateRequestOverhead(

            request,

            signed.signature

        );


    // --------------------------------------------------------
    // Total latency
    // --------------------------------------------------------

    const end =
        process.hrtime.bigint();


    const totalLatency =

        Number(

            end -
            start

        ) / 1e6;


    const result = {

        request,

        signature:
            signed.signature,

        requestHash:
            signed.requestHash,

        signatureAlgorithm:
            signed.algorithm,

        signatureVerified,

        metrics: {

            requestCreationLatencyMs:
                requestCreationLatency,

            signingLatencyMs:
                signingLatency,

            totalLatencyMs:
                totalLatency,

            requestBytes:
                overhead.requestBytes,

            signatureBytes:
                overhead.signatureBytes,

            overheadBytes:
                overhead.totalBytes

        },

        createdAt:
            new Date()
                .toISOString()

    };


    return result;

}


// ============================================================
// Store Request Locally
// ============================================================

function storeRequest(
    result
) {

    appendJSON(

        REQUEST_FILE,

        {

            rid:
                result.request.rid,

            hospitalId:
                result.request.hospitalId,

            hospitalAddress:
                result.request.hospitalAddress,

            patientAddress:
                result.request.patientAddress,

            recordId:
                result.request.recordId,

            purpose:
                result.request.purpose,

            scope:
                result.request.scope,

            requestedAt:
                result.request.requestedAt,

            requestedUntil:
                result.request.requestedUntil,

            requestHash:
                result.requestHash,

            signature:
                result.signature,

            signatureAlgorithm:
                result.signatureAlgorithm,

            metrics:
                result.metrics

        }

    );


    audit(

        "HOSPITAL_REQUEST_CREATED",

        {

            rid:
                result.request.rid,

            recordId:
                result.request.recordId,

            patient:
                result.request.patientAddress,

            purpose:
                result.request.purpose,

            scope:
                result.request.scope,

            latencyMs:
                result.metrics.totalLatencyMs,

            overheadBytes:
                result.metrics.overheadBytes

        }

    );


    return true;

}


// ============================================================
// Connect to Chain Y
// ============================================================

function createChainYWeb3() {

    return new Web3(
        CHAIN_Y_RPC
    );

}


// ============================================================
// Load HospitalRequest Artifact
// ============================================================

function loadHospitalRequestArtifact() {

    const artifactPath =
        path.join(

            __dirname,

            "..",

            "build",

            "contracts",

            "HospitalRequest.json"

        );


    if (
        !fs.existsSync(
            artifactPath
        )
    ) {

        throw new Error(

            "HospitalRequest.json not found at " +
            artifactPath

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
// Get HospitalRequest Contract
// ============================================================

function getHospitalRequestContract(

    web3,

    contractAddress = null

) {

    const artifact =
        loadHospitalRequestArtifact();


    let address =
        contractAddress;


    if (
        !address
        &&
        artifact.networks
    ) {

        const network =
            artifact.networks[
                CHAIN_Y_CHAIN_ID
            ];


        if (network) {

            address =
                network.address;

        }

    }


    if (
        !address
    ) {

        throw new Error(

            "HospitalRequest contract address not found"

        );

    }


    return new web3.eth.Contract(

        artifact.abi,

        address

    );

}


// ============================================================
// Submit Request to Chain Y
// ============================================================

/**
 * Sends Hospital Y's signed request to HospitalRequest.sol.
 *
 * The exact smart-contract method depends on the contract
 * generated in your project.
 */

async function submitRequestToChainY(

    result,

    contractAddress = null

) {

    if (
        !HOSPITAL_PRIVATE_KEY
    ) {

        throw new Error(

            "HOSPITAL_PRIVATE_KEY is required for " +
            "blockchain submission"

        );

    }


    const web3 =
        createChainYWeb3();


    const account =
        web3.eth.accounts.privateKeyToAccount(

            HOSPITAL_PRIVATE_KEY

        );


    web3.eth.accounts.wallet.add(
        account
    );


    const contract =
        getHospitalRequestContract(

            web3,

            contractAddress

        );


    const request =
        result.request;


    let method;


    /*
     * Preferred function:
     *
     * submitRequest(
     *      rid,
     *      patient,
     *      recordId,
     *      purpose,
     *      scope,
     *      duration,
     *      signature
     * )
     */


    if (
        contract.methods.submitRequest
    ) {

        method =
            contract.methods.submitRequest(

                request.rid,

                request.patientAddress,

                request.recordId,

                request.purpose,

                request.scope,

                request.requestedUntil,

                result.signature

            );

    }

    else if (
        contract.methods.createRequest
    ) {

        method =
            contract.methods.createRequest(

                request.rid,

                request.patientAddress,

                request.recordId,

                request.purpose,

                request.scope,

                request.requestedUntil,

                result.signature

            );

    }

    else {

        throw new Error(

            "HospitalRequest.sol does not expose " +
            "submitRequest() or createRequest()"

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

        "HOSPITAL_REQUEST_SUBMITTED",

        {

            rid:
                request.rid,

            transactionHash:
                receipt.transactionHash,

            blockchainLatencyMs:
                blockchainLatency

        }

    );


    return {

        rid:
            request.rid,

        transactionHash:
            receipt.transactionHash,

        blockchainLatencyMs:
            blockchainLatency

    };

}


// ============================================================
// Complete Hospital Request Workflow
// ============================================================

async function createAndSubmitRequest({

    recordId,

    patientAddress,

    purpose,

    scope,

    durationMs,

    contractAddress = null

}) {

    const result =
        await prepareAccessRequest({

            recordId,

            patientAddress,

            purpose,

            scope,

            durationMs

        });


    storeRequest(
        result
    );


    /*
     * Blockchain submission is performed only when the
     * hospital private key is configured.
     */

    let blockchainResult =
        null;


    if (
        HOSPITAL_PRIVATE_KEY
    ) {

        blockchainResult =
            await submitRequestToChainY(

                result,

                contractAddress

            );

    }


    return {

        ...result,

        blockchain:
            blockchainResult

    };

}


// ============================================================
// Request Status
// ============================================================

function isRequestExpired(
    request
) {

    return (

        Date.now()
        >
        Number(
            request.requestedUntil
        )

    );

}


// ============================================================
// Get Remaining Request Duration
// ============================================================

function getRemainingRequestTime(
    request
) {

    return Math.max(

        0,

        Number(
            request.requestedUntil
        )
        -
        Date.now()

    );

}


// ============================================================
// Export
// ============================================================

module.exports = {

    generateHospitalKeyPair,

    saveHospitalKeyPair,

    generateRequestId,

    generateNonce,

    createAccessRequest,

    canonicalizeRequest,

    hashRequest,

    signAccessRequest,

    verifyAccessRequest,

    calculateRequestOverhead,

    prepareAccessRequest,

    storeRequest,

    createChainYWeb3,

    getHospitalRequestContract,

    submitRequestToChainY,

    createAndSubmitRequest,

    isRequestExpired,

    getRemainingRequestTime

};


// ============================================================
// Standalone Demonstration
// ============================================================

if (
    require.main === module
) {

    (async () => {

        console.log(
            "\n=================================================="
        );

        console.log(
            " HOSPITAL Y - ACCESS REQUEST"
        );

        console.log(
            "==================================================\n"
        );


        try {

            // ------------------------------------------------
            // Example patient
            // ------------------------------------------------

            const patientAddress =
                process.env.PATIENT_ADDRESS ||

                "0x0000000000000000000000000000000000000002";


            // ------------------------------------------------
            // Example encrypted record
            // ------------------------------------------------

            const recordId =
                process.env.RECORD_ID ||

                "REC-DEMO-001";


            // ------------------------------------------------
            // Create request
            // ------------------------------------------------

            const result =
                await prepareAccessRequest({

                    recordId,

                    patientAddress,

                    purpose:
                        "Diabetes treatment",

                    scope:
                        "prescription,diagnostic_images",

                    durationMs:
                        30 * 60 * 1000

                });


            // ------------------------------------------------
            // Display request
            // ------------------------------------------------

            console.log(
                "Request ID:",
                result.request.rid
            );


            console.log(
                "Hospital ID:",
                result.request.hospitalId
            );


            console.log(
                "Patient:",
                result.request.patientAddress
            );


            console.log(
                "Record:",
                result.request.recordId
            );


            console.log(
                "Purpose:",
                result.request.purpose
            );


            console.log(
                "Scope:",
                result.request.scope
            );


            console.log(
                "Request Hash:",
                result.requestHash
            );


            console.log(
                "\nSignature:"
            );


            console.log(
                result.signature
            );


            // ------------------------------------------------
            // Performance
            // ------------------------------------------------

            console.log(
                "\nPerformance Metrics:"
            );


            console.table({

                requestCreationLatencyMs:
                    result.metrics
                        .requestCreationLatencyMs,

                signingLatencyMs:
                    result.metrics
                        .signingLatencyMs,

                totalLatencyMs:
                    result.metrics
                        .totalLatencyMs,

                requestBytes:
                    result.metrics
                        .requestBytes,

                signatureBytes:
                    result.metrics
                        .signatureBytes,

                overheadBytes:
                    result.metrics
                        .overheadBytes

            });


            // ------------------------------------------------
            // Store request
            // ------------------------------------------------

            storeRequest(
                result
            );


            console.log(
                "\nHospital request stored."
            );


            console.log(
                "Ready for Chain Y submission."
            );


        } catch (error) {

            console.error(
                "\nHospital request failed:"
            );


            console.error(
                error.message
            );


            process.exitCode = 1;

        }

    })();

}