//Complete Threshold Attack-Detection JavaScript Code
//Source file: test_demo_with_attack_detection.js
//The complete code is included below. Preserve the code order when copying it into your project.
/**
 * ============================================================
 * test/demo.js
 * ============================================================
 *
 * HEALTHCARE CROSS-CHAIN OBSERVER + THRESHOLD CRYPTOGRAPHY
 * EXPERIMENTAL EVALUATION
 *
 * Chains:
 *   Chain X : Alice / Patient side
 *   Chain Y : Hospital side
 *
 * Cryptography:
 *   AES-256-GCM
 *   Shamir Secret Sharing
 *   Lagrange Interpolation
 *   SHA-256 Session Key
 *
 * Experiments:
 *
 *   Observer configurations:
 *
 *       2-of-3
 *       3-of-5
 *       4-of-7
 *       6-of-10
 *
 *   Executions:
 *       100 per configuration per attack mode
 *
 *   Modes:
 *       NORMAL
 *       GRIEFING
 *
 * Metrics:
 *
 *   Normal:
 *       - Detection Latency
 *       - Reconstruction Latency
 *       - Access Latency
 *       - Total Execution Time
 *       - Communication Overhead
 *
 *   Griefing:
 *       - Griefing Detection Latency
 *       - Reconstruction Failure
 *       - Access Delay
 *       - Withheld Shares
 *       - Invalid Shares
 *       - Threshold Failure Rate
 *
 * Output:
 *
 *   results/raw-results.json
 *   results/average-results.json
 *   results/experiment-results.csv
 *
 * ============================================================
 */
 
"use strict";
 
const Web3 = require("web3");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
 
 
// ============================================================
// GANACHE CONFIGURATION
// ============================================================
 
const CHAIN_X_URL =
    process.env.CHAIN_X_URL ||
    "http://127.0.0.1:7545";
 
const CHAIN_Y_URL =
    process.env.CHAIN_Y_URL ||
    "http://127.0.0.1:7546";
 
 
// ============================================================
// WEB3
// ============================================================
 
const web3X =
    new Web3(CHAIN_X_URL);
 
const web3Y =
    new Web3(CHAIN_Y_URL);
 
 
// ============================================================
// EXPERIMENT CONFIGURATION
// ============================================================
 
/*
 * Change this to 30 or 50 while debugging.
 *
 * For final experimental results:
 *
 *     NUM_EXECUTIONS = 100
 */
const NUM_EXECUTIONS = 20;
 
// Cumulative checkpoints used for the attack-detection chart.
const DETECTION_CHART_CHECKPOINTS = [5, 10, 15, 20];
 
 
/*
 * Observer configurations.
 *
 * t-of-n threshold configurations.
 */
const OBSERVER_CONFIGURATIONS = [
 
    {
        observers: 3,
        threshold: 2
    },
 
    {
        observers: 5,
        threshold: 3
    },
 
    {
        observers: 7,
        threshold: 4
    }
 
    
 
];
 
 
// ============================================================
// ATTACK CONFIGURATION
// ============================================================
 
/*
 * For each configuration, the number of malicious observers
 * is selected as:
 *
 *     n - t + 1
 *
 * Therefore, if all malicious observers fail to provide
 * valid shares, the system falls below the threshold.
 *
 * Examples:
 *
 *   2-of-3  -> 2 malicious
 *   3-of-5  -> 3 malicious
 *   4-of-7  -> 4 malicious
 *   6-of-10 -> 5 malicious
 *
 * Among malicious observers:
 *
 *   half withhold shares
 *   half submit invalid shares
 *
 * This allows BOTH attack behaviours to be measured.
 */
function getMaliciousCount(
    n,
    t
) {
 
    return (
        n - t + 1
    );
 
}
 
 
// ============================================================
// CRYPTOGRAPHIC PRIME
// ============================================================
 
/*
 * Mersenne prime:
 *
 *     P = 2^521 - 1
 *
 * This is safely larger than a 256-bit AES key.
 *
 * IMPORTANT:
 *
 * The previous 61-bit prime:
 *
 *     2305843009213693951
 *
 * cannot represent an entire AES-256 key.
 */
const PRIME =
    (1n << 521n) - 1n;
 
 
// ============================================================
// OUTPUT DIRECTORY
// ============================================================
 
const RESULTS_DIR =
    path.join(
        __dirname,
        "..",
        "results"
    );
 
 
function ensureResultsDirectory() {
 
    if (
        !fs.existsSync(
            RESULTS_DIR
        )
    ) {
 
        fs.mkdirSync(
            RESULTS_DIR,
            {
                recursive: true
            }
        );
 
    }
 
}
 
 
// ============================================================
// UTILITY
// ============================================================
 
function elapsedMs(
    start
) {
 
    return (
 
        Number(
            process.hrtime.bigint() -
            start
        ) / 1e6
 
    );
 
}
 
 
function sleep(
    ms
) {
 
    return new Promise(
        resolve =>
            setTimeout(
                resolve,
                ms
            )
    );
 
}
 
 
function calculateBytes(
    object
) {
 
    return Buffer.byteLength(
 
        JSON.stringify(
            object
        ),
 
        "utf8"
 
    );
 
}
 
 
function randomId(
    prefix
) {
 
    return (
 
        prefix +
        "-" +
        Date.now() +
        "-" +
        crypto
            .randomBytes(4)
            .toString("hex")
 
    );
 
}
 
 
// ============================================================
// MODULAR ARITHMETIC
// ============================================================
 
function mod(
    value,
    prime = PRIME
) {
 
    const result =
        value % prime;
 
    return (
        result >= 0n
            ? result
            : result + prime
    );
 
}
 
 
// ============================================================
// MODULAR INVERSE
// ============================================================
 
function modInverse(
    value,
    prime = PRIME
) {
 
    let a =
        mod(
            value,
            prime
        );
 
    let b =
        prime;
 
    let x0 =
        1n;
 
    let x1 =
        0n;
 
 
    while (
        b !== 0n
    ) {
 
        const quotient =
            a / b;
 
 
        [
            a,
            b
        ] = [
 
            b,
 
            a -
            quotient * b
 
        ];
 
 
        [
            x0,
            x1
        ] = [
 
            x1,
 
            x0 -
            quotient * x1
 
        ];
 
    }
 
 
    if (
        a !== 1n
    ) {
 
        throw new Error(
            "Modular inverse does not exist."
        );
 
    }
 
 
    return mod(
        x0,
        prime
    );
 
}
 
 
// ============================================================
// RANDOM FIELD ELEMENT
// ============================================================
 
function randomFieldElement() {
 
    /*
     * 66 random bytes give enough entropy for
     * the 521-bit field.
     */
    const bytes =
        crypto.randomBytes(66);
 
 
    return (
 
        BigInt(
            "0x" +
            bytes.toString("hex")
        ) % PRIME
 
    );
 
}
 
 
// ============================================================
// AES-256-GCM ENCRYPTION
// ============================================================
 
function encryptMedicalRecord(
    medicalRecord
) {
 
    const key =
        crypto.randomBytes(32);
 
    const iv =
        crypto.randomBytes(12);
 
 
    const cipher =
        crypto.createCipheriv(
            "aes-256-gcm",
            key,
            iv
        );
 
 
    const plaintext =
        JSON.stringify(
            medicalRecord
        );
 
 
    let ciphertext =
        cipher.update(
            plaintext,
            "utf8",
            "hex"
        );
 
 
    ciphertext +=
        cipher.final(
            "hex"
        );
 
 
    const authTag =
        cipher
            .getAuthTag();
 
 
    return {
 
        algorithm:
            "AES-256-GCM",
 
        ciphertext,
 
        iv:
            iv.toString("hex"),
 
        authTag:
            authTag.toString("hex"),
 
        /*
         * This key is never printed.
         *
         * It is the actual data encryption key
         * that is divided using Shamir.
         */
        key:
            key.toString("hex")
 
    };
 
}
 
 
// ============================================================
// AES-256-GCM DECRYPTION
// ============================================================
 
function decryptMedicalRecord(
    encryptedRecord,
    keyHex
) {
 
    const key =
        Buffer.from(
            keyHex,
            "hex"
        );
 
 
    const iv =
        Buffer.from(
            encryptedRecord.iv,
            "hex"
        );
 
 
    const authTag =
        Buffer.from(
            encryptedRecord.authTag,
            "hex"
        );
 
 
    const decipher =
        crypto.createDecipheriv(
            "aes-256-gcm",
            key,
            iv
        );
 
 
    decipher.setAuthTag(
        authTag
    );
 
 
    let plaintext =
        decipher.update(
            encryptedRecord.ciphertext,
            "hex",
            "utf8"
        );
 
 
    plaintext +=
        decipher.final(
            "utf8"
        );
 
 
    return JSON.parse(
        plaintext
    );
 
}
 
 
// ============================================================
// SECRET CONVERSION
// ============================================================
 
function secretHexToBigInt(
    secretHex
) {
 
    return BigInt(
        "0x" +
        secretHex
    );
 
}
 
 
function bigIntToSecretHex(
    secret
) {
 
    return (
 
        secret
            .toString(16)
            .padStart(64, "0")
 
    );
 
}
 
 
// ============================================================
// SHAMIR SECRET SHARING
// ============================================================
 
function generateShamirShares(
    secretHex,
    threshold,
    totalObservers
) {
 
    const secret =
        secretHexToBigInt(
            secretHex
        );
 
 
    if (
        secret >= PRIME
    ) {
 
        throw new Error(
            "Secret is larger than Shamir field."
        );
 
    }
 
 
    /*
     * Polynomial:
     *
     * f(x) =
     *   a0 +
     *   a1*x +
     *   a2*x^2 + ...
     *
     * where:
     *
     *   a0 = secret
     */
    const coefficients = [
 
        secret
 
    ];
 
 
    for (
        let i = 1;
        i < threshold;
        i++
    ) {
 
        coefficients.push(
            randomFieldElement()
        );
 
    }
 
 
    const shares = [];
 
 
    for (
        let x = 1;
        x <= totalObservers;
        x++
    ) {
 
        let y =
            coefficients[0];
 
 
        for (
            let degree = 1;
            degree < coefficients.length;
            degree++
        ) {
 
            const xValue =
                BigInt(x);
 
 
            const xPower =
                xValue **
                BigInt(degree);
 
 
            y =
 
                mod(
 
                    y +
                    coefficients[degree] *
                    xPower,
 
                    PRIME
 
                );
 
        }
 
 
        shares.push({
 
            x,
 
            y:
                y.toString(),
 
            observerId:
                `O${x}`
 
        });
 
    }
 
 
    return shares;
 
}
 
 
// ============================================================
// LAGRANGE RECONSTRUCTION
// ============================================================
 
function reconstructSecret(
    shares
) {
 
    if (
        shares.length === 0
    ) {
 
        throw new Error(
            "No shares supplied."
        );
 
    }
 
 
    let secret =
        0n;
 
 
    for (
        let i = 0;
        i < shares.length;
        i++
    ) {
 
        const xi =
            BigInt(
                shares[i].x
            );
 
 
        const yi =
            BigInt(
                shares[i].y
            );
 
 
        let lambda =
            1n;
 
 
        for (
            let j = 0;
            j < shares.length;
            j++
        ) {
 
            if (
                i === j
            ) {
 
                continue;
 
            }
 
 
            const xj =
                BigInt(
                    shares[j].x
                );
 
 
            const numerator =
                mod(
                    -xj
                );
 
 
            const denominator =
                mod(
                    xi -
                    xj
                );
 
 
            const inverse =
                modInverse(
                    denominator
                );
 
 
            lambda =
 
                mod(
 
                    lambda *
                    numerator *
                    inverse
 
                );
 
        }
 
 
        secret =
 
            mod(
 
                secret +
                yi *
                lambda
 
            );
 
    }
 
 
    return secret;
 
}
 
 
// ============================================================
// SESSION KEY
// ============================================================
 
function generateSessionKey(
    reconstructedSecret,
    rid,
    cid
) {
 
    /*
     * The reconstructed AES key is NOT directly printed.
     *
     * A separate session key is derived from:
     *
     *   reconstructed secret
     *   RID
     *   CID
     */
    return crypto
        .createHash("sha256")
        .update(
            reconstructedSecret +
            ":" +
            rid +
            ":" +
            cid
        )
        .digest("hex");
 
}
 
 
// ============================================================
// MEDICAL RECORD
// ============================================================
 
function generateMedicalRecord() {
 
    return {
 
        patientName:
            "Alice",
 
        patientId:
            "PATIENT-001",
 
        disease:
            "Diabetes",
 
        prescription:
            "Metformin",
 
        diagnosticImages:
            "MRI_HASH_REFERENCE",
 
        timestamp:
            new Date()
                .toISOString()
 
    };
 
}
 
 
// ============================================================
// HOSPITAL REQUEST
// ============================================================
 
function createHospitalRequest(
    hospital,
    rid
) {
 
    const request = {
 
        rid,
 
        hospital,
 
        patient:
            "Alice",
 
        purpose:
            "diabetes treatment",
 
        scope: [
 
            "prescription",
 
            "diagnostic-images"
 
        ],
 
        duration:
            60,
 
        timestamp:
            new Date()
                .toISOString()
 
    };
 
 
    request.requestHash =
        crypto
            .createHash("sha256")
            .update(
                JSON.stringify(
                    request
                )
            )
            .digest("hex");
 
 
    return request;
 
}
 
 
// ============================================================
// CONSENT
// ============================================================
 
function createConsent(
    alice,
    hospital,
    cid
) {
 
    const validFrom =
        new Date();
 
 
    const validUntil =
        new Date(
            Date.now() +
            60 * 60 * 1000
        );
 
 
    const consent = {
 
        cid,
 
        patient:
            alice,
 
        recipient:
            hospital,
 
        purpose:
            "diabetes treatment",
 
        scope: [
 
            "prescription",
 
            "diagnostic-images"
 
        ],
 
        duration:
            60,
 
        validFrom:
            validFrom.toISOString(),
 
        validUntil:
            validUntil.toISOString()
 
    };
 
 
    consent.consentHash =
        crypto
            .createHash("sha256")
            .update(
                JSON.stringify(
                    consent
                )
            )
            .digest("hex");
 
 
    return consent;
 
}
 
 
// ============================================================
// BRIDGE VALIDATION
// ============================================================
 
function validateCrossChainRequest(
    request,
    consent,
    hospital
) {
 
    const start =
        process.hrtime.bigint();
 
 
    const errors = [];
 
 
    if (
        request.hospital !==
        hospital
    ) {
 
        errors.push(
            "Hospital identity mismatch."
        );
 
    }
 
 
    if (
        request.rid === undefined
    ) {
 
        errors.push(
            "RID missing."
        );
 
    }
 
 
    if (
        consent.recipient !==
        hospital
    ) {
 
        errors.push(
            "Consent recipient mismatch."
        );
 
    }
 
 
    if (
        request.purpose !==
        consent.purpose
    ) {
 
        errors.push(
            "Purpose mismatch."
        );
 
    }
 
 
    const requestScope =
        JSON.stringify(
            request.scope
        );
 
 
    const consentScope =
        JSON.stringify(
            consent.scope
        );
 
 
    if (
        requestScope !==
        consentScope
    ) {
 
        errors.push(
            "Scope mismatch."
        );
 
    }
 
 
    const valid =
        errors.length === 0;
 
 
    const detectionLatencyMs =
        elapsedMs(
            start
        );
 
 
    return {
 
        valid,
 
        errors,
 
        detectionLatencyMs
 
    };
 
}
 
 
// ============================================================
// NORMAL OBSERVER APPROVAL
// ============================================================
 
function normalObserverApproval(
    observers
) {
 
    const approvals = [];
 
 
    const start =
        process.hrtime.bigint();
 
 
    for (
        let i = 0;
        i < observers.length;
        i++
    ) {
 
        approvals.push({
 
            observerId:
                observers[i].observerId,
 
            address:
                observers[i].address,
 
            approved:
                true,
 
            timestamp:
                new Date()
                    .toISOString()
 
        });
 
    }
 
 
    return {
 
        approvals,
 
        approvalLatencyMs:
            elapsedMs(start)
 
    };
 
}
 
 
// ============================================================
// GRIEFING OBSERVER APPROVAL
// ============================================================
 
function griefingObserverApproval(
    observers,
    threshold
) {
 
    const approvals = [];
 
 
    const maliciousCount =
        getMaliciousCount(
            observers.length,
            threshold
        );
 
 
    /*
     * Malicious observers:
     *
     * approve the request but later:
     *
     *   - withhold some shares
     *   - submit invalid shares
     *
     * This represents a griefing behaviour where
     * observers consume protocol resources/participate
     * in approval but prevent successful reconstruction.
     */
 
    const maliciousObservers =
        observers.slice(
            0,
            maliciousCount
        );
 
 
    const honestObservers =
        observers.slice(
            maliciousCount
        );
 
 
    for (
        const observer of maliciousObservers
    ) {
 
        approvals.push({
 
            observerId:
                observer.observerId,
 
            address:
                observer.address,
 
            approved:
                true,
 
            malicious:
                true,
 
            timestamp:
                new Date()
                    .toISOString()
 
        });
 
    }
 
 
    for (
        const observer of honestObservers
    ) {
 
        approvals.push({
 
            observerId:
                observer.observerId,
 
            address:
                observer.address,
 
            approved:
                true,
 
            malicious:
                false,
 
            timestamp:
                new Date()
                    .toISOString()
 
        });
 
    }
 
 
    return {
 
        approvals,
 
        maliciousCount
 
    };
 
}
 
 
// ============================================================
// NORMAL SHARE SUBMISSION
// ============================================================
 
function normalShareSubmission(
    approvals,
    shares
) {
 
    const submittedShares = [];
 
 
    const start =
        process.hrtime.bigint();
 
 
    for (
        const approval of approvals
    ) {
 
        if (
            !approval.approved
        ) {
 
            continue;
 
        }
 
 
        const share =
            shares.find(
                item =>
                    item.observerId ===
                    approval.observerId
            );
 
 
        if (
            !share
        ) {
 
            continue;
 
        }
 
 
        submittedShares.push({
 
            rid:
                share.rid,
 
            observerId:
                share.observerId,
 
            x:
                share.x,
 
            y:
                share.y,
 
            valid:
                true,
 
            timestamp:
                new Date()
                    .toISOString()
 
        });
 
    }
 
 
    return {
 
        submittedShares,
 
        submissionLatencyMs:
            elapsedMs(start),
 
        withheldShares:
            0,
 
        invalidShares:
            0
 
    };
 
}
 
 
// ============================================================
// GRIEFING SHARE SUBMISSION
// ============================================================
 
function griefingShareSubmission(
    approvals,
    shares
) {
 
    const submittedShares = [];
 
 
    let withheldShares =
        0;
 
    let invalidShares =
        0;
 
 
    const malicious =
        approvals.filter(
            approval =>
                approval.malicious ===
                true
        );
 
 
    const honest =
        approvals.filter(
            approval =>
                approval.malicious !==
                true
        );
 
 
    /*
     * Split malicious observers:
     *
     * first half -> withhold
     * second half -> invalid
     */
    const numberWithholding =
        Math.floor(
            malicious.length / 2
        );
 
 
    const withholdingObservers =
        malicious.slice(
            0,
            numberWithholding
        );
 
 
    const invalidObservers =
        malicious.slice(
            numberWithholding
        );
 
 
    const start =
        process.hrtime.bigint();
 
 
    // --------------------------------------------------------
    // Honest observers submit valid shares
    // --------------------------------------------------------
 
    for (
        const approval of honest
    ) {
 
        const share =
            shares.find(
                item =>
                    item.observerId ===
                    approval.observerId
            );
 
 
        if (
            share
        ) {
 
            submittedShares.push({
 
                rid:
                    share.rid,
 
                observerId:
                    share.observerId,
 
                x:
                    share.x,
 
                y:
                    share.y,
 
                valid:
                    true,
 
                malicious:
                    false,
 
                timestamp:
                    new Date()
                        .toISOString()
 
            });
 
        }
 
    }
 
 
    // --------------------------------------------------------
    // Malicious observers withhold shares
    // --------------------------------------------------------
 
    for (
        const approval of withholdingObservers
    ) {
 
        withheldShares++;
 
        /*
         * No share is submitted.
         */
 
    }
 
 
    // --------------------------------------------------------
    // Malicious observers submit invalid shares
    // --------------------------------------------------------
 
    for (
        const approval of invalidObservers
    ) {
 
        const originalShare =
            shares.find(
                item =>
                    item.observerId ===
                    approval.observerId
            );
 
 
        if (
            originalShare
        ) {
 
            /*
             * Modify y while preserving the same x.
             *
             * This makes the share invalid with respect
             * to the original polynomial.
             */
            const invalidY =
 
                mod(
 
                    BigInt(
                        originalShare.y
                    ) +
                    123456789n
 
                );
 
 
            submittedShares.push({
 
                rid:
                    originalShare.rid,
 
                observerId:
                    originalShare.observerId,
 
                x:
                    originalShare.x,
 
                y:
                    invalidY.toString(),
 
                valid:
                    false,
 
                malicious:
                    true,
 
                timestamp:
                    new Date()
                        .toISOString()
 
            });
 
 
            invalidShares++;
 
        }
 
    }
 
 
    return {
 
        submittedShares,
 
        submissionLatencyMs:
            elapsedMs(start),
 
        withheldShares,
 
        invalidShares
 
    };
 
}
 
 
// ============================================================
// VALIDATE SHARES
// ============================================================
 
function validateSubmittedShares(
    submittedShares,
    originalShares
) {
 
    const start =
        process.hrtime.bigint();
 
 
    const validShares = [];
 
    const invalidShares = [];
 
 
    for (
        const submitted of submittedShares
    ) {
 
        const original =
            originalShares.find(
                share =>
                    share.observerId ===
                    submitted.observerId
            );
 
 
        if (
            !original
        ) {
 
            invalidShares.push(
                submitted
            );
 
            continue;
 
        }
 
 
        if (
            submitted.x !==
            original.x
        ) {
 
            invalidShares.push(
                submitted
            );
 
            continue;
 
        }
 
 
        if (
            BigInt(
                submitted.y
            ) !==
            BigInt(
                original.y
            )
        ) {
 
            invalidShares.push(
                submitted
            );
 
            continue;
 
        }
 
 
        validShares.push(
            submitted
        );
 
    }
 
 
    return {
 
        validShares,
 
        invalidShares,
 
        validationLatencyMs:
            elapsedMs(start)
 
    };
 
}
 
 
// ============================================================
// RECONSTRUCTION
// ============================================================
 
function performReconstruction(
    validShares,
    threshold,
    originalSecretHex
) {
 
    const start =
        process.hrtime.bigint();
 
 
    /*
     * Threshold condition.
     */
    if (
        validShares.length <
        threshold
    ) {
 
        return {
 
            success:
                false,
 
            secret:
                null,
 
            reconstructionLatencyMs:
                elapsedMs(start)
 
        };
 
    }
 
 
    /*
     * Exactly threshold shares are sufficient.
     *
     * Using exactly t shares also gives a consistent
     * experimental reconstruction workload.
     */
    const selectedShares =
        validShares.slice(
            0,
            threshold
        );
 
 
    let reconstructed;
 
 
    try {
 
        reconstructed =
            reconstructSecret(
                selectedShares
            );
 
    } catch (
        error
    ) {
 
        return {
 
            success:
                false,
 
            secret:
                null,
 
            reconstructionLatencyMs:
                elapsedMs(start),
 
            error:
                error.message
 
        };
 
    }
 
 
    const reconstructedHex =
        bigIntToSecretHex(
            reconstructed
        );
 
 
    /*
     * VERY IMPORTANT:
     *
     * Reconstruction is considered successful only
     * when the reconstructed secret is exactly equal
     * to the original AES-256 key.
     */
    const success =
        reconstructedHex.toLowerCase() ===
        originalSecretHex.toLowerCase();
 
 
    return {
 
        success,
 
        secret:
            success
                ? reconstructedHex
                : null,
 
        reconstructionLatencyMs:
            elapsedMs(start)
 
    };
 
}
 
 
// ============================================================
// AUTHORIZATION
// ============================================================
 
function authorizeAccess(
    consent,
    request,
    reconstruction,
    thresholdReached,
    rid,
    cid
) {
 
    const start =
        process.hrtime.bigint();
 
 
    if (
        !thresholdReached
    ) {
 
        return {
 
            authorized:
                false,
 
            reason:
                "Observer threshold not reached.",
 
            authorizationLatencyMs:
                elapsedMs(start)
 
        };
 
    }
 
 
    if (
        !reconstruction.success
    ) {
 
        return {
 
            authorized:
                false,
 
            reason:
                "Secret reconstruction failed.",
 
            authorizationLatencyMs:
                elapsedMs(start)
 
        };
 
    }
 
 
    if (
        consent.recipient !==
        request.hospital
    ) {
 
        return {
 
            authorized:
                false,
 
            reason:
                "Consent recipient mismatch.",
 
            authorizationLatencyMs:
                elapsedMs(start)
 
        };
 
    }
 
 
    const sessionKey =
        generateSessionKey(
            reconstruction.secret,
            rid,
            cid
        );
 
 
    return {
 
        authorized:
            true,
 
        sessionKeyGenerated:
            Boolean(sessionKey),
 
        expiresAt:
            consent.validUntil,
 
        authorizationLatencyMs:
            elapsedMs(start)
 
    };
 
}
 
 
// ============================================================
// COMMUNICATION OVERHEAD
// ============================================================
 
function calculateCommunicationOverhead(
    request,
    consent,
    approvals,
    submittedShares
) {
 
    const requestBytes =
        calculateBytes(
            request
        );
 
 
    const consentBytes =
        calculateBytes(
            consent
        );
 
 
    const approvalBytes =
        calculateBytes(
            approvals
        );
 
 
    const shareBytes =
        calculateBytes(
            submittedShares
        );
 
 
    /*
     * Session key itself is NOT transmitted.
     *
     * It is derived locally after reconstruction.
     *
     * Therefore it should NOT be counted as network
     * communication overhead.
     */
    const totalBytes =
 
        requestBytes +
        consentBytes +
        approvalBytes +
        shareBytes;
 
 
    return {
 
        requestBytes,
 
        consentBytes,
 
        approvalBytes,
 
        shareBytes,
 
        totalBytes
 
    };
 
}
 
 
// ============================================================
// CREATE OBSERVERS
// ============================================================
 
function createObservers(
    accounts,
    n
) {
 
    return accounts
        .slice(
            1,
            n + 1
        )
        .map(
            (
                address,
                index
            ) => ({
 
                observerId:
                    `O${index + 1}`,
 
                address
 
            })
        );
 
}
 
 
// ============================================================
// CREATE EXPERIMENT DATA
// ============================================================
 
function createExperimentData(
    alice,
    hospital
) {
 
    const rid =
        randomId(
            "RID"
        );
 
 
    const cid =
        randomId(
            "CID"
        );
 
 
    const recordId =
        randomId(
            "REC"
        );
 
 
    const medicalRecord =
        generateMedicalRecord();
 
 
    const encryptedRecord =
        encryptMedicalRecord(
            medicalRecord
        );
 
 
    const secretHex =
        encryptedRecord.key;
 
 
    const request =
        createHospitalRequest(
            hospital,
            rid
        );
 
 
    const consent =
        createConsent(
            alice,
            hospital,
            cid
        );
 
 
    return {
 
        rid,
 
        cid,
 
        recordId,
 
        medicalRecord,
 
        encryptedRecord,
 
        secretHex,
 
        request,
 
        consent
 
    };
 
}
 
 
// ============================================================
// VERIFY ENCRYPTION
// ============================================================
 
function verifyEncryption(
    encryptedRecord,
    secretHex,
    originalRecord
) {
 
    try {
 
        const decrypted =
            decryptMedicalRecord(
                encryptedRecord,
                secretHex
            );
 
 
        return (
 
            JSON.stringify(
                decrypted
            ) ===
            JSON.stringify(
                originalRecord
            )
 
        );
 
    } catch (
        error
    ) {
 
        return false;
 
    }
 
}
 
 
// ============================================================
// RUN NORMAL EXECUTION
// ============================================================
 
async function runNormalExperiment(
    config,
    accounts,
    iteration
) {
 
    const n =
        config.observers;
 
 
    const t =
        config.threshold;
 
 
    const observers =
        createObservers(
            accounts.chainX,
            n
        );
 
 
    const experiment =
        createExperimentData(
            accounts.alice,
            accounts.hospital
        );
 
 
    const totalStart =
        process.hrtime.bigint();
 
 
    /*
     * Verify that encryption/decryption works before
     * sharing the AES key.
     */
    const encryptionVerified =
        verifyEncryption(
            experiment.encryptedRecord,
            experiment.secretHex,
            experiment.medicalRecord
        );
 
 
    if (
        !encryptionVerified
    ) {
 
        throw new Error(
            "AES encryption/decryption verification failed."
        );
 
    }
 
 
    /*
     * Shamir generation.
     */
    const shares =
        generateShamirShares(
            experiment.secretHex,
            t,
            n
        );
 
 
    /*
     * Hospital request + consent -> bridge.
     */
    const bridge =
        validateCrossChainRequest(
            experiment.request,
            experiment.consent,
            accounts.hospital
        );
 
 
    if (
        !bridge.valid
    ) {
 
        throw new Error(
            "Bridge validation failed."
        );
 
    }
 
 
    /*
     * Observer approval.
     */
    const approval =
        normalObserverApproval(
            observers
        );
 
 
    const approvalCount =
        approval.approvals.filter(
            item =>
                item.approved
        ).length;
 
 
    const thresholdReached =
        approvalCount >= t;
 
 
    /*
     * Share submission.
     */
    const submission =
        normalShareSubmission(
            approval.approvals,
            shares
        );
 
 
    /*
     * Share validation.
     */
    const validation =
        validateSubmittedShares(
            submission.submittedShares,
            shares
        );
 
 
    /*
     * Reconstruction.
     */
    const reconstruction =
        performReconstruction(
            validation.validShares,
            t,
            experiment.secretHex
        );
 
 
    /*
     * Authorization.
     */
    const authorization =
        authorizeAccess(
            experiment.consent,
            experiment.request,
            reconstruction,
            thresholdReached,
            experiment.rid,
            experiment.cid
        );
 
 
    /*
     * Communication overhead.
     */
    const overhead =
        calculateCommunicationOverhead(
            experiment.request,
            experiment.consent,
            approval.approvals,
            submission.submittedShares
        );
 
 
    const totalExecutionTimeMs =
        elapsedMs(
            totalStart
        );
 
 
    /*
     * Access latency:
     *
     * Bridge detection
     * +
     * Observer approval
     * +
     * Share submission
     * +
     * Share validation
     * +
     * Reconstruction
     * +
     * Authorization
     *
     * This is much more complete than:
     *
     * detection + reconstruction
     */
    const accessLatencyMs =
 
        bridge.detectionLatencyMs +
 
        approval.approvalLatencyMs +
 
        submission.submissionLatencyMs +
 
        validation.validationLatencyMs +
 
        reconstruction.reconstructionLatencyMs +
 
        authorization.authorizationLatencyMs;
 
 
    return {
 
        mode:
            "NORMAL",
 
        iteration,
 
        observers:
            n,
 
        threshold:
            t,
 
        rid:
            experiment.rid,
 
        cid:
            experiment.cid,
 
        approvalCount,
 
        validShares:
            validation.validShares.length,
 
        invalidShares:
            0,
 
        withheldShares:
            0,
 
        thresholdReached,
 
        reconstructionSuccess:
            reconstruction.success,
 
        authorized:
            authorization.authorized,
 
        detectionLatencyMs:
            bridge.detectionLatencyMs,
 
        reconstructionLatencyMs:
            reconstruction.reconstructionLatencyMs,
 
        accessLatencyMs,
 
        totalExecutionTimeMs,
 
        communicationOverheadBytes:
            overhead.totalBytes,
 
        griefingDetectionLatencyMs:
            0,
 
        reconstructionFailure:
            0,
 
        accessDelayMs:
            0,
 
        encryptionVerified
 
    };
 
}
 
 
// ============================================================
// RUN GRIEFING EXECUTION
// ============================================================
 
async function runGriefingExperiment(
    config,
    accounts,
    iteration,
    normalResult
) {
 
    const totalStart =
        process.hrtime.bigint();
 
 
    const n =
        config.observers;
 
 
    const t =
        config.threshold;
 
 
    const observers =
        createObservers(
            accounts.chainX,
            n
        );
 
 
    const experiment =
        createExperimentData(
            accounts.alice,
            accounts.hospital
        );
 
 
    const encryptionVerified =
        verifyEncryption(
            experiment.encryptedRecord,
            experiment.secretHex,
            experiment.medicalRecord
        );
 
 
    if (
        !encryptionVerified
    ) {
 
        throw new Error(
            "AES encryption/decryption verification failed."
        );
 
    }
 
 
    /*
     * Generate valid Shamir shares.
     */
    const shares =
        generateShamirShares(
            experiment.secretHex,
            t,
            n
        );
 
 
    /*
     * Bridge validation.
     */
    const bridge =
        validateCrossChainRequest(
            experiment.request,
            experiment.consent,
            accounts.hospital
        );
 
 
    if (
        !bridge.valid
    ) {
 
        throw new Error(
            "Bridge validation failed."
        );
 
    }
 
 
    /*
     * Malicious observers approve the request.
     */
    const approval =
        griefingObserverApproval(
            observers,
            t
        );
 
 
    const approvalCount =
        approval.approvals.filter(
            item =>
                item.approved
        ).length;
 
 
    const thresholdReached =
        approvalCount >= t;
 
 
    /*
     * Griefing occurs during share submission.
     */
    const submission =
        griefingShareSubmission(
            approval.approvals,
            shares
        );
 
 
    /*
     * Validate shares.
     *
     * Invalid shares are detected here.
     */
    const validationStart =
        process.hrtime.bigint();
 
 
    const validation =
        validateSubmittedShares(
            submission.submittedShares,
            shares
        );
 
 
    const griefingDetectionLatencyMs =
        elapsedMs(
            validationStart
        );
 
 
    /*
     * Reconstruction.
     *
     * Only valid shares are allowed.
     */
    const reconstruction =
        performReconstruction(
            validation.validShares,
            t,
            experiment.secretHex
        );
 
 
    /*
     * Authorization.
     *
     * Should fail if reconstruction fails.
     */
    const authorization =
        authorizeAccess(
            experiment.consent,
            experiment.request,
            reconstruction,
            thresholdReached,
            experiment.rid,
            experiment.cid
        );
 
 
    /*
     * Communication overhead.
     */
    const overhead =
        calculateCommunicationOverhead(
            experiment.request,
            experiment.consent,
            approval.approvals,
            submission.submittedShares
        );
 
 
    const totalExecutionTimeMs =
        elapsedMs(
            totalStart
        );
 
 
    /*
     * Access latency.
     *
     * If authorization succeeds, use the complete
     * protocol latency.
     *
     * If authorization fails, use the time until
     * the failure is detected.
     */
    const accessLatencyMs =
 
        bridge.detectionLatencyMs +
 
        approval.approvalLatencyMs +
 
        submission.submissionLatencyMs +
 
        validation.validationLatencyMs +
 
        reconstruction.reconstructionLatencyMs +
 
        authorization.authorizationLatencyMs;
 
 
    /*
     * Paired access delay:
     *
     * Griefing execution - corresponding normal execution.
     *
     * This gives a more meaningful attack delay metric.
     */
    const accessDelayMs =
 
        Math.max(
            0,
            accessLatencyMs -
            normalResult.accessLatencyMs
        );
 
 
    /*
     * Reconstruction failure:
     *
     * 1 = failed
     * 0 = successful
     */
    const reconstructionFailure =
 
        reconstruction.success
            ? 0
            : 1;
 
 
    return {
 
        mode:
            "GRIEFING",
 
        iteration,
 
        observers:
            n,
 
        threshold:
            t,
 
        rid:
            experiment.rid,
 
        cid:
            experiment.cid,
 
        approvalCount,
 
        validShares:
            validation.validShares.length,
 
        invalidShares:
            submission.invalidShares,
 
        withheldShares:
            submission.withheldShares,
 
        thresholdReached,
 
        reconstructionSuccess:
            reconstruction.success,
 
        authorized:
            authorization.authorized,
 
        detectionLatencyMs:
            bridge.detectionLatencyMs,
 
        griefingDetectionLatencyMs,
 
        reconstructionLatencyMs:
            reconstruction.reconstructionLatencyMs,
 
        accessLatencyMs,
 
        accessDelayMs,
 
        totalExecutionTimeMs,
 
        communicationOverheadBytes:
            overhead.totalBytes,
 
        reconstructionFailure,
 
        // Detection outcome for charting:
        // true when invalid shares are rejected by validation, or the
        // available valid shares fall below the required threshold.
        attackDetected:
            validation.invalidShares.length > 0 ||
            validation.validShares.length < t,
 
        // Prevention outcome is recorded separately from detection.
        attackPrevented:
            authorization.authorized === false,
 
        invalidSharesDetected:
            validation.invalidShares.length,
 
        encryptionVerified
 
    };
 
}
 
 
// ============================================================
// AVERAGE
// ============================================================
 
function average(
    values
) {
 
    if (
        values.length === 0
    ) {
 
        return 0;
 
    }
 
 
    return (
 
        values.reduce(
            (
                sum,
                value
            ) =>
                sum + Number(value),
            0
        ) /
        values.length
 
    );
 
}
 
 
// ============================================================
// ROUND
// ============================================================
 
function round(
    value,
    decimals = 3
) {
 
    return Number(
        Number(value)
            .toFixed(decimals)
    );
 
}
 
 
// ============================================================
// AGGREGATE NORMAL RESULTS
// ============================================================
 
function aggregateNormalResults(
    results
) {
 
    return {
 
        mode:
            "NORMAL",
 
        observers:
            results[0].observers,
 
        threshold:
            results[0].threshold,
 
        executions:
            results.length,
 
        avgDetectionLatencyMs:
            round(
                average(
                    results.map(
                        r =>
                            r.detectionLatencyMs
                    )
                )
            ),
 
        avgReconstructionLatencyMs:
            round(
                average(
                    results.map(
                        r =>
                            r.reconstructionLatencyMs
                    )
                )
            ),
 
        avgAccessLatencyMs:
            round(
                average(
                    results.map(
                        r =>
                            r.accessLatencyMs
                    )
                )
            ),
 
        avgTotalExecutionTimeMs:
            round(
                average(
                    results.map(
                        r =>
                            r.totalExecutionTimeMs
                    )
                )
            ),
 
        avgCommunicationOverheadBytes:
            round(
                average(
                    results.map(
                        r =>
                            r.communicationOverheadBytes
                    )
                )
            ),
 
        reconstructionFailureRate:
            round(
                average(
                    results.map(
                        r =>
                            r.reconstructionFailure
                    )
                ) * 100
            ),
 
        authorizedRate:
            round(
                average(
                    results.map(
                        r =>
                            r.authorized
                                ? 1
                                : 0
                    )
                ) * 100
            )
 
    };
 
}
 
 
// ============================================================
// AGGREGATE GRIEFING RESULTS
// ============================================================
 
function aggregateGriefingResults(
    results
) {
 
    return {
 
        mode:
            "GRIEFING",
 
        observers:
            results[0].observers,
 
        threshold:
            results[0].threshold,
 
        executions:
            results.length,
 
        avgDetectionLatencyMs:
            round(
                average(
                    results.map(
                        r =>
                            r.detectionLatencyMs
                    )
                )
            ),
 
        avgGriefingDetectionLatencyMs:
            round(
                average(
                    results.map(
                        r =>
                            r.griefingDetectionLatencyMs
                    )
                )
            ),
 
        avgReconstructionLatencyMs:
            round(
                average(
                    results.map(
                        r =>
                            r.reconstructionLatencyMs
                    )
                )
            ),
 
        avgAccessLatencyMs:
            round(
                average(
                    results.map(
                        r =>
                            r.accessLatencyMs
                    )
                )
            ),
 
        avgAccessDelayMs:
            round(
                average(
                    results.map(
                        r =>
                            r.accessDelayMs
                    )
                )
            ),
 
        avgTotalExecutionTimeMs:
            round(
                average(
                    results.map(
                        r =>
                            r.totalExecutionTimeMs
                    )
                )
            ),
 
        avgCommunicationOverheadBytes:
            round(
                average(
                    results.map(
                        r =>
                            r.communicationOverheadBytes
                    )
                )
            ),
 
        avgWithheldShares:
            round(
                average(
                    results.map(
                        r =>
                            r.withheldShares
                    )
                )
            ),
 
        avgInvalidShares:
            round(
                average(
                    results.map(
                        r =>
                            r.invalidShares
                    )
                )
            ),
 
        reconstructionFailureRate:
            round(
                average(
                    results.map(
                        r =>
                            r.reconstructionFailure
                    )
                ) * 100
            ),
 
        thresholdFailureRate:
            round(
                average(
                    results.map(
                        r =>
                            r.validShares <
                            r.threshold
                                ? 1
                                : 0
                    )
                ) * 100
            ),
 
        authorizedRate:
            round(
                average(
                    results.map(
                        r =>
                            r.authorized
                                ? 1
                                : 0
                    )
                ) * 100
            )
 
    };
 
}
 
 
// ============================================================
// PRINT CONFIGURATION SUMMARY
// ============================================================
 
function printConfigurationHeader(
    config
) {
 
    console.log(
        "\n============================================================"
    );
 
    console.log(
        ` OBSERVERS = ${config.observers} | ` +
        `THRESHOLD = ${config.threshold}-of-${config.observers}`
    );
 
    console.log(
        "============================================================"
    );
 
}
 
 
// ============================================================
// PRINT AGGREGATE RESULT
// ============================================================
 
function printAggregate(
    normal,
    griefing
) {
 
    console.log(
        "\nNORMAL"
    );
 
    console.log(
        "------------------------------------------------------------"
    );
 
    console.log(
        "Executions:",
        normal.executions
    );
 
    console.log(
        "Average Detection Latency:",
        normal.avgDetectionLatencyMs,
        "ms"
    );
 
    console.log(
        "Average Reconstruction Latency:",
        normal.avgReconstructionLatencyMs,
        "ms"
    );
 
    console.log(
        "Average Access Latency:",
        normal.avgAccessLatencyMs,
        "ms"
    );
 
    console.log(
        "Average Total Execution Time:",
        normal.avgTotalExecutionTimeMs,
        "ms"
    );
 
    console.log(
        "Average Communication Overhead:",
        normal.avgCommunicationOverheadBytes,
        "bytes"
    );
 
    console.log(
        "Reconstruction Failure Rate:",
        normal.reconstructionFailureRate,
        "%"
    );
 
 
    console.log(
        "\nGRIEFING ATTACK"
    );
 
    console.log(
        "------------------------------------------------------------"
    );
 
    console.log(
        "Executions:",
        griefing.executions
    );
 
    console.log(
        "Average Detection Latency:",
        griefing.avgDetectionLatencyMs,
        "ms"
    );
 
    console.log(
        "Average Griefing Detection Latency:",
        griefing.avgGriefingDetectionLatencyMs,
        "ms"
    );
 
    console.log(
        "Average Reconstruction Latency:",
        griefing.avgReconstructionLatencyMs,
        "ms"
    );
 
    console.log(
        "Average Access Latency:",
        griefing.avgAccessLatencyMs,
        "ms"
    );
 
    console.log(
        "Average Access Delay:",
        griefing.avgAccessDelayMs,
        "ms"
    );
 
    console.log(
        "Average Total Execution Time:",
        griefing.avgTotalExecutionTimeMs,
        "ms"
    );
 
    console.log(
        "Average Communication Overhead:",
        griefing.avgCommunicationOverheadBytes,
        "bytes"
    );
 
    console.log(
        "Average Withheld Shares:",
        griefing.avgWithheldShares
    );
 
    console.log(
        "Average Invalid Shares:",
        griefing.avgInvalidShares
    );
 
    console.log(
        "Reconstruction Failure Rate:",
        griefing.reconstructionFailureRate,
        "%"
    );
 
    console.log(
        "Threshold Failure Rate:",
        griefing.thresholdFailureRate,
        "%"
    );
 
    console.log(
        "Authorization Success Rate:",
        griefing.authorizedRate,
        "%"
    );
 
}
 
 
// ============================================================
// CSV ESCAPE
// ============================================================
 
function csvEscape(
    value
) {
 
    const stringValue =
        String(value);
 
 
    if (
        stringValue.includes(",") ||
        stringValue.includes("\"") ||
        stringValue.includes("\n")
    ) {
 
        return (
 
            "\"" +
            stringValue.replace(
                /"/g,
                "\"\""
            ) +
            "\""
 
        );
 
    }
 
 
    return stringValue;
 
}
 
 
// ============================================================
// SAVE RAW RESULTS
// ============================================================
 
function saveRawResults(
    rawResults
) {
 
    ensureResultsDirectory();
 
 
    const file =
        path.join(
            RESULTS_DIR,
            "raw-results.json"
        );
 
 
    fs.writeFileSync(
 
        file,
 
        JSON.stringify(
            rawResults,
            null,
            2
        ),
 
        "utf8"
 
    );
 
 
    console.log(
        "\nRaw results saved to:",
        file
    );
 
}
 
 
// ============================================================
// SAVE AVERAGE RESULTS
// ============================================================
 
function saveAverageResults(
    averages
) {
 
    ensureResultsDirectory();
 
 
    const file =
        path.join(
            RESULTS_DIR,
            "average-results.json"
        );
 
 
    fs.writeFileSync(
 
        file,
 
        JSON.stringify(
            averages,
            null,
            2
        ),
 
        "utf8"
 
    );
 
 
    console.log(
        "Average results saved to:",
        file
    );
 
}
 
 
// ============================================================
// SAVE CSV
// ============================================================
 
function saveCSV(
    averages
) {
 
    ensureResultsDirectory();
 
 
    const file =
        path.join(
            RESULTS_DIR,
            "experiment-results.csv"
        );
 
 
    const headers = [
 
        "Observers",
 
        "Threshold",
 
        "Attack",
 
        "Executions",
 
        "Avg Detection Latency (ms)",
 
        "Avg Griefing Detection Latency (ms)",
 
        "Avg Reconstruction Latency (ms)",
 
        "Avg Access Latency (ms)",
 
        "Avg Access Delay (ms)",
 
        "Avg Total Execution Time (ms)",
 
        "Avg Communication Overhead (bytes)",
 
        "Avg Withheld Shares",
 
        "Avg Invalid Shares",
 
        "Reconstruction Failure Rate (%)",
 
        "Threshold Failure Rate (%)",
 
        "Authorization Success Rate (%)"
 
    ];
 
 
    const rows = [
 
        headers
 
    ];
 
 
    for (
        const result of averages
    ) {
 
        rows.push([
 
            result.observers,
 
            result.threshold,
 
            result.mode,
 
            result.executions,
 
            result.avgDetectionLatencyMs,
 
            result.avgGriefingDetectionLatencyMs ??
                0,
 
            result.avgReconstructionLatencyMs,
 
            result.avgAccessLatencyMs,
 
            result.avgAccessDelayMs ??
                0,
 
            result.avgTotalExecutionTimeMs,
 
            result.avgCommunicationOverheadBytes,
 
            result.avgWithheldShares ??
                0,
 
            result.avgInvalidShares ??
                0,
 
            result.reconstructionFailureRate,
 
            result.thresholdFailureRate ??
                0,
 
            result.authorizedRate
 
        ]);
 
    }
 
 
    const csv =
 
        rows
            .map(
                row =>
                    row
                        .map(
                            csvEscape
                        )
                        .join(",")
            )
            .join("\n");
 
 
    fs.writeFileSync(
        file,
        csv,
        "utf8"
    );
 
 
    console.log(
        "CSV results saved to:",
        file
    );
 
}
 
 
// ============================================================
// PRINT FINAL COMPARISON TABLE
// ============================================================
 
function printFinalComparison(
    averages
) {
 
    console.log(
        "\n\n============================================================"
    );
 
    console.log(
        "                 FINAL EXPERIMENTAL RESULTS"
    );
 
    console.log(
        "============================================================\n"
    );
 
 
    const header =
 
        "Observers | Threshold | Attack    | " +
        "Detection | Recon. | Access | Total | Overhead";
 
 
    console.log(
        header
    );
 
 
    console.log(
        "-".repeat(
            header.length
        )
    );
 
 
    for (
        const result of averages
    ) {
 
        const detection =
 
            result.mode === "GRIEFING"
 
                ? result.avgGriefingDetectionLatencyMs
 
                : result.avgDetectionLatencyMs;
 
 
        console.log(
 
            String(
                result.observers
            ).padEnd(9) +
 
            " | " +
 
            String(
                result.threshold
            ).padEnd(9) +
 
            " | " +
 
            String(
                result.mode
            ).padEnd(9) +
 
            " | " +
 
            String(
                detection
            ).padEnd(9) +
 
            " | " +
 
            String(
                result.avgReconstructionLatencyMs
            ).padEnd(6) +
 
            " | " +
 
            String(
                result.avgAccessLatencyMs
            ).padEnd(6) +
 
            " | " +
 
            String(
                result.avgTotalExecutionTimeMs
            ).padEnd(5) +
 
            " | " +
 
            String(
                result.avgCommunicationOverheadBytes
            )
 
        );
 
    }
 
 
    console.log(
        "\n\n============================================================"
    );
 
    console.log(
        "             GRIEFING ATTACK ANALYSIS"
    );
 
    console.log(
        "============================================================\n"
    );
 
 
    const attackHeader =
 
        "Observers | Threshold | " +
        "Grief Detect | Failure | " +
        "Access Delay | Withheld | Invalid | Threshold Failure";
 
 
    console.log(
        attackHeader
    );
 
 
    console.log(
        "-".repeat(
            attackHeader.length
        )
    );
 
 
    for (
        const result of averages
    ) {
 
        if (
            result.mode !==
            "GRIEFING"
        ) {
 
            continue;
 
        }
 
 
        console.log(
 
            String(
                result.observers
            ).padEnd(9) +
 
            " | " +
 
            String(
                result.threshold
            ).padEnd(9) +
 
            " | " +
 
            String(
                result.avgGriefingDetectionLatencyMs
            ).padEnd(12) +
 
            " | " +
 
            String(
                result.reconstructionFailureRate
            ).padEnd(7) +
 
            " | " +
 
            String(
                result.avgAccessDelayMs
            ).padEnd(12) +
 
            " | " +
 
            String(
                result.avgWithheldShares
            ).padEnd(8) +
 
            " | " +
 
            String(
                result.avgInvalidShares
            ).padEnd(7) +
 
            " | " +
 
            String(
                result.thresholdFailureRate
            ) +
 
            "%"
 
        );
 
    }
 
}
 
 
// ============================================================
// MAIN EXPERIMENT
// ============================================================
 
async function main() {
 
    console.log(
        "\n============================================================"
    );
 
    console.log(
        " HEALTHCARE CROSS-CHAIN EXPERIMENT"
    );
 
    console.log(
        " OBSERVER + THRESHOLD CRYPTOGRAPHY"
    );
 
    console.log(
        "============================================================\n"
    );
 
 
    console.log(
        "Executions per configuration:",
        NUM_EXECUTIONS
    );
 
 
    console.log(
        "\nObserver configurations:"
    );
 
 
    OBSERVER_CONFIGURATIONS.forEach(
        config => {
 
            console.log(
 
                `  ${config.threshold}-of-${config.observers}`
 
            );
 
        }
    );
 
 
    // ========================================================
    // CONNECT BLOCKCHAINS
    // ========================================================
 
    console.log(
        "\nConnecting to Chain X..."
    );
 
 
    const chainXId =
        await web3X.eth.getChainId();
 
 
    console.log(
        "Chain X Chain ID:",
        chainXId
    );
 
 
    console.log(
        "Connecting to Chain Y..."
    );
 
 
    const chainYId =
        await web3Y.eth.getChainId();
 
 
    console.log(
        "Chain Y Chain ID:",
        chainYId
    );
 
 
    // ========================================================
    // LOAD ACCOUNTS
    // ========================================================
 
    const accountsX =
        await web3X.eth.getAccounts();
 
 
    const accountsY =
        await web3Y.eth.getAccounts();
 
 
    /*
     * Need:
     *
     *   Alice = 1 account
     *   Observers = maximum 10
     *
     * Therefore Chain X needs at least 11 accounts.
     */
 
    const MAX_OBSERVERS = Math.max(
    ...OBSERVER_CONFIGURATIONS.map(c => c.observers)
);
 
const REQUIRED_ACCOUNTS = 1 + MAX_OBSERVERS;
    if (accountsX.length < REQUIRED_ACCOUNTS) {
    throw new Error(
        `Chain X requires at least ${REQUIRED_ACCOUNTS} accounts ` +
        `(1 Alice + ${MAX_OBSERVERS} observers). ` +
        `Currently available: ${accountsX.length}`
    );
}
 
 
    if (
        accountsY.length <
        1
    ) {
 
        throw new Error(
            "Chain Y requires at least 1 hospital account."
        );
 
    }
 
 
    const accounts = {
 
        chainX:
            accountsX,
 
        chainY:
            accountsY,
 
        alice:
            accountsX[0],
 
        hospital:
            accountsY[0]
 
    };
 
 
    console.log(
        "\nAlice:",
        accounts.alice
    );
 
 
    console.log(
        "Hospital Y:",
        accounts.hospital
    );
 
 
    console.log(
        "Available Chain X accounts:",
        accountsX.length
    );
 
 
    // ========================================================
    // RAW RESULTS
    // ========================================================
 
    const rawResults = [];
 
    // Cumulative detection counts at 5, 10, 15 and 20 attack executions.
    const attackDetectionChartRows = [];
 
    const averages = [];
 
 
    // ========================================================
    // CONFIGURATION LOOP
    // ========================================================
 
    for (
        const config of OBSERVER_CONFIGURATIONS
    ) {
 
        printConfigurationHeader(
            config
        );
 
 
        const normalResults = [];
 
        const griefingResults = [];
 
 
        // ====================================================
        // EXECUTION LOOP
        // ====================================================
 
        for (
            let iteration = 1;
            iteration <= NUM_EXECUTIONS;
            iteration++
        ) {
 
            /*
             * Run NORMAL.
             */
            const normal =
                await runNormalExperiment(
                    config,
                    accounts,
                    iteration
                );
 
 
            /*
             * Run GRIEFING using a separate experiment
             * instance but paired with this normal run.
             */
            const griefing =
                await runGriefingExperiment(
                    config,
                    accounts,
                    iteration,
                    normal
                );
 
 
            normalResults.push(
                normal
            );
 
 
            griefingResults.push(
                griefing
            );
 
 
            rawResults.push(
                normal
            );
 
 
            rawResults.push(
                griefing
            );
 
 
            /*
             * Progress.
             */
            if (
                iteration === 1 ||
                iteration % 10 === 0 ||
                iteration === NUM_EXECUTIONS
            ) {
 
                console.log(
 
                    `Execution ${iteration}/${NUM_EXECUTIONS} ` +
                    `completed | ` +
                    `Normal access=${normal.accessLatencyMs.toFixed(3)} ms | ` +
                    `Griefing failure=${griefing.reconstructionFailure}`
 
                );
 
            }
 
        }
 
 
        // ====================================================
        // ATTACK-DETECTION CHART COUNTS
        // ====================================================
        for (const checkpoint of DETECTION_CHART_CHECKPOINTS) {
 
            const subset = griefingResults.slice(0, checkpoint);
            const attacksLaunched = subset.length;
            const attacksDetected = subset.filter(
                result => result.attackDetected === true
            ).length;
            const attacksNotDetected = attacksLaunched - attacksDetected;
 
            attackDetectionChartRows.push({
                method: "Threshold Cryptography",
                configuration: `${config.threshold}-of-${config.observers}`,
                attacks_launched: attacksLaunched,
                attacks_detected: attacksDetected,
                attacks_not_detected: attacksNotDetected,
                detection_rate_percent: attacksLaunched > 0
                    ? Number((attacksDetected / attacksLaunched * 100).toFixed(2))
                    : 0
            });
        }
 
 
        // ====================================================
        // AGGREGATION
        // ====================================================
 
        const normalAverage =
            aggregateNormalResults(
                normalResults
            );
 
 
        const griefingAverage =
            aggregateGriefingResults(
                griefingResults
            );
 
 
        averages.push(
            normalAverage
        );
 
 
        averages.push(
            griefingAverage
        );
 
 
        // ====================================================
        // PRINT
        // ====================================================
 
        printAggregate(
            normalAverage,
            griefingAverage
        );
 
    }
 
 
    // ========================================================
    // SAVE
    // ========================================================
 
    saveRawResults(
        rawResults
    );
 
 
    saveAverageResults(
        averages
    );
 
 
    saveCSV(
        averages
    );
 
 
    // Save threshold attack-detection counts for charting.
    ensureResultsDirectory();
    const detectionChartJsonPath = path.join(
        RESULTS_DIR,
        "threshold-attack-detection-chart.json"
    );
    fs.writeFileSync(
        detectionChartJsonPath,
        JSON.stringify(attackDetectionChartRows, null, 2),
        "utf8"
    );
 
    const detectionChartHeaders = [
        "method",
        "configuration",
        "attacks_launched",
        "attacks_detected",
        "attacks_not_detected",
        "detection_rate_percent"
    ];
    const detectionChartCsvRows = attackDetectionChartRows.map(row =>
        detectionChartHeaders.map(header => csvEscape(row[header] ?? "")).join(",")
    );
    const detectionChartCsvPath = path.join(
        RESULTS_DIR,
        "threshold-attack-detection-chart.csv"
    );
    fs.writeFileSync(
        detectionChartCsvPath,
        [detectionChartHeaders.join(","), ...detectionChartCsvRows].join("\n"),
        "utf8"
    );
 
    console.log("Attack-detection chart CSV saved to:", detectionChartCsvPath);
    console.log("Attack-detection chart JSON saved to:", detectionChartJsonPath);
    console.log("\nThreshold attack-detection chart data:");
    console.table(attackDetectionChartRows);
 
 
    // ========================================================
    // FINAL TABLE
    // ========================================================
 
    printFinalComparison(
        averages
    );
 
 
    // ========================================================
    // EXPERIMENT COMPLETED
    // ========================================================
 
    console.log(
        "\n============================================================"
    );
 
    console.log(
        " EXPERIMENT COMPLETED SUCCESSFULLY"
    );
 
    console.log(
        "============================================================"
    );
 
 
    console.log(
        "\nTotal configurations:",
        OBSERVER_CONFIGURATIONS.length
    );
 
 
    console.log(
        "Executions per configuration:",
        NUM_EXECUTIONS
    );
 
 
    console.log(
        "Modes:",
        "NORMAL + GRIEFING"
    );
 
 
    console.log(
        "Total protocol executions:",
        OBSERVER_CONFIGURATIONS.length *
        NUM_EXECUTIONS *
        2
    );
 
 
    console.log(
        "\nResults directory:",
        RESULTS_DIR
    );
 
}
 
 
// ============================================================
// ERROR HANDLER
// ============================================================
 
main()
 
    .catch(
        error => {
 
            console.error(
                "\n============================================================"
            );
 
            console.error(
                " EXPERIMENT FAILED"
            );
 
            console.error(
                "============================================================"
            );
 
 
            console.error(
                error.message
            );
 
 
            if (
                error.stack
            ) {
 
                console.error(
                    error.stack
                );
 
            }
 
 
            process.exit(
                1
            );
 
        }
    );