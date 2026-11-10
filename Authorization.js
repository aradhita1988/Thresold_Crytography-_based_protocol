

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { performance } = require("perf_hooks");

const lagrange = require("../crypto/lagrange");
const sessionKey = require("../crypto/sessionKey");

const SHARES_FILE = path.join(
    __dirname,
    "../database/shares.json"
);

const OBSERVERS_FILE = path.join(
    __dirname,
    "../database/observers.json"
);

const AUDIT_FILE = path.join(
    __dirname,
    "../database/audit.json"
);

const RECORDS_FILE = path.join(
    __dirname,
    "../database/records.json"
);


// ---------------------------------------------------------
// Utility functions
// ---------------------------------------------------------

function readJSON(file) {
    if (!fs.existsSync(file)) {
        return {};
    }

    const data = fs.readFileSync(file, "utf8");

    if (!data.trim()) {
        return {};
    }

    return JSON.parse(data);
}


function writeJSON(file, data) {
    fs.writeFileSync(
        file,
        JSON.stringify(data, null, 2)
    );
}


function appendAudit(event) {

    const database = readJSON(AUDIT_FILE);

    if (!database.audit) {
        database.audit = [];
    }

    database.audit.push(event);

    writeJSON(AUDIT_FILE, database);
}


// ---------------------------------------------------------
// Observer validation
// ---------------------------------------------------------

function getValidObservers() {

    const database = readJSON(OBSERVERS_FILE);

    if (!database.observers) {
        return [];
    }

    return database.observers.filter(
        observer =>
            observer.registered === true &&
            observer.active !== false
    );
}


// ---------------------------------------------------------
// Retrieve submitted Shamir shares
// ---------------------------------------------------------

function getSubmittedShares(rid) {

    const database = readJSON(SHARES_FILE);

    if (!database.shares) {
        return [];
    }

    return database.shares
        .filter(
            share =>
                share.rid === rid &&
                share.submitted === true
        )
        .map(share => ({
            observerId: share.observerId,
            x: BigInt(share.x),
            y: BigInt(share.y)
        }));
}


// ---------------------------------------------------------
// Check duplicate x values
// ---------------------------------------------------------

function validateShares(shares, prime) {

    const xValues = new Set();

    for (const share of shares) {

        const x = ((share.x % prime) + prime) % prime;

        if (x === 0n) {
            throw new Error(
                `Invalid share ${share.observerId}: x cannot be zero`
            );
        }

        const key = x.toString();

        if (xValues.has(key)) {
            throw new Error(
                `Duplicate x-coordinate detected: ${key}`
            );
        }

        xValues.add(key);

        if (share.y < 0n || share.y >= prime) {
            throw new Error(
                `Invalid y-coordinate from ${share.observerId}`
            );
        }
    }

    return true;
}


// ---------------------------------------------------------
// Reconstruct secret
// ---------------------------------------------------------

function reconstructSecret(shares, threshold, prime) {

    if (shares.length < threshold) {

        throw new Error(
            `Insufficient shares: ${shares.length}/${threshold}`
        );
    }

    // Only use threshold number of shares.
    const selectedShares =
        shares.slice(0, threshold);

    validateShares(
        selectedShares,
        prime
    );

    const secret = lagrange.reconstructSecret(
        selectedShares,
        prime
    );

    return {
        secret,
        sharesUsed: selectedShares
    };
}


// ---------------------------------------------------------
// Generate temporary session key
// ---------------------------------------------------------

function generateTemporaryKey(secret) {

    /*
     * The reconstructed Shamir secret should not itself
     * be transmitted to Hospital Y.
     *
     * Instead, derive a session key from it.
     */

    const secretString = secret.toString();

    if (sessionKey &&
        typeof sessionKey.generateSessionKey === "function") {

        return sessionKey.generateSessionKey(
            secretString
        );
    }

    // Fallback implementation.
    return crypto
        .createHash("sha256")
        .update(secretString)
        .digest("hex");
}


// ---------------------------------------------------------
// Main authorization function
// ---------------------------------------------------------

async function authorizeAccess(options = {}) {

    const startTime = performance.now();

    const rid =
        options.rid || "RID-001";

    const cid =
        options.cid || "CID-001";

    const threshold =
        Number(options.threshold || 3);

    const prime =
        BigInt(
            options.prime ||
            process.env.SHAMIR_PRIME ||
            "2305843009213693951"
        );

    console.log("");
    console.log(
        "============================================================"
    );
    console.log(
        "             SECURE ACCESS AUTHORIZATION"
    );
    console.log(
        "============================================================"
    );

    console.log(`Request ID: ${rid}`);
    console.log(`Consent ID: ${cid}`);
    console.log(`Threshold: ${threshold}`);
    console.log("");

    try {

        // -------------------------------------------------
        // STEP 1
        // Verify observers
        // -------------------------------------------------

        console.log(
            "STEP 1: Verifying registered observers..."
        );

        const observers =
            getValidObservers();

        console.log(
            `Registered active observers: ${observers.length}`
        );


        // -------------------------------------------------
        // STEP 2
        // Retrieve shares
        // -------------------------------------------------

        console.log("");
        console.log(
            "STEP 2: Retrieving submitted shares..."
        );

        const shares =
            getSubmittedShares(rid);

        console.log(
            `Submitted shares: ${shares.length}`
        );

        console.log(
            `Required threshold: ${threshold}`
        );


        // -------------------------------------------------
        // STEP 3
        // Threshold check
        // -------------------------------------------------

        console.log("");
        console.log(
            "STEP 3: Checking threshold..."
        );

        if (shares.length < threshold) {

            const executionTime =
                performance.now() - startTime;

            console.log(
                `THRESHOLD NOT REACHED`
            );

            console.log(
                `${shares.length} < ${threshold}`
            );

            appendAudit({
                eventId:
                    `AUTH-${Date.now()}`,

                rid,

                cid,

                event:
                    "ACCESS_DENIED",

                reason:
                    "THRESHOLD_NOT_REACHED",

                threshold,

                sharesReceived:
                    shares.length,

                executionTimeMs:
                    Number(executionTime.toFixed(4)),

                timestamp:
                    new Date().toISOString()
            });

            return {
                success: false,
                authorized: false,
                reason: "THRESHOLD_NOT_REACHED",
                sharesReceived: shares.length,
                threshold,
                executionTimeMs: executionTime
            };
        }


        console.log(
            `${shares.length} >= ${threshold}`
        );

        console.log(
            "THRESHOLD REACHED"
        );


        // -------------------------------------------------
        // STEP 4
        // Secret reconstruction
        // -------------------------------------------------

        console.log("");
        console.log(
            "STEP 4: Reconstructing Shamir secret..."
        );

        const reconstructionStart =
            performance.now();

        const reconstruction =
            reconstructSecret(
                shares,
                threshold,
                prime
            );

        const reconstructionLatency =
            performance.now() -
            reconstructionStart;

        console.log(
            "Secret reconstructed successfully."
        );

        console.log(
            `Shares used: ${
                reconstruction.sharesUsed.length
            }`
        );

        console.log(
            `Reconstruction latency: ${
                reconstructionLatency.toFixed(4)
            } ms`
        );


        // -------------------------------------------------
        // STEP 5
        // Generate temporary session key
        // -------------------------------------------------

        console.log("");
        console.log(
            "STEP 5: Generating temporary session key..."
        );

        const keyStart =
            performance.now();

        const temporaryKey =
            generateTemporaryKey(
                reconstruction.secret
            );

        const keyGenerationLatency =
            performance.now() -
            keyStart;

        console.log(
            "Temporary session key generated."
        );

        console.log(
            `Key generation latency: ${
                keyGenerationLatency.toFixed(4)
            } ms`
        );


        // -------------------------------------------------
        // STEP 6
        // Calculate total latency
        // -------------------------------------------------

        const totalLatency =
            performance.now() -
            startTime;


        // -------------------------------------------------
        // STEP 7
        // Audit record
        // -------------------------------------------------

        appendAudit({

            eventId:
                `AUTH-${Date.now()}`,

            rid,

            cid,

            event:
                "ACCESS_GRANTED",

            authorized:
                true,

            threshold,

            sharesReceived:
                shares.length,

            sharesUsed:
                reconstruction.sharesUsed.map(
                    share => share.observerId
                ),

            reconstructionLatencyMs:
                Number(
                    reconstructionLatency.toFixed(4)
                ),

            keyGenerationLatencyMs:
                Number(
                    keyGenerationLatency.toFixed(4)
                ),

            accessLatencyMs:
                Number(
                    totalLatency.toFixed(4)
                ),

            timestamp:
                new Date().toISOString()
        });


        // -------------------------------------------------
        // STEP 8
        // Result
        // -------------------------------------------------

        console.log("");
        console.log(
            "============================================================"
        );
        console.log(
            "                 ACCESS AUTHORIZED"
        );
        console.log(
            "============================================================"
        );

        console.log(
            `Request: ${rid}`
        );

        console.log(
            `Threshold: ${threshold}`
        );

        console.log(
            `Shares used: ${
                reconstruction.sharesUsed.length
            }`
        );

        console.log(
            `Access latency: ${
                totalLatency.toFixed(4)
            } ms`
        );

        console.log(
            `Reconstruction latency: ${
                reconstructionLatency.toFixed(4)
            } ms`
        );

        console.log(
            "Audit record written to database/audit.json"
        );

        console.log(
            "============================================================"
        );


        return {

            success: true,

            authorized: true,

            rid,

            cid,

            threshold,

            sharesReceived:
                shares.length,

            sharesUsed:
                reconstruction.sharesUsed.length,

            temporaryKey,

            reconstructionLatencyMs:
                reconstructionLatency,

            keyGenerationLatencyMs:
                keyGenerationLatency,

            accessLatencyMs:
                totalLatency
        };

    } catch (error) {

        const executionTime =
            performance.now() -
            startTime;

        console.error("");
        console.error(
            "ACCESS AUTHORIZATION FAILED"
        );

        console.error(
            error.message
        );


        appendAudit({

            eventId:
                `AUTH-ERROR-${Date.now()}`,

            rid,

            cid,

            event:
                "ACCESS_AUTHORIZATION_ERROR",

            authorized:
                false,

            error:
                error.message,

            executionTimeMs:
                Number(
                    executionTime.toFixed(4)
                ),

            timestamp:
                new Date().toISOString()
        });


        return {

            success: false,

            authorized: false,

            rid,

            cid,

            error:
                error.message,

            executionTimeMs:
                executionTime
        };
    }
}


// ---------------------------------------------------------
// Export
// ---------------------------------------------------------

module.exports = {
    authorizeAccess,
    getSubmittedShares,
    reconstructSecret
};


// ---------------------------------------------------------
// Direct execution
// ---------------------------------------------------------

if (require.main === module) {

    authorizeAccess({

        rid:
            process.argv[2] ||
            "RID-001",

        cid:
            process.argv[3] ||
            "CID-001",

        threshold:
            Number(
                process.argv[4] ||
                3
            )
    });
}