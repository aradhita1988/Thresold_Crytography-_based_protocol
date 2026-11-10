/**
 * ============================================================
 * crypto/sessionKey.js
 * ============================================================
 *
 * Temporary Session Key Generation
 *
 * Algorithm 5:
 *
 *      S
 *      |
 *      v
 *    H(S)
 *      |
 *      v
 *  Ktemp
 *
 * The reconstructed Shamir secret is NEVER directly used as
 * the hospital session key.
 *
 * Instead:
 *
 *      Ktemp = SHA-256(S || context)
 *
 * or HKDF-SHA256 can be used for stronger key derivation.
 *
 * ============================================================
 */

const crypto = require("crypto");


// ============================================================
// Configuration
// ============================================================

const SESSION_KEY_LENGTH = 32; // 256 bits

const DEFAULT_ACCESS_DURATION =
    60 * 60 * 1000; // 1 hour


// ============================================================
// Convert Secret to Buffer
// ============================================================

function secretToBuffer(secret) {

    if (Buffer.isBuffer(secret)) {

        return Buffer.from(secret);
    }


    if (typeof secret === "bigint") {

        let hex =
            secret.toString(16);


        hex =
            hex.padStart(
                64,
                "0"
            );


        return Buffer.from(
            hex,
            "hex"
        );
    }


    if (typeof secret === "string") {

        /*
         * Assume hexadecimal representation.
         */

        const cleanSecret =
            secret.startsWith("0x")
                ? secret.slice(2)
                : secret;


        if (
            !/^[0-9a-fA-F]+$/.test(
                cleanSecret
            )
        ) {

            throw new Error(
                "Secret string must be hexadecimal"
            );
        }


        return Buffer.from(
            cleanSecret,
            "hex"
        );
    }


    throw new Error(
        "Secret must be Buffer, BigInt, or hexadecimal string"
    );
}


// ============================================================
// Validate Secret
// ============================================================

function validateSecret(secret) {

    const secretBuffer =
        secretToBuffer(
            secret
        );


    if (
        secretBuffer.length === 0
    ) {

        throw new Error(
            "Secret cannot be empty"
        );
    }


    return secretBuffer;
}


// ============================================================
// Generate Session Key using SHA-256
// ============================================================

/**
 * Algorithm:
 *
 *      Ktemp = H(S || context)
 *
 * SHA-256 produces a 256-bit key.
 */

function generateSessionKey(

    secret,

    context = "HEALTHCARE-ACCESS"

) {

    const secretBuffer =
        validateSecret(
            secret
        );


    if (
        typeof context !== "string"
    ) {

        throw new Error(
            "Context must be a string"
        );
    }


    const hash =
        crypto.createHash(
            "sha256"
        );


    hash.update(
        secretBuffer
    );


    hash.update(
        Buffer.from(
            context,
            "utf8"
        )
    );


    const sessionKey =
        hash.digest();


    return sessionKey;
}


// ============================================================
// Generate Session Key Hex
// ============================================================

function generateSessionKeyHex(

    secret,

    context = "HEALTHCARE-ACCESS"

) {

    return generateSessionKey(

        secret,

        context

    ).toString("hex");
}


// ============================================================
// HKDF Session Key
// ============================================================

/**
 * More robust key derivation:
 *
 *      Ktemp = HKDF-SHA256(S, salt, info)
 *
 * Node.js provides HKDF through:
 *
 *      crypto.hkdfSync()
 */

function generateSessionKeyHKDF(

    secret,

    options = {}

) {

    const secretBuffer =
        validateSecret(
            secret
        );


    const salt =
        options.salt
            ? Buffer.isBuffer(
                options.salt
            )
                ? options.salt
                : Buffer.from(
                    options.salt,
                    "utf8"
                )
            : crypto.randomBytes(
                32
            );


    const info =
        options.info
            ? Buffer.isBuffer(
                options.info
            )
                ? options.info
                : Buffer.from(
                    options.info,
                    "utf8"
                )
            : Buffer.from(
                "HEALTHCARE-OBSERVER-THRESHOLD",
                "utf8"
            );


    const key =
        crypto.hkdfSync(

            "sha256",

            secretBuffer,

            salt,

            info,

            SESSION_KEY_LENGTH
        );


    return {

        key:
            Buffer.from(key),

        salt
    };
}


// ============================================================
// Generate Random Session Identifier
// ============================================================

function generateSessionId() {

    return crypto
        .randomBytes(16)
        .toString("hex");
}


// ============================================================
// Generate Access Token
// ============================================================

/**
 * Generates a random token that identifies the temporary
 * authorization session.
 *
 * The token is NOT the encryption key.
 */

function generateAccessToken() {

    return crypto
        .randomBytes(32)
        .toString("hex");
}


// ============================================================
// Create Temporary Session
// ============================================================

/**
 * Creates a temporary Hospital Y access session.
 *
 * Example:
 *
 *      duration = 30 minutes
 *
 * Session contains:
 *
 *      sessionId
 *      key
 *      createdAt
 *      expiresAt
 *      duration
 */

function createTemporarySession(

    secret,

    options = {}

) {

    const duration =
        options.durationMs ||
        DEFAULT_ACCESS_DURATION;


    if (
        !Number.isFinite(
            duration
        )
        ||
        duration <= 0
    ) {

        throw new Error(
            "Invalid session duration"
        );
    }


    const sessionId =
        generateSessionId();


    const accessToken =
        generateAccessToken();


    const context =
        options.context ||
        `HEALTHCARE-ACCESS:${sessionId}`;


    const key =
        generateSessionKey(

            secret,

            context
        );


    const createdAt =
        Date.now();


    const expiresAt =
        createdAt +
        duration;


    return {

        sessionId,

        accessToken,

        key,

        keyHex:
            key.toString("hex"),

        context,

        createdAt,

        expiresAt,

        durationMs:
            duration
    };
}


// ============================================================
// Check Session Expiry
// ============================================================

function isSessionExpired(

    session

) {

    if (
        !session
        ||
        typeof session.expiresAt !==
        "number"
    ) {

        throw new Error(
            "Invalid session"
        );
    }


    return (
        Date.now()
        >=
        session.expiresAt
    );
}


// ============================================================
// Check Session Validity
// ============================================================

function isSessionValid(

    session

) {

    return !isSessionExpired(
        session
    );
}


// ============================================================
// Remaining Session Time
// ============================================================

function getRemainingTime(

    session

) {

    if (
        !session
        ||
        typeof session.expiresAt !==
        "number"
    ) {

        throw new Error(
            "Invalid session"
        );
    }


    return Math.max(

        0,

        session.expiresAt -
        Date.now()

    );
}


// ============================================================
// Revoke Session
// ============================================================

function revokeSession(

    session

) {

    if (!session) {

        throw new Error(
            "Invalid session"
        );
    }


    /*
     * Set expiry to current time.
     *
     * The actual application should additionally maintain
     * a server-side revocation list or smart-contract state.
     */

    session.expiresAt =
        Date.now();


    session.revoked =
        true;


    return session;
}


// ============================================================
// Verify Access Token
// ============================================================

function verifyAccessToken(

    session,

    accessToken

) {

    if (
        !session
        ||
        !accessToken
    ) {

        return false;
    }


    if (
        session.revoked
    ) {

        return false;
    }


    if (
        isSessionExpired(
            session
        )
    ) {

        return false;
    }


    const tokenA =
        Buffer.from(
            session.accessToken,
            "utf8"
        );


    const tokenB =
        Buffer.from(
            accessToken,
            "utf8"
        );


    if (
        tokenA.length !==
        tokenB.length
    ) {

        return false;
    }


    return crypto.timingSafeEqual(

        tokenA,

        tokenB
    );
}


// ============================================================
// Secure Session Key Destruction
// ============================================================

/**
 * Best-effort memory cleanup.
 *
 * JavaScript cannot guarantee immediate memory erasure,
 * but overwriting the Buffer is preferable to retaining
 * the key unnecessarily.
 */

function destroySessionKey(

    session

) {

    if (
        session
        &&
        Buffer.isBuffer(
            session.key
        )
    ) {

        session.key.fill(0);
    }


    if (session) {

        session.keyHex =
            null;

        session.destroyed =
            true;
    }


    return true;
}


// ============================================================
// Session-Key Generation Latency
// ============================================================

/**
 * Used in your experimental evaluation.
 *
 * Measures:
 *
 *      Session Key Generation Latency
 *
 * Unit:
 *
 *      milliseconds
 */

function measureSessionKeyLatency(

    secret,

    context = "HEALTHCARE-ACCESS"

) {

    const start =
        process.hrtime.bigint();


    const key =
        generateSessionKey(

            secret,

            context
        );


    const end =
        process.hrtime.bigint();


    const elapsed =
        end -
        start;


    return {

        key,

        keyHex:
            key.toString("hex"),

        latencyNanoseconds:
            elapsed.toString(),

        latencyMilliseconds:
            Number(elapsed) / 1e6
    };
}


// ============================================================
// Batch Latency Experiment
// ============================================================

/**
 * Executes session-key generation multiple times.
 *
 * Useful for your experimental results.
 */

function benchmarkSessionKey(

    secret,

    iterations = 20

) {

    if (
        iterations <= 0
    ) {

        throw new Error(
            "Iterations must be positive"
        );
    }


    const measurements = [];


    let totalNanoseconds =
        0n;


    for (
        let i = 0;
        i < iterations;
        i++
    ) {

        const result =
            measureSessionKeyLatency(

                secret,

                `BENCHMARK-${i}`
            );


        const latency =
            BigInt(
                result.latencyNanoseconds
            );


        totalNanoseconds +=
            latency;


        measurements.push({

            iteration:
                i + 1,

            latencyMilliseconds:
                result.latencyMilliseconds
        });
    }


    const averageMilliseconds =

        Number(
            totalNanoseconds
        )
        /
        1e6
        /
        iterations;


    return {

        iterations,

        averageLatencyMilliseconds:
            averageMilliseconds,

        measurements
    };
}


// ============================================================
// Session Metadata
// ============================================================

/**
 * Removes the actual cryptographic key from metadata.
 *
 * This object can safely be used when preparing audit
 * information for blockchain storage.
 */

function getSessionMetadata(

    session

) {

    if (!session) {

        throw new Error(
            "Invalid session"
        );
    }


    return {

        sessionId:
            session.sessionId,

        createdAt:
            session.createdAt,

        expiresAt:
            session.expiresAt,

        durationMs:
            session.durationMs,

        context:
            session.context,

        revoked:
            Boolean(
                session.revoked
            )
    };
}


// ============================================================
// Export
// ============================================================

module.exports = {

    SESSION_KEY_LENGTH,

    DEFAULT_ACCESS_DURATION,

    secretToBuffer,

    validateSecret,

    generateSessionKey,

    generateSessionKeyHex,

    generateSessionKeyHKDF,

    generateSessionId,

    generateAccessToken,

    createTemporarySession,

    isSessionExpired,

    isSessionValid,

    getRemainingTime,

    revokeSession,

    verifyAccessToken,

    destroySessionKey,

    measureSessionKeyLatency,

    benchmarkSessionKey,

    getSessionMetadata
};


// ============================================================
// Standalone Demonstration
// ============================================================

if (require.main === module) {

    console.log(
        "\n================================================"
    );

    console.log(
        " TEMPORARY SESSION KEY DEMONSTRATION"
    );

    console.log(
        "================================================\n"
    );


    // --------------------------------------------------------
    // Simulated reconstructed secret
    // --------------------------------------------------------

    const reconstructedSecret =
        crypto.randomBytes(32);


    console.log(
        "Reconstructed Secret:"
    );

    console.log(
        reconstructedSecret.toString("hex")
    );


    // --------------------------------------------------------
    // Generate session key
    // --------------------------------------------------------

    const result =
        measureSessionKeyLatency(

            reconstructedSecret,

            "ALICE-HOSPITAL-Y"
        );


    console.log(
        "\nTemporary Session Key:"
    );

    console.log(
        result.keyHex
    );


    console.log(
        "\nSession-key generation latency:",
        result.latencyMilliseconds,
        "ms"
    );


    // --------------------------------------------------------
    // Create temporary access session
    // --------------------------------------------------------

    const session =
        createTemporarySession(

            reconstructedSecret,

            {

                durationMs:
                    30 * 60 * 1000,

                context:
                    "ALICE-HOSPITAL-Y"
            }
        );


    console.log(
        "\nTemporary Session:"
    );


    console.log({

        sessionId:
            session.sessionId,

        accessToken:
            session.accessToken,

        createdAt:
            new Date(
                session.createdAt
            ).toISOString(),

        expiresAt:
            new Date(
                session.expiresAt
            ).toISOString(),

        durationMs:
            session.durationMs
    });


    // --------------------------------------------------------
    // Verify access token
    // --------------------------------------------------------

    console.log(
        "\nAccess Token Valid:",
        verifyAccessToken(

            session,

            session.accessToken
        )
    );


    // --------------------------------------------------------
    // Remaining time
    // --------------------------------------------------------

    console.log(
        "Remaining access time:",
        getRemainingTime(
            session
        ),
        "ms"
    );


    // --------------------------------------------------------
    // Session metadata for audit
    // --------------------------------------------------------

    console.log(
        "\nBlockchain Audit Metadata:"
    );

    console.log(
        getSessionMetadata(
            session
        )
    );


    // --------------------------------------------------------
    // Benchmark
    // --------------------------------------------------------

    const benchmark =
        benchmarkSessionKey(

            reconstructedSecret,

            20
        );


    console.log(
        "\n20-run Session Key Benchmark:"
    );

    console.log(
        "Average latency:",
        benchmark.averageLatencyMilliseconds,
        "ms"
    );


    console.log(
        "\n================================================"
    );

    console.log(
        "Session key module completed."
    );

    console.log(
        "================================================\n"
    );
}