/**
 * ============================================================
 * crypto/lagrange.js
 * ============================================================
 *
 * Shamir Secret Reconstruction using Lagrange Interpolation
 *
 * Algorithm 4
 *
 * Input:
 *
 *      t valid shares:
 *      (x1,y1), (x2,y2), ..., (xt,yt)
 *
 * Output:
 *
 *      Secret S
 *
 * Formula:
 *
 *                 xj
 * λi = Π ---------------------- mod p
 *       j != i (xj - xi)
 *
 * Since we reconstruct f(0):
 *
 *                 xj
 * λi = Π ---------------------- mod p
 *       j != i (xj - xi)
 *
 * Then:
 *
 *      S = Σ yi * λi mod p
 *
 * ============================================================
 */

const crypto = require("crypto");


// ============================================================
// Import Shamir Configuration
// ============================================================

const {
    PRIME,
    mod,
    modInverse,
    validateShare,
    validateShareSet
} = require("./shamir");


// ============================================================
// Constants
// ============================================================

const DEFAULT_SECRET_LENGTH = 32;


// ============================================================
// Convert Buffer -> BigInt
// ============================================================

function bufferToBigInt(
    buffer
) {

    if (!Buffer.isBuffer(buffer)) {

        throw new Error(
            "Input must be a Buffer"
        );
    }


    if (buffer.length === 0) {

        throw new Error(
            "Buffer cannot be empty"
        );
    }


    return BigInt(
        "0x" +
        buffer.toString("hex")
    );
}


// ============================================================
// Convert BigInt -> Buffer
// ============================================================

function bigIntToBuffer(

    value,

    length = DEFAULT_SECRET_LENGTH

) {

    if (
        typeof value !== "bigint"
    ) {

        value =
            BigInt(value);
    }


    if (value < 0n) {

        throw new Error(
            "Value cannot be negative"
        );
    }


    let hex =
        value.toString(16);


    hex =
        hex.padStart(
            length * 2,
            "0"
        );


    /*
     * If value requires more bytes than requested,
     * do not silently truncate it.
     */

    if (
        hex.length >
        length * 2
    ) {

        throw new Error(
            "Value exceeds requested buffer length"
        );
    }


    return Buffer.from(
        hex,
        "hex"
    );
}


// ============================================================
// Normalize Share
// ============================================================

function normalizeShare(

    share

) {

    if (!share) {

        throw new Error(
            "Share is required"
        );
    }


    if (
        share.x === undefined
        ||
        share.y === undefined
    ) {

        throw new Error(
            "Share must contain x and y"
        );
    }


    let x =
        BigInt(
            share.x
        );


    let y =
        BigInt(
            share.y
        );


    x =
        mod(
            x,
            PRIME
        );


    y =
        mod(
            y,
            PRIME
        );


    return {

        observerIndex:
            share.observerIndex,

        x,

        y
    };
}


// ============================================================
// Validate X Values
// ============================================================

function validateDistinctXValues(

    shares

) {

    const xSet =
        new Set();


    for (
        const share of shares
    ) {

        const key =
            share.x.toString();


        if (
            xSet.has(key)
        ) {

            throw new Error(
                "Duplicate x value detected"
            );
        }


        xSet.add(key);
    }


    return true;
}


// ============================================================
// Compute Lagrange Coefficient
// ============================================================

/**
 * Computes:
 *
 *                 xj
 * λi = Π ---------------------- mod p
 *       j != i (xj - xi)
 *
 * for reconstruction at x = 0.
 *
 * Equivalent to:
 *
 *      (0-xj)/(xi-xj)
 *
 * because:
 *
 *      (-xj)/(xi-xj)
 *
 *      =
 *
 *      xj/(xj-xi)
 *
 * ============================================================
 */

function computeLagrangeCoefficient(

    shares,

    index,

    prime = PRIME

) {

    if (
        !Array.isArray(shares)
    ) {

        throw new Error(
            "Shares must be an array"
        );
    }


    if (
        index < 0
        ||
        index >= shares.length
    ) {

        throw new Error(
            "Invalid share index"
        );
    }


    const xi =
        shares[index].x;


    let coefficient =
        1n;


    for (
        let j = 0;
        j < shares.length;
        j++
    ) {

        if (
            j === index
        ) {

            continue;
        }


        const xj =
            shares[j].x;


        /*
         * Numerator:
         *
         *      xj
         */

        const numerator =
            mod(
                xj,
                prime
            );


        /*
         * Denominator:
         *
         *      xj - xi
         */

        const denominator =
            mod(
                xj - xi,
                prime
            );


        if (
            denominator === 0n
        ) {

            throw new Error(
                "Lagrange denominator is zero. x values must be distinct."
            );
        }


        const inverse =
            modInverse(
                denominator,
                prime
            );


        const term =
            mod(
                numerator * inverse,
                prime
            );


        coefficient =
            mod(
                coefficient * term,
                prime
            );
    }


    return coefficient;
}


// ============================================================
// Compute All Lagrange Coefficients
// ============================================================

function computeLagrangeCoefficients(

    shares,

    prime = PRIME

) {

    const coefficients = [];


    for (
        let i = 0;
        i < shares.length;
        i++
    ) {

        const lambda =
            computeLagrangeCoefficient(

                shares,

                i,

                prime
            );


        coefficients.push(
            lambda
        );
    }


    return coefficients;
}


// ============================================================
// Reconstruct Secret
// ============================================================

/**
 * Algorithm 4
 *
 * Require:
 *
 *      Shares (xi, yi)
 *
 * Ensure:
 *
 *      Secret S
 *
 * Steps:
 *
 * 1. Initialize S = 0
 * 2. Retrieve t valid shares
 * 3. Compute λi
 * 4. S = S + yiλi mod p
 * 5. Return S
 */

function reconstructSecret(

    shares,

    threshold

) {

    // --------------------------------------------------------
    // Validate threshold
    // --------------------------------------------------------

    if (
        !Number.isInteger(
            threshold
        )
    ) {

        throw new Error(
            "Threshold must be an integer"
        );
    }


    if (
        threshold < 2
    ) {

        throw new Error(
            "Threshold must be at least 2"
        );
    }


    // --------------------------------------------------------
    // Validate shares array
    // --------------------------------------------------------

    if (
        !Array.isArray(shares)
    ) {

        throw new Error(
            "Shares must be an array"
        );
    }


    if (
        shares.length <
        threshold
    ) {

        throw new Error(

            `Insufficient shares: ` +
            `${shares.length} provided, ` +
            `${threshold} required`
        );
    }


    /*
     * Use exactly t shares.
     *
     * This follows Algorithm 4.
     */

    const selectedShares =
        shares
            .slice(
                0,
                threshold
            )
            .map(
                normalizeShare
            );


    // --------------------------------------------------------
    // Validate each share
    // --------------------------------------------------------

    for (
        const share of selectedShares
    ) {

        if (
            !validateShare({

                x:
                    share.x.toString(),

                y:
                    share.y.toString()
            })
        ) {

            throw new Error(
                "Invalid Shamir share"
            );
        }
    }


    // --------------------------------------------------------
    // Validate distinct x values
    // --------------------------------------------------------

    validateDistinctXValues(
        selectedShares
    );


    // --------------------------------------------------------
    // Initialize secret
    // --------------------------------------------------------

    let secret =
        0n;


    // --------------------------------------------------------
    // Lagrange interpolation
    // --------------------------------------------------------

    const coefficients =
        computeLagrangeCoefficients(

            selectedShares,

            PRIME
        );


    for (
        let i = 0;
        i < selectedShares.length;
        i++
    ) {

        const yi =
            selectedShares[i].y;


        const lambda =
            coefficients[i];


        const contribution =
            mod(
                yi * lambda,
                PRIME
            );


        secret =
            mod(
                secret +
                contribution,

                PRIME
            );
    }


    return {

        secret,

        secretHex:
            bigIntToBuffer(
                secret,
                DEFAULT_SECRET_LENGTH
            ).toString("hex"),

        coefficients,

        sharesUsed:
            selectedShares
    };
}


// ============================================================
// Reconstruct AES-256 Key
// ============================================================

/**
 * Convenience function specifically for Alice's
 * medical-record encryption key.
 */

function reconstructAESKey(

    shares,

    threshold

) {

    const result =
        reconstructSecret(

            shares,

            threshold
        );


    return {

        key:
            bigIntToBuffer(
                result.secret,
                32
            ),

        keyHex:
            result.secretHex,

        coefficients:
            result.coefficients,

        sharesUsed:
            result.sharesUsed
    };
}


// ============================================================
// Verify Reconstruction
// ============================================================

/**
 * Checks whether reconstructed secret matches the
 * expected AES key.
 *
 * This is useful for experiments and testing.
 *
 * DO NOT expose the secret in production logs.
 */

function verifyReconstruction(

    reconstructedSecret,

    originalSecret

) {

    let reconstructedBuffer;


    if (
        Buffer.isBuffer(
            reconstructedSecret
        )
    ) {

        reconstructedBuffer =
            reconstructedSecret;

    } else if (
        typeof reconstructedSecret ===
        "string"
    ) {

        reconstructedBuffer =
            Buffer.from(
                reconstructedSecret,
                "hex"
            );

    } else if (
        typeof reconstructedSecret ===
        "bigint"
    ) {

        reconstructedBuffer =
            bigIntToBuffer(
                reconstructedSecret
            );

    } else {

        throw new Error(
            "Invalid reconstructed secret"
        );
    }


    let originalBuffer;


    if (
        Buffer.isBuffer(
            originalSecret
        )
    ) {

        originalBuffer =
            originalSecret;

    } else if (
        typeof originalSecret ===
        "string"
    ) {

        originalBuffer =
            Buffer.from(
                originalSecret,
                "hex"
            );

    } else {

        throw new Error(
            "Invalid original secret"
        );
    }


    if (
        reconstructedBuffer.length !==
        originalBuffer.length
    ) {

        return false;
    }


    return crypto.timingSafeEqual(

        reconstructedBuffer,

        originalBuffer
    );
}


// ============================================================
// Reconstruction Latency
// ============================================================

/**
 * Measures local Lagrange reconstruction time.
 *
 * This metric is used in your experiment as:
 *
 *      Reconstruction Latency
 *
 * It does not include blockchain transaction latency.
 */

function measureReconstructionLatency(

    shares,

    threshold

) {

    const start =
        process.hrtime.bigint();


    const result =
        reconstructSecret(

            shares,

            threshold
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

        ...result,

        latencyNanoseconds:

            latencyNanoseconds.toString(),

        latencyMilliseconds
    };
}


// ============================================================
// Share Combination Utility
// ============================================================

/**
 * Returns every possible t-share combination.
 *
 * Useful for evaluating:
 *
 *      Fault tolerance
 *      Robustness
 *      Reconstruction success
 *
 * Example:
 *
 *      n = 5
 *      t = 3
 *
 * Number of combinations:
 *
 *      C(5,3) = 10
 */

function combinations(

    array,

    size

) {

    const result = [];


    function generate(

        start,

        current

    ) {

        if (
            current.length ===
            size
        ) {

            result.push(
                [...current]
            );

            return;
        }


        for (
            let i = start;

            i <=
            array.length -
            (size -
            current.length);

            i++
        ) {

            current.push(
                array[i]
            );


            generate(

                i + 1,

                current
            );


            current.pop();
        }
    }


    generate(
        0,
        []
    );


    return result;
}


// ============================================================
// Test All Threshold Combinations
// ============================================================

/**
 * Useful for your research experiment.
 *
 * Example:
 *
 *      n = 5
 *      t = 3
 *
 * All 10 combinations of 3 shares are tested.
 */

function testAllCombinations(

    shares,

    threshold,

    expectedSecret

) {

    const groups =
        combinations(

            shares,

            threshold
        );


    let successful =
        0;


    let failed =
        0;


    const results = [];


    for (
        const group of groups
    ) {

        try {

            const reconstruction =
                reconstructSecret(

                    group,

                    threshold
                );


            const valid =
                verifyReconstruction(

                    reconstruction.secret,

                    expectedSecret
                );


            if (valid) {

                successful++;

            } else {

                failed++;
            }


            results.push({

                success:
                    valid,

                shares:
                    group.map(
                        share =>
                            share.observerIndex
                    )
            });

        } catch (error) {

            failed++;


            results.push({

                success:
                    false,

                shares:
                    group.map(
                        share =>
                            share.observerIndex
                    ),

                error:
                    error.message
            });
        }
    }


    return {

        totalCombinations:
            groups.length,

        successful,

        failed,

        successRate:

            groups.length === 0
                ? 0
                : (
                    successful /
                    groups.length
                ) * 100,

        results
    };
}


// ============================================================
// Export
// ============================================================

module.exports = {

    bufferToBigInt,

    bigIntToBuffer,

    normalizeShare,

    validateDistinctXValues,

    computeLagrangeCoefficient,

    computeLagrangeCoefficients,

    reconstructSecret,

    reconstructAESKey,

    verifyReconstruction,

    measureReconstructionLatency,

    combinations,

    testAllCombinations
};


// ============================================================
// Standalone Demonstration
// ============================================================

if (require.main === module) {

    const {
        generateSharesFromAESKey,
        generateRandomThreshold
    } = require("./shamir");


    console.log(
        "\n================================================"
    );

    console.log(
        " SHAMIR + LAGRANGE RECONSTRUCTION TEST"
    );

    console.log(
        "================================================\n"
    );


    // --------------------------------------------------------
    // Alice generates AES-256 secret
    // --------------------------------------------------------

    const originalKey =
        crypto.randomBytes(32);


    console.log(
        "Original AES Key:"
    );

    console.log(
        originalKey.toString("hex")
    );


    // --------------------------------------------------------
    // Observer configuration
    // --------------------------------------------------------

    const n = 5;


    const t =
        generateRandomThreshold(n);


    console.log(
        "\nObserver count:",
        n
    );

    console.log(
        "Random threshold:",
        t
    );


    // --------------------------------------------------------
    // Generate Shamir shares
    // --------------------------------------------------------

    const generated =
        generateSharesFromAESKey(

            originalKey,

            t,

            n
        );


    console.log(
        "\nGenerated shares:",
        generated.shares.length
    );


    // --------------------------------------------------------
    // Select t shares
    // --------------------------------------------------------

    const selectedShares =
        generated.shares.slice(
            0,
            t
        );


    console.log(
        "\nShares selected for reconstruction:"
    );


    for (
        const share of selectedShares
    ) {

        console.log(

            `Observer ${share.observerIndex}`,

            `x=${share.x}`
        );
    }


    // --------------------------------------------------------
    // Reconstruct
    // --------------------------------------------------------

    const result =
        measureReconstructionLatency(

            selectedShares,

            t
        );


    console.log(
        "\nReconstructed AES Key:"
    );

    console.log(
        result.secretHex
    );


    // --------------------------------------------------------
    // Verify
    // --------------------------------------------------------

    const verified =
        verifyReconstruction(

            result.secret,

            originalKey
        );


    console.log(
        "\nReconstruction verified:",
        verified
    );


    // --------------------------------------------------------
    // Latency
    // --------------------------------------------------------

    console.log(
        "Reconstruction latency:",
        result.latencyMilliseconds,
        "ms"
    );


    // --------------------------------------------------------
    // Test all combinations
    // --------------------------------------------------------

    const combinationResult =
        testAllCombinations(

            generated.shares,

            t,

            originalKey
        );


    console.log(
        "\nCombination Test:"
    );

    console.log(
        "Total:",
        combinationResult.totalCombinations
    );

    console.log(
        "Successful:",
        combinationResult.successful
    );

    console.log(
        "Failed:",
        combinationResult.failed
    );

    console.log(
        "Success Rate:",
        combinationResult.successRate,
        "%"
    );


    console.log(
        "\n================================================"
    );

    console.log(
        "Lagrange reconstruction completed."
    );

    console.log(
        "================================================\n"
    );
}