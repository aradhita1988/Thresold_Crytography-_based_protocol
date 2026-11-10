/**
 * ============================================================
 * crypto/shamir.js
 * ============================================================
 *
 * Shamir Secret Sharing
 *
 * Used by:
 *
 *      Alice
 *        |
 *        | AES-256 secret key S
 *        v
 *      shamir.js
 *        |
 *        +----> Observer 1
 *        +----> Observer 2
 *        +----> Observer 3
 *        +----> Observer 4
 *        +----> Observer 5
 *
 * Any t out of n shares can reconstruct the secret.
 *
 * Example:
 *
 *      n = 5
 *      t = 3
 *
 *      3 observers are sufficient.
 *      2 observers alone cannot reconstruct the key.
 *
 * ============================================================
 */

const crypto = require("crypto");


// ============================================================
// Configuration
// ============================================================

/*
 * Prime field.
 *
 * This prime is larger than a 256-bit AES key.
 *
 * p =
 * 2^256 - 189
 *
 * It is used only as a field modulus for the prototype.
 */

const PRIME =
    (1n << 256n) - 189n;


// ============================================================
// Constants
// ============================================================

const MIN_THRESHOLD = 2;

const DEFAULT_OBSERVERS = 5;


// ============================================================
// Utility: BigInt -> Buffer
// ============================================================

function bigIntToBuffer(
    value,
    length = 32
) {

    let hex =
        value.toString(16);


    hex =
        hex.padStart(
            length * 2,
            "0"
        );


    return Buffer.from(
        hex,
        "hex"
    );
}


// ============================================================
// Utility: Buffer -> BigInt
// ============================================================

function bufferToBigInt(
    buffer
) {

    if (!Buffer.isBuffer(buffer)) {

        throw new Error(
            "Secret must be a Buffer"
        );
    }


    return BigInt(
        "0x" +
        buffer.toString("hex")
    );
}


// ============================================================
// Modular Normalization
// ============================================================

function mod(
    value,
    prime = PRIME
) {

    const result =
        value % prime;


    return result < 0n
        ? result + prime
        : result;
}


// ============================================================
// Modular Exponentiation
// ============================================================

function modPow(

    base,

    exponent,

    prime = PRIME

) {

    base =
        mod(
            base,
            prime
        );


    let result = 1n;


    while (
        exponent > 0n
    ) {

        if (
            exponent & 1n
        ) {

            result =
                mod(
                    result * base,
                    prime
                );
        }


        base =
            mod(
                base * base,
                prime
            );


        exponent >>= 1n;
    }


    return result;
}


// ============================================================
// Modular Inverse
// ============================================================

/**
 * Fermat's Little Theorem:
 *
 *      a^-1 = a^(p-2) mod p
 *
 * because p is prime.
 */

function modInverse(

    value,

    prime = PRIME

) {

    value =
        mod(
            value,
            prime
        );


    if (value === 0n) {

        throw new Error(
            "Modular inverse does not exist"
        );
    }


    return modPow(
        value,
        prime - 2n,
        prime
    );
}


// ============================================================
// Cryptographically Secure Random Field Element
// ============================================================

function randomFieldElement(

    prime = PRIME

) {

    const byteLength =
        Math.ceil(
            prime.toString(2).length / 8
        );


    while (true) {

        const randomBytes =
            crypto.randomBytes(
                byteLength
            );


        let value =
            BigInt(
                "0x" +
                randomBytes.toString("hex")
            );


        value =
            mod(
                value,
                prime
            );


        if (
            value > 0n
            &&
            value < prime
        ) {

            return value;
        }
    }
}


// ============================================================
// Validate Prime
// ============================================================

/**
 * For this project PRIME is fixed.
 *
 * The function is retained because your algorithm explicitly
 * requires field validation.
 */

function validatePrime(
    prime
) {

    if (
        typeof prime !== "bigint"
    ) {

        throw new Error(
            "Prime must be a BigInt"
        );
    }


    if (
        prime <= 2n
    ) {

        throw new Error(
            "Prime must be greater than 2"
        );
    }


    /*
     * Miller-Rabin is unnecessary for the fixed prototype
     * prime because PRIME is defined by the project.
     *
     * We therefore perform a basic sanity check here.
     */

    if (
        prime !== PRIME
    ) {

        throw new Error(
            "This implementation expects the configured project prime"
        );
    }


    return true;
}


// ============================================================
// Validate Secret
// ============================================================

function validateSecret(
    secret,
    prime = PRIME
) {

    let secretBigInt;


    if (Buffer.isBuffer(secret)) {

        secretBigInt =
            bufferToBigInt(
                secret
            );

    } else if (
        typeof secret === "string"
    ) {

        /*
         * Hexadecimal AES key.
         */

        secretBigInt =
            BigInt(
                "0x" + secret
            );

    } else if (
        typeof secret === "bigint"
    ) {

        secretBigInt =
            secret;

    } else {

        throw new Error(
            "Secret must be Buffer, hexadecimal string, or BigInt"
        );
    }


    if (
        secretBigInt < 0n
        ||
        secretBigInt >= prime
    ) {

        throw new Error(
            "Secret must belong to the field Zp"
        );
    }


    return secretBigInt;
}


// ============================================================
// Validate Threshold
// ============================================================

function validateThreshold(

    threshold,

    numberOfObservers

) {

    if (
        !Number.isInteger(threshold)
    ) {

        throw new Error(
            "Threshold must be an integer"
        );
    }


    if (
        !Number.isInteger(
            numberOfObservers
        )
    ) {

        throw new Error(
            "Number of observers must be an integer"
        );
    }


    if (
        threshold < MIN_THRESHOLD
    ) {

        throw new Error(
            `Threshold must be at least ${MIN_THRESHOLD}`
        );
    }


    if (
        threshold > numberOfObservers
    ) {

        throw new Error(
            "Threshold cannot exceed number of observers"
        );
    }


    return true;
}


// ============================================================
// Random Threshold
// ============================================================

/**
 * Generates a random threshold.
 *
 * Example:
 *
 *      n = 5
 *
 * Possible t:
 *
 *      2, 3, 4, 5
 *
 * This satisfies:
 *
 *      2 <= t <= n
 */

function generateRandomThreshold(

    numberOfObservers = DEFAULT_OBSERVERS

) {

    if (
        numberOfObservers <
        MIN_THRESHOLD
    ) {

        throw new Error(
            "At least two observers are required"
        );
    }


    const randomBytes =
        crypto.randomBytes(4);


    const randomNumber =
        randomBytes.readUInt32BE(0);


    return (

        MIN_THRESHOLD
        +
        (
            randomNumber %
            (
                numberOfObservers -
                MIN_THRESHOLD +
                1
            )
        )

    );
}


// ============================================================
// Generate Observer X Values
// ============================================================

/**
 * Generates:
 *
 *      x1, x2, ..., xn
 *
 * The x values are:
 *
 *      non-zero
 *      pairwise distinct
 *
 * For this implementation we use:
 *
 *      x1 = 1
 *      x2 = 2
 *      ...
 *      xn = n
 *
 * Since n << p, they are valid field elements.
 */

function generateXValues(

    numberOfObservers,

    prime = PRIME

) {

    if (
        numberOfObservers <= 0
    ) {

        throw new Error(
            "Observer count must be positive"
        );
    }


    if (
        BigInt(numberOfObservers)
        >=
        prime
    ) {

        throw new Error(
            "Observer count is too large for field"
        );
    }


    const xValues = [];


    for (
        let i = 1;
        i <= numberOfObservers;
        i++
    ) {

        xValues.push(
            BigInt(i)
        );
    }


    return xValues;
}


// ============================================================
// Validate X Values
// ============================================================

function validateXValues(

    xValues,

    prime = PRIME

) {

    const seen =
        new Set();


    for (
        const x of xValues
    ) {

        if (
            typeof x !== "bigint"
        ) {

            throw new Error(
                "Each x value must be BigInt"
            );
        }


        const normalized =
            mod(
                x,
                prime
            );


        if (
            normalized === 0n
        ) {

            throw new Error(
                "x values must be non-zero"
            );
        }


        const key =
            normalized.toString();


        if (
            seen.has(key)
        ) {

            throw new Error(
                "x values must be pairwise distinct"
            );
        }


        seen.add(key);
    }


    return true;
}


// ============================================================
// Generate Random Coefficients
// ============================================================

/**
 * Algorithm 1:
 *
 *      a1, a2, ..., a(t-1) <-R- Zp
 *
 * Secure random generation is performed using Node.js
 * crypto.randomBytes().
 */

function generateRandomCoefficients(

    threshold,

    prime = PRIME

) {

    const coefficients = [];


    /*
     * a0 = secret
     *
     * Only random coefficients a1...a(t-1) are generated here.
     */

    for (
        let k = 1;
        k < threshold;
        k++
    ) {

        coefficients.push(
            randomFieldElement(
                prime
            )
        );
    }


    return coefficients;
}


// ============================================================
// Polynomial Evaluation
// ============================================================

/**
 * Evaluates:
 *
 * f(x) =
 *
 * S + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)
 *
 * mod p
 *
 * Horner's method is used for efficiency.
 */

function evaluatePolynomial(

    x,

    secret,

    coefficients,

    prime = PRIME

) {

    let result =
        secret;


    /*
     * Work backwards:
     *
     * f(x) = (...((a(t-1)x + a(t-2))x + ...)
     */

    for (
        let i =
            coefficients.length - 1;

        i >= 0;

        i--
    ) {

        result =
            mod(
                result * x
                +
                coefficients[i],

                prime
            );
    }


    result =
        mod(
            result * x
            +
            secret,

            prime
        );


    return result;
}


// ============================================================
// Correct Polynomial Evaluation
// ============================================================

/**
 * Explicit polynomial evaluation.
 *
 * This version directly follows Algorithm 1 and is used by
 * generateShares().
 */

function evaluatePolynomialDirect(

    x,

    secret,

    coefficients,

    prime = PRIME

) {

    let result =
        secret;


    for (
        let k = 1;
        k <= coefficients.length;
        k++
    ) {

        const coefficient =
            coefficients[k - 1];


        const power =
            modPow(
                x,
                BigInt(k),
                prime
            );


        result =
            mod(
                result
                +
                coefficient * power,

                prime
            );
    }


    return result;
}


// ============================================================
// Generate Shares
// ============================================================

/**
 * Main Shamir function.
 *
 * Implements Algorithm 1:
 *
 * Input:
 *
 *      Secret S
 *      threshold t
 *      observer set O
 *      field Fp
 *
 * Output:
 *
 *      (xi, yi)
 *
 * Example:
 *
 *      n = 5
 *      t = 3
 *
 * Polynomial:
 *
 *      f(x) = S + a1*x + a2*x² mod p
 */

function generateShares(

    secret,

    threshold,

    numberOfObservers = DEFAULT_OBSERVERS,

    prime = PRIME

) {

    // --------------------------------------------------------
    // Step 1: Validate field
    // --------------------------------------------------------

    validatePrime(
        prime
    );


    // --------------------------------------------------------
    // Step 2: Validate threshold
    // --------------------------------------------------------

    validateThreshold(

        threshold,

        numberOfObservers
    );


    // --------------------------------------------------------
    // Step 3: Validate secret
    // --------------------------------------------------------

    const secretBigInt =
        validateSecret(

            secret,

            prime
        );


    // --------------------------------------------------------
    // Step 4: Generate x values
    // --------------------------------------------------------

    const xValues =
        generateXValues(

            numberOfObservers,

            prime
        );


    validateXValues(

        xValues,

        prime
    );


    // --------------------------------------------------------
    // Step 5: Generate random coefficients
    // --------------------------------------------------------

    const coefficients =
        generateRandomCoefficients(

            threshold,

            prime
        );


    // --------------------------------------------------------
    // Step 6: Evaluate polynomial
    // --------------------------------------------------------

    const shares = [];


    for (
        let i = 0;
        i < numberOfObservers;
        i++
    ) {

        const x =
            xValues[i];


        const y =
            evaluatePolynomialDirect(

                x,

                secretBigInt,

                coefficients,

                prime
            );


        shares.push({

            observerIndex:
                i + 1,

            x:
                x.toString(),

            y:
                y.toString()
        });
    }


    // --------------------------------------------------------
    // Return shares
    // --------------------------------------------------------

    return shares;
}



// ============================================================
// Generate Shares from AES Key
// ============================================================

/**
 * Convenience function for Alice.
 *
 * Input:
 *
 *      AES key Buffer
 *
 * Output:
 *
 *      Shamir shares
 */

function generateSharesFromAESKey(

    aesKey,

    threshold,

    numberOfObservers = DEFAULT_OBSERVERS

) {

    if (!Buffer.isBuffer(aesKey)) {

        throw new Error(
            "AES key must be a Buffer"
        );
    }


    if (
        aesKey.length !== 32
    ) {

        throw new Error(
            "AES-256 key must be 32 bytes"
        );
    }


    return generateShares(

        aesKey,

        threshold,

        numberOfObservers,

        PRIME
    );
}


// ============================================================
// Share Validation
// ============================================================

function validateShare(

    share,

    prime = PRIME

) {

    if (!share) {

        return false;
    }


    if (
        share.x === undefined
        ||
        share.y === undefined
    ) {

        return false;
    }


    let x;
    let y;


    try {

        x =
            BigInt(
                share.x
            );

        y =
            BigInt(
                share.y
            );

    } catch (error) {

        return false;
    }


    if (
        x <= 0n
        ||
        x >= prime
    ) {

        return false;
    }


    if (
        y < 0n
        ||
        y >= prime
    ) {

        return false;
    }


    return true;
}


// ============================================================
// Validate Share Set
// ============================================================

function validateShareSet(

    shares,

    threshold,

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
        shares.length <
        threshold
    ) {

        throw new Error(
            `At least ${threshold} shares are required`
        );
    }


    const xValues =
        shares.map(
            share =>
                BigInt(share.x)
        );


    validateXValues(

        xValues,

        prime
    );


    for (
        const share of shares
    ) {

        if (
            !validateShare(
                share,
                prime
            )
        ) {

            throw new Error(
                "Invalid Shamir share"
            );
        }
    }


    return true;
}


// ============================================================
// Convert Share to Blockchain Format
// ============================================================

/**
 * Smart contracts generally store uint256 values.
 *
 * This function prepares a share for ObserverManager.sol.
 */

function shareForBlockchain(

    share

) {

    if (
        !validateShare(
            share
        )
    ) {

        throw new Error(
            "Invalid share"
        );
    }


    return {

        x:
            BigInt(
                share.x
            ).toString(),

        y:
            BigInt(
                share.y
            ).toString()
    };
}


// ============================================================
// Calculate Share Overhead
// ============================================================

/**
 * Used for your communication-overhead experiment.
 *
 * Each share contains:
 *
 *      observerIndex
 *      x
 *      y
 */

function calculateShareOverhead(

    shares

) {

    if (
        !Array.isArray(shares)
    ) {

        throw new Error(
            "Shares must be an array"
        );
    }


    let totalBytes = 0;


    const details = [];


    for (
        const share of shares
    ) {

        const xBytes =
            bigIntToBuffer(
                BigInt(share.x),
                32
            ).length;


        const yBytes =
            bigIntToBuffer(
                BigInt(share.y),
                32
            ).length;


        /*
         * observerIndex is represented as 4 bytes
         * for experimental overhead calculation.
         */

        const observerIndexBytes = 4;


        const shareBytes =
            observerIndexBytes
            +
            xBytes
            +
            yBytes;


        totalBytes +=
            shareBytes;


        details.push({

            observerIndex:
                share.observerIndex,

            xBytes,

            yBytes,

            observerIndexBytes,

            totalBytes:
                shareBytes
        });
    }


    return {

        numberOfShares:
            shares.length,

        totalBytes,

        details
    };
}


// ============================================================
// Get Prime
// ============================================================

function getPrime() {

    return PRIME;
}


// ============================================================
// Export
// ============================================================

module.exports = {

    PRIME,

    MIN_THRESHOLD,

    DEFAULT_OBSERVERS,

    mod,

    modPow,

    modInverse,

    randomFieldElement,

    generateRandomThreshold,

    generateXValues,

    validateXValues,

    generateRandomCoefficients,

    evaluatePolynomialDirect,

    generateShares,

    generateSharesFromAESKey,

    validateSecret,

    validateShare,

    validateShareSet,

    shareForBlockchain,

    calculateShareOverhead,

    getPrime
};


// ============================================================
// Standalone Demonstration
// ============================================================

if (require.main === module) {

    console.log(
        "\n=============================================="
    );

    console.log(
        " SHAMIR SECRET SHARING DEMONSTRATION"
    );

    console.log(
        "==============================================\n"
    );


    // --------------------------------------------------------
    // Generate AES-256 secret
    // --------------------------------------------------------

    const secret =
        crypto.randomBytes(32);


    console.log(
        "Alice AES Key:"
    );

    console.log(
        secret.toString("hex")
    );


    // --------------------------------------------------------
    // Number of observers
    // --------------------------------------------------------

    const n = 5;


    // --------------------------------------------------------
    // Random threshold
    // --------------------------------------------------------

    const t =
        generateRandomThreshold(n);


    console.log(
        "\nNumber of observers:",
        n
    );

    console.log(
        "Random threshold:",
        t
    );


    // --------------------------------------------------------
    // Generate shares
    // --------------------------------------------------------

    const result =
        generateSharesFromAESKey(

            secret,

            t,

            n
        );


    console.log(
        "\nGenerated Shares:"
    );


    for (
        const share of result
    ) {

        console.log(
            `Observer ${share.observerIndex}:`,
            `(x=${share.x}, y=${share.y})`
        );
    }


    // --------------------------------------------------------
    // Calculate overhead
    // --------------------------------------------------------

    const overhead =
        calculateShareOverhead(
            result
        );


    console.log(
        "\nShare Communication Overhead:"
    );

    console.log(
        overhead
    );


    // --------------------------------------------------------
    // Validate shares
    // --------------------------------------------------------

    console.log(
        "\nShare Validation:"
    );


    for (
        const share of result
        
    ) {

        console.log(

            `Observer ${share.observerIndex}:`,

            validateShare(
                share
            )
        );
    }


    console.log(
        "\n=============================================="
    );

    console.log(
        "Shamir share generation completed."
    );

    console.log(
        "==============================================\n"
    );
}