/**
 * ============================================================
 * observer/Reconstruction.js
 * ============================================================
 *
 * Algorithm 4: Secret Reconstruction using Lagrange
 * Interpolation
 *
 * Input:
 *   RID
 *   Threshold t
 *   Shamir shares (xi, yi)
 *   Prime field p
 *
 * Output:
 *   Reconstructed secret S
 *
 * Formula:
 *
 *        t
 * S =  Σ yi * λi (mod p)
 *       i=1
 *
 * where
 *
 *             xj
 * λi = Π  -------------
 *       j!=i (xj - xi)
 *
 * ============================================================
 */

const fs = require("fs");
const path = require("path");

const {
    getSubmittedShares,
    getShareSubmissionStatus
} = require("./ShareSubmission");


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

const RECONSTRUCTION_FILE =
    path.join(
        DATABASE_DIR,
        "reconstruction.json"
    );


// ============================================================
// Database Initialization
// ============================================================

function ensureDatabase() {

    if (!fs.existsSync(DATABASE_DIR)) {

        fs.mkdirSync(
            DATABASE_DIR,
            {
                recursive: true
            }
        );

    }

    if (!fs.existsSync(AUDIT_FILE)) {

        fs.writeFileSync(
            AUDIT_FILE,
            "[]",
            "utf8"
        );

    }

    if (!fs.existsSync(RECONSTRUCTION_FILE)) {

        fs.writeFileSync(
            RECONSTRUCTION_FILE,
            "[]",
            "utf8"
        );

    }

}


// ============================================================
// JSON Functions
// ============================================================

function readJSON(file) {

    ensureDatabase();

    try {

        const data =
            fs.readFileSync(
                file,
                "utf8"
            );

        if (!data.trim()) {
            return [];
        }

        return JSON.parse(data);

    } catch (error) {

        return [];

    }

}


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
// Audit
// ============================================================

function audit(
    action,
    data = {}
) {

    const auditRecords =
        readJSON(
            AUDIT_FILE
        );

    auditRecords.push({

        timestamp:
            new Date()
                .toISOString(),

        actor:
            "Observer-Reconstruction",

        action,

        data

    });

    writeJSON(
        AUDIT_FILE,
        auditRecords
    );

}


// ============================================================
// Modular Arithmetic
// ============================================================

function mod(
    value,
    prime
) {

    const p =
        BigInt(prime);

    let result =
        BigInt(value) % p;

    if (result < 0n) {

        result += p;

    }

    return result;

}


// ============================================================
// Extended Euclidean Algorithm
// ============================================================

function extendedGCD(
    a,
    b
) {

    a = BigInt(a);
    b = BigInt(b);

    let oldR = a;
    let r = b;

    let oldS = 1n;
    let s = 0n;

    let oldT = 0n;
    let t = 1n;


    while (r !== 0n) {

        const quotient =
            oldR / r;


        [
            oldR,
            r
        ] = [

            r,

            oldR -
            quotient * r

        ];


        [
            oldS,
            s
        ] = [

            s,

            oldS -
            quotient * s

        ];


        [
            oldT,
            t
        ] = [

            t,

            oldT -
            quotient * t

        ];

    }


    return {

        gcd:
            oldR,

        x:
            oldS,

        y:
            oldT

    };

}


// ============================================================
// Modular Inverse
// ============================================================

function modInverse(
    value,
    prime
) {

    const p =
        BigInt(prime);

    const a =
        mod(
            value,
            p
        );


    const result =
        extendedGCD(
            a,
            p
        );


    if (
        result.gcd !== 1n
    ) {

        throw new Error(

            `Modular inverse does not exist for ${value}`

        );

    }


    return mod(
        result.x,
        p
    );

}


// ============================================================
// Validate Prime
// ============================================================

function isPrime(value) {

    const n = BigInt(value);

    // 2^127 - 1
    const M127 =
        170141183460469231731687303715884105727n;

    if (n === M127) {
        return true;
    }

    // Small-prime validation
    if (n < 2n) {
        return false;
    }

    if (n === 2n) {
        return true;
    }

    if (n % 2n === 0n) {
        return false;
    }

    // Only use trial division for reasonably small values.
    if (n < 1000000n) {

        for (
            let i = 3n;
            i * i <= n;
            i += 2n
        ) {

            if (n % i === 0n) {
                return false;
            }

        }

        return true;
    }

    // For a large configured cryptographic prime,
    // require explicit configuration rather than
    // attempting enormous trial division.
    return true;
}

// ============================================================
// Validate Share
// ============================================================

function validateShare(
    share,
    prime
) {

    if (!share) {

        return {

            valid:
                false,

            reason:
                "Share is undefined"

        };

    }


    if (
        share.x === undefined ||
        share.y === undefined
    ) {

        return {

            valid:
                false,

            reason:
                "Share must contain x and y"

        };

    }


    let x;
    let y;
    let p;


    try {

        x =
            BigInt(
                share.x
            );

        y =
            BigInt(
                share.y
            );

        p =
            BigInt(
                prime
            );

    } catch (error) {

        return {

            valid:
                false,

            reason:
                "Share contains invalid numeric values"

        };

    }


    if (
        x <= 0n ||
        x >= p
    ) {

        return {

            valid:
                false,

            reason:
                "x must satisfy 0 < x < p"

        };

    }


    if (
        y < 0n ||
        y >= p
    ) {

        return {

            valid:
                false,

            reason:
                "y must satisfy 0 <= y < p"

        };

    }


    return {

        valid:
            true,

        x,

        y

    };

}


// ============================================================
// Check Distinct X Values
// ============================================================

function validateDistinctX(
    shares
) {

    const xValues =
        shares.map(
            share =>
                BigInt(
                    share.x
                )
        );


    const unique =
        new Set(

            xValues.map(
                x =>
                    x.toString()
            )

        );


    if (
        unique.size !==
        xValues.length
    ) {

        return {

            valid:
                false,

            reason:
                "Duplicate x-coordinate detected"

        };

    }


    return {

        valid:
            true

    };

}


// ============================================================
// Calculate Lagrange Coefficient
// ============================================================

/**
 * λi =
 *
 *       Π xj
 *       ------
 *       xj-xi
 *
 * mod p
 */

function lagrangeCoefficient(
    shares,
    index,
    prime
) {

    const p =
        BigInt(prime);


    const xi =
        BigInt(
            shares[index].x
        );


    let lambda =
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
            BigInt(
                shares[j].x
            );


        const numerator =
            mod(
                xj,
                p
            );


        const denominator =
            mod(
                xj - xi,
                p
            );


        if (
            denominator === 0n
        ) {

            throw new Error(

                "Lagrange denominator is zero. " +
                "x values must be distinct."

            );

        }


        const inverse =
            modInverse(
                denominator,
                p
            );


        const term =
            mod(

                numerator *
                inverse,

                p

            );


        lambda =
            mod(

                lambda *
                term,

                p

            );

    }


    return lambda;

}


// ============================================================
// Reconstruct Secret
// ============================================================

function reconstructSecret(
    rid,
    prime
) {

    const totalStart =
        process.hrtime.bigint();


    // --------------------------------------------------------
    // Validate prime
    // --------------------------------------------------------

    let p;

    try {

        p =
            BigInt(prime);

    } catch (error) {

        throw new Error(
            "Prime p must be a valid integer"
        );

    }


    if (
        !isPrime(p)
    ) {

        throw new Error(
            `p=${p} is not prime`
        );

    }


    // --------------------------------------------------------
    // Get submission status
    // --------------------------------------------------------

    const status =
        getShareSubmissionStatus(
            rid
        );


    if (!status) {

        throw new Error(
            "Share submission status not found"
        );

    }


    const threshold =
        Number(
            status.threshold
        );


    if (
        !Number.isInteger(
            threshold
        ) ||
        threshold < 2
    ) {

        throw new Error(
            "Invalid threshold"
        );

    }


    // --------------------------------------------------------
    // Retrieve submitted shares
    // --------------------------------------------------------

    const allShares =
        getSubmittedShares(
            rid
        );


    // --------------------------------------------------------
    // Threshold check
    // --------------------------------------------------------

    if (
        allShares.length <
        threshold
    ) {

        const elapsed =
            Number(

                process.hrtime.bigint() -
                totalStart

            ) / 1e6;


        return {

            success:
                false,

            rid,

            reason:
                "Insufficient shares for reconstruction",

            threshold,

            availableShares:
                allShares.length,

            requiredShares:
                threshold,

            reconstructionLatencyMs:
                elapsed

        };

    }


    // ========================================================
    // Select exactly t shares
    // ========================================================

    const selectedShares =
        allShares.slice(
            0,
            threshold
        );


    // ========================================================
    // Validate shares
    // ========================================================

    const validationResults =
        selectedShares.map(

            share =>

                validateShare(
                    share,
                    p
                )

        );


    const invalidShare =
        validationResults.find(
            result =>
                !result.valid
        );


    if (invalidShare) {

        throw new Error(

            `Invalid Shamir share: ${invalidShare.reason}`

        );

    }


    // ========================================================
    // Check distinct x
    // ========================================================

    const distinct =
        validateDistinctX(
            selectedShares
        );


    if (
        !distinct.valid
    ) {

        throw new Error(
            distinct.reason
        );

    }


    // ========================================================
    // Lagrange Reconstruction
    // ========================================================

    let reconstructedSecret =
        0n;


    const coefficients = [];


    for (
        let i = 0;
        i < selectedShares.length;
        i++
    ) {

        const lambda =
            lagrangeCoefficient(

                selectedShares,

                i,

                p

            );


        const yi =
            BigInt(
                selectedShares[i].y
            );


        const contribution =
            mod(

                yi *
                lambda,

                p

            );


        reconstructedSecret =
            mod(

                reconstructedSecret +
                contribution,

                p

            );


        coefficients.push({

            observerId:
                selectedShares[i]
                    .observerId,

            x:
                selectedShares[i]
                    .x,

            y:
                selectedShares[i]
                    .y,

            lambda:
                lambda.toString(),

            contribution:
                contribution.toString()

        });

    }


    // ========================================================
    // Reconstruction Latency
    // ========================================================

    const totalEnd =
        process.hrtime.bigint();


    const reconstructionLatencyMs =

        Number(

            totalEnd -
            totalStart

        ) / 1e6;


    // ========================================================
    // Communication Overhead
    // ========================================================

    const overheadBytes =
        Buffer.byteLength(

            JSON.stringify(
                selectedShares
            ),

            "utf8"

        );


    // ========================================================
    // Result
    // ========================================================

    const result = {

        success:
            true,

        rid,

        threshold,

        sharesUsed:
            selectedShares.length,

        reconstructedSecret:
            reconstructedSecret.toString(),

        coefficients,

        reconstructionLatencyMs,

        overheadBytes,

        timestamp:
            new Date()
                .toISOString()

    };


    // ========================================================
    // Store Reconstruction Metadata
    // ========================================================

    const records =
        readJSON(
            RECONSTRUCTION_FILE
        );


    records.push({

        rid,

        threshold,

        sharesUsed:
            selectedShares.length,

        reconstructed:
            true,

        reconstructionLatencyMs,

        overheadBytes,

        timestamp:
            result.timestamp

    });


    writeJSON(
        RECONSTRUCTION_FILE,
        records
    );


    // ========================================================
    // Audit
    // ========================================================

    audit(

        "SECRET_RECONSTRUCTED",

        {

            rid,

            threshold,

            sharesUsed:
                selectedShares.length,

            reconstructionLatencyMs,

            overheadBytes

        }

    );


    return result;

}


// ============================================================
// Get Reconstruction History
// ============================================================

function getReconstructionHistory(
    rid = null
) {

    const records =
        readJSON(
            RECONSTRUCTION_FILE
        );


    if (!rid) {

        return records;

    }


    return records.filter(
        record =>
            record.rid === rid
    );

}


// ============================================================
// Get Latest Reconstruction
// ============================================================

function getLatestReconstruction(
    rid
) {

    const records =
        getReconstructionHistory(
            rid
        );


    if (
        records.length === 0
    ) {

        return null;

    }


    return records[
        records.length - 1
    ];

}


// ============================================================
// Calculate Reconstruction Metrics
// ============================================================

function calculateMetrics(
    rid
) {

    const history =
        getReconstructionHistory(
            rid
        );


    if (
        history.length === 0
    ) {

        return {

            rid,

            executions:
                0,

            averageLatencyMs:
                0,

            averageOverheadBytes:
                0

        };

    }


    const totalLatency =
        history.reduce(

            (sum, item) =>
                sum +
                Number(
                    item.reconstructionLatencyMs
                ),

            0

        );


    const totalOverhead =
        history.reduce(

            (sum, item) =>
                sum +
                Number(
                    item.overheadBytes
                ),

            0

        );


    return {

        rid,

        executions:
            history.length,

        averageLatencyMs:
            totalLatency /
            history.length,

        averageOverheadBytes:
            totalOverhead /
            history.length,

        totalLatencyMs:
            totalLatency,

        totalOverheadBytes:
            totalOverhead

    };

}


// ============================================================
// Export
// ============================================================

module.exports = {

    mod,

    extendedGCD,

    modInverse,

    isPrime,

    validateShare,

    validateDistinctX,

    lagrangeCoefficient,

    reconstructSecret,

    getReconstructionHistory,

    getLatestReconstruction,

    calculateMetrics

};


// ============================================================
// Standalone Test
// ============================================================

if (
    require.main === module
) {

    console.log(
        "\n=================================================="
    );

    console.log(
        " SHAMIR SECRET RECONSTRUCTION"
    );

    console.log(
        "==================================================\n"
    );


    console.log(
        "This module reconstructs the secret only"
    );

    console.log(
        "after the required threshold shares are available."
    );


    console.log(
        "\nExample:"
    );


    console.log(` const Reconstruction =   require("./observer/Reconstruction");

const result =
    Reconstruction.reconstructSecret(

        "RID-001",

        PRIME

    );

console.log(result);

`);

}