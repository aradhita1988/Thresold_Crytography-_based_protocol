/**
 * ============================================================
 * config.js
 * ============================================================
 *
 * Central configuration for the healthcare blockchain
 * experiment.
 *
 * ============================================================
 */

require("dotenv").config();


// ============================================================
// Helper
// ============================================================

function getNumber(
    value,
    defaultValue
) {

    const number =
        Number(value);


    if (
        Number.isNaN(number)
    ) {

        return defaultValue;

    }


    return number;

}


// ============================================================
// Configuration
// ============================================================

const config = {

    // --------------------------------------------------------
    // Environment
    // --------------------------------------------------------

    environment:
        process.env.NODE_ENV ||
        "development",


    // --------------------------------------------------------
    // Chain X
    // --------------------------------------------------------

    chainX: {

        name:
            "Chain-X",

        type:
            "Patient Chain",

        url:
            process.env.CHAIN_X_URL ||
            "http://127.0.0.1:7545",

        networkId:
            getNumber(

                process.env.CHAIN_X_NETWORK_ID,

                5777

            )

    },


    // --------------------------------------------------------
    // Chain Y
    // --------------------------------------------------------

    chainY: {

        name:
            "Chain-Y",

        type:
            "Hospital Chain",

        url:
            process.env.CHAIN_Y_URL ||
            "http://127.0.0.1:7546",

        networkId:
            getNumber(

                process.env.CHAIN_Y_NETWORK_ID,

                5778

            )

    },


    // --------------------------------------------------------
    // Observer configuration
    // --------------------------------------------------------

    observers: {

        total:
            getNumber(

                process.env.TOTAL_OBSERVERS,

                5

            ),

        minThreshold:
            getNumber(

                process.env.MIN_THRESHOLD,

                2

            ),

        minimumStake:
            process.env.MIN_OBSERVER_STAKE ||
            "10000000000000000"

    },


    // --------------------------------------------------------
    // Healthcare access
    // --------------------------------------------------------

    access: {

        duration:

            getNumber(

                process.env.ACCESS_DURATION,

                60

            )

    },


    // --------------------------------------------------------
    // Shamir Secret Sharing
    // --------------------------------------------------------

    shamir: {

        prime:

            process.env.SHAMIR_PRIME ||

            "2305843009213693951"

    },


    // --------------------------------------------------------
    // Logging
    // --------------------------------------------------------

    logging: {

        audit:

            process.env.ENABLE_AUDIT_LOG ===
            "true",

        metrics:

            process.env.ENABLE_METRICS !==
            "false"

    }

};


// ============================================================
// Configuration Validation
// ============================================================

if (
    config.observers.total < 2
) {

    throw new Error(
        "TOTAL_OBSERVERS must be at least 2."
    );

}


if (
    config.observers.minThreshold < 2
) {

    throw new Error(
        "MIN_THRESHOLD must be at least 2."
    );

}


if (
    config.observers.minThreshold >
    config.observers.total
) {

    throw new Error(

        "MIN_THRESHOLD cannot exceed " +
        "TOTAL_OBSERVERS."

    );

}


// ============================================================
// Export
// ============================================================

module.exports =
    config;