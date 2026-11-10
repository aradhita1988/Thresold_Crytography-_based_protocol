/**
 * ============================================================
 * observer/Observer.js
 * ============================================================
 *
 * Observer Node Management
 *
 * Architecture:
 *
 *        Chain Y
 *           |
 *     Hospital Request
 *           |
 *           v
 *    +----------------+
 *    | Observer Nodes |
 *    +----------------+
 *      |    |    |    |
 *      v    v    v    v
 *     O1   O2   O3   O4 ...
 *           |
 *           v
 *      Threshold t
 *           |
 *           v
 *     Secret Shares
 *           |
 *           v
 *       Chain X
 *
 * ============================================================
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");


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
// Observer Configuration
// ============================================================

const DEFAULT_OBSERVER_COUNT =
    Number(
        process.env.OBSERVER_COUNT ||
        config.OBSERVER_COUNT ||
        5
    );


const MIN_STAKE =
    Number(
        process.env.MIN_OBSERVER_STAKE ||
        config.MIN_OBSERVER_STAKE ||
        10
    );


const MIN_THRESHOLD =
    Number(
        process.env.MIN_THRESHOLD ||
        config.MIN_THRESHOLD ||
        2
    );


const MAX_THRESHOLD =
    Number(
        process.env.MAX_THRESHOLD ||
        config.MAX_THRESHOLD ||
        DEFAULT_OBSERVER_COUNT
    );


// ============================================================
// Database
// ============================================================

const DATABASE_DIR =
    path.join(
        __dirname,
        "..",
        "database"
    );


const OBSERVER_FILE =
    path.join(
        DATABASE_DIR,
        "observers.json"
    );


const AUDIT_FILE =
    path.join(
        DATABASE_DIR,
        "audit.json"
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


    if (!fs.existsSync(OBSERVER_FILE)) {

        fs.writeFileSync(
            OBSERVER_FILE,
            "[]",
            "utf8"
        );

    }


    if (!fs.existsSync(AUDIT_FILE)) {

        fs.writeFileSync(
            AUDIT_FILE,
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

        if (!data.trim()) {
            return [];
        }

        return JSON.parse(data);

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
// Audit
// ============================================================

function audit(
    action,
    data = {}
) {

    const records =
        readJSON(
            AUDIT_FILE
        );

    records.push({

        timestamp:
            new Date()
                .toISOString(),

        actor:
            "ObserverManager",

        action,

        data

    });

    writeJSON(
        AUDIT_FILE,
        records
    );

}


// ============================================================
// Generate Observer ID
// ============================================================

function generateObserverId(
    index
) {

    return (

        "O" +

        String(index)
            .padStart(3, "0")

    );

}


// ============================================================
// Generate Observer Key
// ============================================================

function generateObserverKey() {

    return crypto
        .randomBytes(32)
        .toString("hex");

}


// ============================================================
// Generate Observer Ethereum-like Address
// ============================================================

function generateObserverAddress() {

    const randomBytes =
        crypto.randomBytes(20);

    return (
        "0x" +
        randomBytes.toString("hex")
    );

}


// ============================================================
// Create Observer
// ============================================================

function createObserver({

    id,

    name,

    stake = MIN_STAKE,

    address = null

}) {

    if (!id) {

        throw new Error(
            "Observer ID is required"
        );

    }


    if (
        Number(stake) < MIN_STAKE
    ) {

        throw new Error(

            `Observer ${id} does not satisfy ` +
            `minimum stake requirement ${MIN_STAKE}`

        );

    }


    return {

        id,

        name:
            name ||
            `Observer-${id}`,

        address:
            address ||
            generateObserverAddress(),

        stake:
            Number(stake),

        registered:
            true,

        active:
            true,

        reputation:
            100,

        approvals:
            0,

        rejections:
            0,

        submittedShares:
            0,

        maliciousFlags:
            0,

        createdAt:
            new Date()
                .toISOString()

    };

}


// ============================================================
// Register Observer
// ============================================================

function registerObserver(
    observer
) {

    const observers =
        readJSON(
            OBSERVER_FILE
        );


    const existing =
        observers.find(
            item =>
                item.id === observer.id
        );


    if (existing) {

        throw new Error(

            `Observer ${observer.id} is already registered`

        );

    }


    observers.push(
        observer
    );


    writeJSON(
        OBSERVER_FILE,
        observers
    );


    audit(

        "OBSERVER_REGISTERED",

        {

            observerId:
                observer.id,

            address:
                observer.address,

            stake:
                observer.stake

        }

    );


    return observer;

}


// ============================================================
// Get All Observers
// ============================================================

function getObservers() {

    return readJSON(
        OBSERVER_FILE
    );

}


// ============================================================
// Get Active Observers
// ============================================================

function getActiveObservers() {

    return getObservers()
        .filter(
            observer =>
                observer.registered === true &&
                observer.active === true
        );

}


// ============================================================
// Get Observer
// ============================================================

function getObserver(
    observerId
) {

    return getObservers()
        .find(
            observer =>
                observer.id === observerId
        );

}


// ============================================================
// Verify Observer Registration
// ============================================================

function verifyObserverRegistration(
    observerId
) {

    const start =
        process.hrtime.bigint();


    const observer =
        getObserver(
            observerId
        );


    const registered =
        !!(
            observer &&
            observer.registered &&
            observer.active
        );


    const end =
        process.hrtime.bigint();


    const latencyMs =

        Number(
            end - start
        ) / 1e6;


    return {

        valid:
            registered,

        latencyMs,

        observer

    };

}


// ============================================================
// Verify Stake
// ============================================================

function verifyStake(
    observerId
) {

    const observer =
        getObserver(
            observerId
        );


    if (!observer) {

        return {

            valid:
                false,

            reason:
                "Observer not registered"

        };

    }


    const valid =
        Number(observer.stake)
        >=
        MIN_STAKE;


    return {

        valid,

        stake:
            observer.stake,

        minimumStake:
            MIN_STAKE,

        reason:
            valid
                ? "Stake requirement satisfied"
                : "Insufficient stake"

    };

}


// ============================================================
// Verify Observer Eligibility
// ============================================================

function verifyEligibility(
    observerId
) {

    const start =
        process.hrtime.bigint();


    const registration =
        verifyObserverRegistration(
            observerId
        );


    if (!registration.valid) {

        return {

            eligible:
                false,

            reason:
                "Observer is not registered or inactive",

            detectionLatencyMs:
                Number(
                    process.hrtime.bigint() -
                    start
                ) / 1e6

        };

    }


    const stake =
        verifyStake(
            observerId
        );


    const end =
        process.hrtime.bigint();


    const detectionLatencyMs =

        Number(
            end - start
        ) / 1e6;


    return {

        eligible:
            stake.valid,

        observer:
            registration.observer,

        stake:

            stake.stake,

        detectionLatencyMs,

        reason:
            stake.valid
                ? "Observer eligible"
                : stake.reason

    };

}


// ============================================================
// Random Threshold
// ============================================================

/**
 * Generates a random threshold.
 *
 * Example:
 *
 * n = 5
 *
 * Possible thresholds:
 *
 *      2
 *      3
 *      4
 *      5
 *
 * t is always:
 *
 *      2 <= t <= n
 *
 * This is used for experimental evaluation.
 */

function generateRandomThreshold(
    observerCount
) {

    if (
        observerCount < MIN_THRESHOLD
    ) {

        throw new Error(

            "Observer count is smaller than minimum threshold"

        );

    }


    const max =
        Math.min(
            observerCount,
            MAX_THRESHOLD
        );


    const range =
        max -
        MIN_THRESHOLD +
        1;


    const random =
        crypto.randomInt(
            0,
            range
        );


    return (
        MIN_THRESHOLD +
        random
    );

}


// ============================================================
// Validate Threshold
// ============================================================

function validateThreshold(
    threshold,
    observerCount
) {

    return (

        Number.isInteger(
            Number(threshold)
        )

        &&

        Number(threshold)
        >=
        2

        &&

        Number(threshold)
        <=
        observerCount

    );

}


// ============================================================
// Create Observer Set
// ============================================================

function createObserverSet(
    count = DEFAULT_OBSERVER_COUNT
) {

    if (
        count < 2
    ) {

        throw new Error(
            "At least 2 observers are required"
        );

    }


    const observers = [];


    for (
        let i = 1;
        i <= count;
        i++
    ) {

        const observer =
            createObserver({

                id:
                    generateObserverId(
                        i
                    ),

                name:
                    `Observer-${i}`,

                stake:
                    MIN_STAKE +
                    crypto.randomInt(
                        1,
                        91
                    )

            });


        observers.push(
            observer
        );

    }


    return observers;

}


// ============================================================
// Register Default Observers
// ============================================================

function registerDefaultObservers(
    count = DEFAULT_OBSERVER_COUNT
) {

    const existing =
        getObservers();


    if (
        existing.length >= count
    ) {

        return existing;

    }


    const newObservers =
        createObserverSet(
            count
        );


    for (
        const observer of newObservers
    ) {

        const alreadyExists =
            existing.find(
                item =>
                    item.id === observer.id
            );


        if (!alreadyExists) {

            registerObserver(
                observer
            );

        }

    }


    return getObservers();

}


// ============================================================
// Generate Threshold Configuration
// ============================================================

function createThresholdConfiguration(
    observerCount = DEFAULT_OBSERVER_COUNT
) {

    const threshold =
        generateRandomThreshold(
            observerCount
        );


    if (
        !validateThreshold(
            threshold,
            observerCount
        )
    ) {

        throw new Error(
            "Generated threshold is invalid"
        );

    }


    const configuration = {

        observerCount,

        threshold,

        generatedAt:
            new Date()
                .toISOString(),

        rule:
            `2 <= t <= ${observerCount}`

    };


    audit(

        "RANDOM_THRESHOLD_GENERATED",

        configuration

    );


    return configuration;

}


// ============================================================
// Observer Approval Eligibility
// ============================================================

function canApprove(
    observerId
) {

    const result =
        verifyEligibility(
            observerId
        );


    return {

        canApprove:
            result.eligible,

        observer:
            result.observer,

        detectionLatencyMs:
            result.detectionLatencyMs,

        reason:
            result.reason

    };

}


// ============================================================
// Update Reputation
// ============================================================

function updateReputation(

    observerId,

    delta

) {

    const observers =
        getObservers();


    const index =
        observers.findIndex(
            observer =>
                observer.id === observerId
        );


    if (
        index === -1
    ) {

        throw new Error(
            "Observer not found"
        );

    }


    observers[index].reputation +=
        Number(delta);


    if (
        observers[index].reputation < 0
    ) {

        observers[index].reputation = 0;

    }


    if (
        observers[index].reputation > 100
    ) {

        observers[index].reputation = 100;

    }


    writeJSON(
        OBSERVER_FILE,
        observers
    );


    audit(

        "OBSERVER_REPUTATION_UPDATED",

        {

            observerId,

            delta,

            reputation:
                observers[index]
                    .reputation

        }

    );


    return observers[index];

}


// ============================================================
// Record Approval
// ============================================================

function recordApproval(
    observerId
) {

    const observers =
        getObservers();


    const index =
        observers.findIndex(
            observer =>
                observer.id === observerId
        );


    if (
        index === -1
    ) {

        throw new Error(
            "Observer not found"
        );

    }


    observers[index].approvals += 1;


    writeJSON(
        OBSERVER_FILE,
        observers
    );


    return observers[index];

}


// ============================================================
// Record Rejection
// ============================================================

function recordRejection(
    observerId
) {

    const observers =
        getObservers();


    const index =
        observers.findIndex(
            observer =>
                observer.id === observerId
        );


    if (
        index === -1
    ) {

        throw new Error(
            "Observer not found"
        );

    }


    observers[index].rejections += 1;


    writeJSON(
        OBSERVER_FILE,
        observers
    );


    return observers[index];

}


// ============================================================
// Record Share Submission
// ============================================================

function recordShareSubmission(
    observerId
) {

    const observers =
        getObservers();


    const index =
        observers.findIndex(
            observer =>
                observer.id === observerId
        );


    if (
        index === -1
    ) {

        throw new Error(
            "Observer not found"
        );

    }


    observers[index].submittedShares += 1;


    writeJSON(
        OBSERVER_FILE,
        observers
    );


    audit(

        "OBSERVER_SHARE_SUBMITTED",

        {

            observerId

        }

    );


    return observers[index];

}


// ============================================================
// Flag Malicious Observer
// ============================================================

function flagMaliciousObserver(
    observerId,
    penalty = 10
) {

    const observers =
        getObservers();


    const index =
        observers.findIndex(
            observer =>
                observer.id === observerId
        );


    if (
        index === -1
    ) {

        throw new Error(
            "Observer not found"
        );

    }


    observers[index].maliciousFlags += 1;


    observers[index].reputation =
        Math.max(

            0,

            observers[index].reputation -
            penalty

        );


    writeJSON(
        OBSERVER_FILE,
        observers
    );


    audit(

        "OBSERVER_FLAGGED_MALICIOUS",

        {

            observerId,

            penalty,

            reputation:
                observers[index]
                    .reputation

        }

    );


    return observers[index];

}


// ============================================================
// Deactivate Observer
// ============================================================

function deactivateObserver(
    observerId
) {

    const observers =
        getObservers();


    const index =
        observers.findIndex(
            observer =>
                observer.id === observerId
        );


    if (
        index === -1
    ) {

        throw new Error(
            "Observer not found"
        );

    }


    observers[index].active =
        false;


    writeJSON(
        OBSERVER_FILE,
        observers
    );


    audit(

        "OBSERVER_DEACTIVATED",

        {

            observerId

        }

    );


    return observers[index];

}


// ============================================================
// Observer Statistics
// ============================================================

function getObserverStatistics() {

    const observers =
        getObservers();


    const active =
        observers.filter(
            observer =>
                observer.active
        );


    const totalStake =
        observers.reduce(

            (sum, observer) =>
                sum +
                Number(
                    observer.stake
                ),

            0

        );


    const averageReputation =
        observers.length > 0

            ?

            observers.reduce(

                (sum, observer) =>
                    sum +
                    Number(
                        observer.reputation
                    ),

                0

            )
            /
            observers.length

            :

            0;


    return {

        totalObservers:
            observers.length,

        activeObservers:
            active.length,

        totalStake,

        averageReputation

    };

}


// ============================================================
// Export
// ============================================================

module.exports = {

    generateObserverId,

    generateObserverKey,

    generateObserverAddress,

    createObserver,

    registerObserver,

    getObservers,

    getActiveObservers,

    getObserver,

    verifyObserverRegistration,

    verifyStake,

    verifyEligibility,

    generateRandomThreshold,

    validateThreshold,

    createObserverSet,

    registerDefaultObservers,

    createThresholdConfiguration,

    canApprove,

    updateReputation,

    recordApproval,

    recordRejection,

    recordShareSubmission,

    flagMaliciousObserver,

    deactivateObserver,

    getObserverStatistics

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
        " OBSERVER NODE INITIALIZATION"
    );

    console.log(
        "==================================================\n"
    );


    try {

        // ----------------------------------------------------
        // Create observers
        // ----------------------------------------------------

        const observers =
            registerDefaultObservers(
                DEFAULT_OBSERVER_COUNT
            );


        console.log(
            "Registered Observers:"
        );


        console.table(

            observers.map(
                observer => ({

                    ID:
                        observer.id,

                    Address:
                        observer.address,

                    Stake:
                        observer.stake,

                    Reputation:
                        observer.reputation,

                    Active:
                        observer.active

                })
            )

        );


        // ----------------------------------------------------
        // Random threshold
        // ----------------------------------------------------

        const threshold =
            createThresholdConfiguration(
                observers.length
            );


        console.log(
            "\nRandom Threshold:"
        );


        console.log(
            `n = ${threshold.observerCount}`
        );


        console.log(
            `t = ${threshold.threshold}`
        );


        // ----------------------------------------------------
        // Eligibility test
        // ----------------------------------------------------

        console.log(
            "\nObserver Eligibility:"
        );


        for (
            const observer of observers
        ) {

            const result =
                verifyEligibility(
                    observer.id
                );


            console.log(

                observer.id,

                "=>",

                result.eligible
                    ? "ELIGIBLE"
                    : "NOT ELIGIBLE",

                "| Detection Latency:",

                result.detectionLatencyMs
                    .toFixed(6),

                "ms"

            );

        }


        // ----------------------------------------------------
        // Statistics
        // ----------------------------------------------------

        console.log(
            "\nObserver Statistics:"
        );


        console.table(
            getObserverStatistics()
        );


        console.log(
            "\nObserver initialization completed."
        );


    } catch (error) {

        console.error(
            "\nObserver initialization failed:"
        );

        console.error(
            error.message
        );

        process.exitCode = 1;

    }

}