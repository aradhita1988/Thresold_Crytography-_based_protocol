/**
 * ============================================================
 * observer/Reputation.js
 * ============================================================
 *
 * Observer Reputation and Timeout Management
 *
 * Based on the observer protocol:
 *
 * If:
 *
 *   approve_i = 1 AND submit_i = 0
 *
 * after timeout τ:
 *
 *   Rep(O_i) = Rep(O_i) - δ
 *
 * and:
 *
 *   O_i is flagged as malicious.
 *
 * ============================================================
 */

const fs = require("fs");
const path = require("path");


// ============================================================
// Database Paths
// ============================================================

const DATABASE_DIR =
    path.join(
        __dirname,
        "..",
        "database"
    );

const OBSERVERS_FILE =
    path.join(
        DATABASE_DIR,
        "observers.json"
    );

const AUDIT_FILE =
    path.join(
        DATABASE_DIR,
        "audit.json"
    );

const REPUTATION_FILE =
    path.join(
        DATABASE_DIR,
        "reputation.json"
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


    if (!fs.existsSync(OBSERVERS_FILE)) {

        fs.writeFileSync(

            OBSERVERS_FILE,

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


    if (!fs.existsSync(REPUTATION_FILE)) {

        fs.writeFileSync(

            REPUTATION_FILE,

            "[]",

            "utf8"

        );

    }

}


// ============================================================
// Read JSON
// ============================================================

function readJSON(
    file
) {

    ensureDatabase();

    try {

        const data =
            fs.readFileSync(
                file,
                "utf8"
            );


        if (
            !data.trim()
        ) {

            return [];

        }


        return JSON.parse(
            data
        );

    } catch (error) {

        console.error(

            `Error reading ${file}:`,

            error.message

        );


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
            "ReputationManager",

        action,

        data

    });


    writeJSON(
        AUDIT_FILE,
        records
    );

}


// ============================================================
// Get Observer
// ============================================================

function getObserver(
    observerId
) {

    const observers =
        readJSON(
            OBSERVERS_FILE
        );


    return observers.find(

        observer =>

            String(
                observer.observerId
            ) ===
            String(
                observerId
            )

    );

}


// ============================================================
// Save Observer
// ============================================================

function saveObserver(
    observer
) {

    const observers =
        readJSON(
            OBSERVERS_FILE
        );


    const index =
        observers.findIndex(

            item =>

                String(
                    item.observerId
                ) ===
                String(
                    observer.observerId
                )

        );


    if (
        index === -1
    ) {

        observers.push(
            observer
        );

    } else {

        observers[index] =
            observer;

    }


    writeJSON(
        OBSERVERS_FILE,
        observers
    );

}


// ============================================================
// Initialize Observer Reputation
// ============================================================

function initializeObserver(
    observerId,
    initialReputation = 100
) {

    let observer =
        getObserver(
            observerId
        );


    if (!observer) {

        observer = {

            observerId,

            reputation:
                Number(
                    initialReputation
                ),

            successfulSubmissions:
                0,

            failedSubmissions:
                0,

            timeoutCount:
                0,

            malicious:
                false,

            registered:
                true,

            createdAt:
                new Date()
                    .toISOString()

        };

    } else {

        if (
            observer.reputation ===
            undefined
        ) {

            observer.reputation =
                Number(
                    initialReputation
                );

        }

        if (
            observer.successfulSubmissions ===
            undefined
        ) {

            observer.successfulSubmissions =
                0;

        }

        if (
            observer.failedSubmissions ===
            undefined
        ) {

            observer.failedSubmissions =
                0;

        }

        if (
            observer.timeoutCount ===
            undefined
        ) {

            observer.timeoutCount =
                0;

        }

        if (
            observer.malicious ===
            undefined
        ) {

            observer.malicious =
                false;

        }

    }


    saveObserver(
        observer
    );


    return observer;

}


// ============================================================
// Increase Reputation
// ============================================================

function rewardObserver(
    observerId,
    reward = 1,
    rid = null
) {

    let observer =
        initializeObserver(
            observerId
        );


    const oldReputation =
        Number(
            observer.reputation
        );


    observer.reputation =
        oldReputation +
        Number(
            reward
        );


    observer.successfulSubmissions =
        Number(
            observer.successfulSubmissions
        ) + 1;


    saveObserver(
        observer
    );


    const record = {

        observerId,

        rid,

        type:
            "REWARD",

        oldReputation,

        change:
            Number(
                reward
            ),

        newReputation:
            observer.reputation,

        timestamp:
            new Date()
                .toISOString()

    };


    const history =
        readJSON(
            REPUTATION_FILE
        );


    history.push(
        record
    );


    writeJSON(
        REPUTATION_FILE,
        history
    );


    audit(

        "OBSERVER_REPUTATION_INCREASED",

        record

    );


    return observer;

}


// ============================================================
// Penalize Observer
// ============================================================

function penalizeObserver(
    observerId,
    delta = 5,
    rid = null
) {

    const detectionStart =
        process.hrtime.bigint();


    let observer =
        initializeObserver(
            observerId
        );


    const oldReputation =
        Number(
            observer.reputation
        );


    const penalty =
        Math.max(
            0,
            Number(
                delta
            )
        );


    observer.reputation =
        Math.max(

            0,

            oldReputation -
            penalty

        );


    observer.failedSubmissions =
        Number(
            observer.failedSubmissions
        ) + 1;


    observer.timeoutCount =
        Number(
            observer.timeoutCount
        ) + 1;


    /*
     * Flag observer if reputation reaches zero.
     */
    if (
        observer.reputation <= 0
    ) {

        observer.malicious =
            true;

    }


    saveObserver(
        observer
    );


    const detectionEnd =
        process.hrtime.bigint();


    const detectionLatencyMs =

        Number(

            detectionEnd -
            detectionStart

        ) / 1e6;


    const record = {

        observerId,

        rid,

        type:
            "PENALTY",

        oldReputation,

        change:
            -penalty,

        newReputation:
            observer.reputation,

        timeoutCount:
            observer.timeoutCount,

        malicious:
            observer.malicious,

        detectionLatencyMs,

        timestamp:
            new Date()
                .toISOString()

    };


    const history =
        readJSON(
            REPUTATION_FILE
        );


    history.push(
        record
    );


    writeJSON(
        REPUTATION_FILE,
        history
    );


    audit(

        "OBSERVER_PENALIZED",

        record

    );


    return {

        ...observer,

        detectionLatencyMs

    };

}


// ============================================================
// Flag Observer as Malicious
// ============================================================

function flagMalicious(
    observerId,
    reason = "Protocol violation",
    rid = null
) {

    const detectionStart =
        process.hrtime.bigint();


    let observer =
        initializeObserver(
            observerId
        );


    observer.malicious =
        true;


    observer.flagReason =
        reason;


    observer.flaggedAt =
        new Date()
            .toISOString();


    saveObserver(
        observer
    );


    const detectionEnd =
        process.hrtime.bigint();


    const detectionLatencyMs =

        Number(

            detectionEnd -
            detectionStart

        ) / 1e6;


    const record = {

        observerId,

        rid,

        type:
            "MALICIOUS_FLAG",

        reason,

        detectionLatencyMs,

        timestamp:
            new Date()
                .toISOString()

    };


    const history =
        readJSON(
            REPUTATION_FILE
        );


    history.push(
        record
    );


    writeJSON(
        REPUTATION_FILE,
        history
    );


    audit(

        "OBSERVER_FLAGGED_MALICIOUS",

        record

    );


    return {

        success:
            true,

        observerId,

        malicious:
            true,

        reason,

        detectionLatencyMs

    };

}


// ============================================================
// Unflag Observer
// ============================================================

function unflagObserver(
    observerId
) {

    const observer =
        getObserver(
            observerId
        );


    if (!observer) {

        return {

            success:
                false,

            reason:
                "Observer not found"

        };

    }


    observer.malicious =
        false;


    observer.flagReason =
        null;


    observer.unflaggedAt =
        new Date()
            .toISOString();


    saveObserver(
        observer
    );


    audit(

        "OBSERVER_UNFLAGGED",

        {

            observerId

        }

    );


    return {

        success:
            true,

        observerId,

        malicious:
            false

    };

}


// ============================================================
// Timeout Verification
// ============================================================

/**
 * Verify whether an approved observer submitted
 * its Shamir share within timeout τ.
 *
 * Protocol condition:
 *
 * approve_i = 1 AND submit_i = 0
 *
 * after timeout:
 *
 * Rep(Oi) = Rep(Oi) - δ
 */

function checkObserverTimeout(
    observerId,
    approvalTime,
    shareSubmitted,
    timeoutMs,
    delta = 5,
    rid = null
) {

    const start =
        process.hrtime.bigint();


    const now =
        Date.now();


    const approvedAt =
        new Date(
            approvalTime
        ).getTime();


    const elapsedMs =
        now -
        approvedAt;


    /*
     * Observer submitted its share.
     */
    if (
        shareSubmitted === true
    ) {

        const end =
            process.hrtime.bigint();


        return {

            observerId,

            rid,

            timedOut:
                false,

            submitted:
                true,

            elapsedMs,

            timeoutMs,

            detectionLatencyMs:

                Number(
                    end -
                    start
                ) / 1e6

        };

    }


    /*
     * Timeout has not occurred yet.
     */
    if (
        elapsedMs <
        Number(
            timeoutMs
        )
    ) {

        const end =
            process.hrtime.bigint();


        return {

            observerId,

            rid,

            timedOut:
                false,

            submitted:
                false,

            waiting:
                true,

            elapsedMs,

            remainingMs:

                Number(
                    timeoutMs
                ) -
                elapsedMs,

            timeoutMs,

            detectionLatencyMs:

                Number(
                    end -
                    start
                ) / 1e6

        };

    }


    /*
     * Timeout occurred.
     *
     * Observer approved but did not submit.
     */
    const result =
        penalizeObserver(

            observerId,

            delta,

            rid

        );


    const end =
        process.hrtime.bigint();


    return {

        observerId,

        rid,

        timedOut:
            true,

        submitted:
            false,

        malicious:
            result.malicious,

        reputation:
            result.reputation,

        elapsedMs,

        timeoutMs,

        penalty:
            delta,

        detectionLatencyMs:

            Number(
                end -
                start
            ) / 1e6

    };

}


// ============================================================
// Process All Observer Timeouts
// ============================================================

function processTimeouts(
    observers,
    timeoutMs,
    delta = 5,
    rid = null
) {

    if (
        !Array.isArray(
            observers
        )
    ) {

        throw new Error(
            "observers must be an array"
        );

    }


    const start =
        process.hrtime.bigint();


    const results = [];


    for (
        const observer of observers
    ) {

        if (
            !observer.approved
        ) {

            continue;

        }


        const result =
            checkObserverTimeout(

                observer.observerId,

                observer.approvalTime,

                observer.shareSubmitted,

                timeoutMs,

                delta,

                rid

            );


        results.push(
            result
        );

    }


    const end =
        process.hrtime.bigint();


    const processingLatencyMs =

        Number(

            end -
            start

        ) / 1e6;


    const timedOut =
        results.filter(
            result =>
                result.timedOut
        );


    const successful =
        results.filter(
            result =>
                result.submitted
        );


    const overheadBytes =
        Buffer.byteLength(

            JSON.stringify(
                results
            ),

            "utf8"

        );


    audit(

        "OBSERVER_TIMEOUT_SCAN",

        {

            rid,

            observersChecked:
                results.length,

            timedOut:
                timedOut.length,

            successfulSubmissions:
                successful.length,

            processingLatencyMs,

            overheadBytes

        }

    );


    return {

        rid,

        observersChecked:
            results.length,

        timedOut:
            timedOut.length,

        successfulSubmissions:
            successful.length,

        processingLatencyMs,

        overheadBytes,

        results

    };

}


// ============================================================
// Get Observer Reputation
// ============================================================

function getReputation(
    observerId
) {

    const observer =
        getObserver(
            observerId
        );


    if (!observer) {

        return null;

    }


    return {

        observerId:
            observer.observerId,

        reputation:
            Number(
                observer.reputation ||
                0
            ),

        successfulSubmissions:
            Number(
                observer.successfulSubmissions ||
                0
            ),

        failedSubmissions:
            Number(
                observer.failedSubmissions ||
                0
            ),

        timeoutCount:
            Number(
                observer.timeoutCount ||
                0
            ),

        malicious:
            Boolean(
                observer.malicious
            )

    };

}


// ============================================================
// Get All Reputation Records
// ============================================================

function getAllReputations() {

    const observers =
        readJSON(
            OBSERVERS_FILE
        );


    return observers.map(

        observer => ({

            observerId:
                observer.observerId,

            reputation:
                Number(
                    observer.reputation ||
                    0
                ),

            successfulSubmissions:
                Number(
                    observer.successfulSubmissions ||
                    0
                ),

            failedSubmissions:
                Number(
                    observer.failedSubmissions ||
                    0
                ),

            timeoutCount:
                Number(
                    observer.timeoutCount ||
                    0
                ),

            malicious:
                Boolean(
                    observer.malicious
                )

        })

    );

}


// ============================================================
// Get Reputation History
// ============================================================

function getReputationHistory(
    observerId = null
) {

    const history =
        readJSON(
            REPUTATION_FILE
        );


    if (!observerId) {

        return history;

    }


    return history.filter(

        record =>

            String(
                record.observerId
            ) ===
            String(
                observerId
            )

    );

}


// ============================================================
// Calculate Observer Reliability
// ============================================================

function calculateReliability(
    observerId
) {

    const observer =
        getObserver(
            observerId
        );


    if (!observer) {

        return null;

    }


    const successful =
        Number(
            observer.successfulSubmissions ||
            0
        );


    const failed =
        Number(
            observer.failedSubmissions ||
            0
        );


    const total =
        successful +
        failed;


    const reliability =
        total === 0
            ? 100
            : (
                successful /
                total
            ) *
            100;


    return {

        observerId,

        successful,

        failed,

        total,

        reliabilityPercent:
            Number(
                reliability.toFixed(2)
            ),

        reputation:
            Number(
                observer.reputation ||
                0
            ),

        malicious:
            Boolean(
                observer.malicious
            )

    };

}


// ============================================================
// Reset Reputation
// ============================================================

function resetReputation(
    observerId,
    reputation = 100
) {

    const observer =
        getObserver(
            observerId
        );


    if (!observer) {

        return {

            success:
                false,

            reason:
                "Observer not found"

        };

    }


    observer.reputation =
        Number(
            reputation
        );


    observer.successfulSubmissions =
        0;


    observer.failedSubmissions =
        0;


    observer.timeoutCount =
        0;


    observer.malicious =
        false;


    observer.flagReason =
        null;


    saveObserver(
        observer
    );


    audit(

        "OBSERVER_REPUTATION_RESET",

        {

            observerId,

            reputation

        }

    );


    return {

        success:
            true,

        observerId,

        reputation

    };

}


// ============================================================
// Export
// ============================================================

module.exports = {

    initializeObserver,

    getObserver,

    rewardObserver,

    penalizeObserver,

    flagMalicious,

    unflagObserver,

    checkObserverTimeout,

    processTimeouts,

    getReputation,

    getAllReputations,

    getReputationHistory,

    calculateReliability,

    resetReputation

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
        " OBSERVER REPUTATION MANAGER"
    );

    console.log(
        "==================================================\n"
    );


    console.log(
        "Example:"
    );


    console.log(`

const Reputation =
    require("./observer/Reputation");


// Initialize observer
Reputation.initializeObserver(
    "O1",
    100
);


// Reward observer after successful share
Reputation.rewardObserver(
    "O1",
    1,
    "RID-001"
);


// Penalize observer after timeout
Reputation.penalizeObserver(
    "O2",
    5,
    "RID-001"
);


// Check reputation
console.log(
    Reputation.getReputation("O1")
);

`);

}