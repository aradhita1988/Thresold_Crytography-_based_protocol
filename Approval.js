/**
 * ============================================================
 * observer/Approval.js
 * ============================================================
 *
 * Algorithm 2: Observer Approval Protocol
 *
 * Require:
 *   Request identifier RID
 *   Threshold t
 *
 * Implements:
 *
 *   A(RID) <- 0
 *
 *   For every observer:
 *       Verify registration
 *       Check stake
 *       Approve / Reject
 *       Update approval counter
 *
 *   If A(RID) >= t:
 *       Request approved
 *
 * ============================================================
 */

const fs = require("fs");
const path = require("path");

const {
    getObservers,
    getObserver,
    verifyObserverRegistration,
    verifyStake,
    canApprove,
    recordApproval,
    recordRejection,
    updateReputation,
    flagMaliciousObserver,
    generateRandomThreshold,
    validateThreshold
} = require("./Observer");


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


const APPROVAL_FILE =
    path.join(
        DATABASE_DIR,
        "approvals.json"
    );


// ============================================================
// Ensure Database
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


    if (!fs.existsSync(APPROVAL_FILE)) {

        fs.writeFileSync(
            APPROVAL_FILE,
            "[]",
            "utf8"
        );

    }

}


// ============================================================
// JSON Helpers
// ============================================================

function readJSON(file) {

    ensureDatabase();

    try {

        const content =
            fs.readFileSync(
                file,
                "utf8"
            );

        return content.trim()
            ? JSON.parse(content)
            : [];

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

    const records =
        readJSON(
            AUDIT_FILE
        );


    records.push({

        timestamp:
            new Date()
                .toISOString(),

        actor:
            "Observer",

        action,

        data

    });


    writeJSON(
        AUDIT_FILE,
        records
    );

}


// ============================================================
// Get Request Approval State
// ============================================================

function getApprovalState(
    rid
) {

    const approvals =
        readJSON(
            APPROVAL_FILE
        );


    let state =
        approvals.find(
            item =>
                item.rid === rid
        );


    if (!state) {

        state = {

            rid,

            threshold:
                null,

            approvalCount:
                0,

            rejectedCount:
                0,

            approved:
                false,

            expired:
                false,

            observers: [],

            startedAt:
                null,

            completedAt:
                null

        };

    }


    return state;

}


// ============================================================
// Save Approval State
// ============================================================

function saveApprovalState(
    state
) {

    const approvals =
        readJSON(
            APPROVAL_FILE
        );


    const index =
        approvals.findIndex(
            item =>
                item.rid === state.rid
        );


    if (index === -1) {

        approvals.push(
            state
        );

    } else {

        approvals[index] =
            state;

    }


    writeJSON(
        APPROVAL_FILE,
        approvals
    );


    return state;

}


// ============================================================
// Initialize Request
// ============================================================

function initializeApproval(
    rid,
    threshold = null,
    observerCount = null
) {

    if (!rid) {

        throw new Error(
            "Request ID (RID) is required"
        );

    }


    const observers =
        observerCount
            ? getObservers()
                .slice(
                    0,
                    observerCount
                )
            : getObservers();


    if (
        observers.length < 2
    ) {

        throw new Error(
            "At least two observers are required"
        );

    }


    // --------------------------------------------------------
    // Generate random threshold if not supplied
    // --------------------------------------------------------

    if (
        threshold === null ||
        threshold === undefined
    ) {

        threshold =
            generateRandomThreshold(
                observers.length
            );

    }


    // --------------------------------------------------------
    // Validate threshold
    // --------------------------------------------------------

    if (
        !validateThreshold(
            threshold,
            observers.length
        )
    ) {

        throw new Error(

            `Invalid threshold t=${threshold}. ` +
            `Required: 2 <= t <= ${observers.length}`

        );

    }


    const existing =
        getApprovalState(
            rid
        );


    if (
        existing.startedAt
    ) {

        return existing;

    }


    const state = {

        rid,

        threshold:
            Number(threshold),

        observerCount:
            observers.length,

        approvalCount:
            0,

        rejectedCount:
            0,

        approved:
            false,

        expired:
            false,

        observers: [],

        startedAt:
            Date.now(),

        completedAt:
            null

    };


    saveApprovalState(
        state
    );


    audit(

        "APPROVAL_PROTOCOL_STARTED",

        {

            rid,

            threshold,

            observerCount:
                observers.length

        }

    );


    return state;

}


// ============================================================
// Validate Observer
// ============================================================

function validateObserverForApproval(
    observerId
) {

    const start =
        process.hrtime.bigint();


    const registration =
        verifyObserverRegistration(
            observerId
        );


    if (
        !registration.valid
    ) {

        return {

            valid:
                false,

            observerId,

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


    if (
        !stake.valid
    ) {

        return {

            valid:
                false,

            observerId,

            reason:
                "Observer does not satisfy minimum stake",

            stake:
                stake.stake,

            minimumStake:
                stake.minimumStake,

            detectionLatencyMs:

                Number(
                    process.hrtime.bigint() -
                    start
                ) / 1e6

        };

    }


    const end =
        process.hrtime.bigint();


    return {

        valid:
            true,

        observerId,

        observer:
            registration.observer,

        stake:
            stake.stake,

        detectionLatencyMs:

            Number(
                end - start
            ) / 1e6

    };

}


// ============================================================
// Check Duplicate Approval
// ============================================================

function hasObserverResponded(
    state,
    observerId
) {

    return state.observers.some(

        observer =>
            observer.observerId === observerId

    );

}


// ============================================================
// Submit Observer Approval
// ============================================================

/**
 * Algorithm 2:
 *
 * Step 3:
 *   Verify observer registration
 *
 * Step 4:
 *   Check stake requirement
 *
 * Step 5:
 *   Approve request
 *
 * Step 6:
 *   A(RID) = A(RID) + 1
 */

function approveRequest(
    rid,
    observerId
) {

    const protocolStart =
        process.hrtime.bigint();


    if (!rid) {

        throw new Error(
            "RID is required"
        );

    }


    if (!observerId) {

        throw new Error(
            "Observer ID is required"
        );

    }


    let state =
        getApprovalState(
            rid
        );


    if (
        !state.startedAt
    ) {

        state =
            initializeApproval(
                rid
            );

    }


    // --------------------------------------------------------
    // Already approved
    // --------------------------------------------------------

    if (
        state.approved
    ) {

        return {

            success:
                true,

            approved:
                true,

            reason:
                "Request already reached threshold",

            rid,

            threshold:
                state.threshold,

            approvalCount:
                state.approvalCount

        };

    }


    // --------------------------------------------------------
    // Duplicate observer
    // --------------------------------------------------------

    if (
        hasObserverResponded(
            state,
            observerId
        )
    ) {

        return {

            success:
                false,

            approved:
                state.approved,

            reason:
                "Observer has already submitted a decision",

            rid,

            observerId,

            approvalCount:
                state.approvalCount,

            threshold:
                state.threshold

        };

    }


    // --------------------------------------------------------
    // Validate observer
    // --------------------------------------------------------

    const validation =
        validateObserverForApproval(
            observerId
        );


    // --------------------------------------------------------
    // Invalid observer
    // --------------------------------------------------------

    if (
        !validation.valid
    ) {

        state.rejectedCount += 1;


        state.observers.push({

            observerId,

            decision:
                "REJECTED",

            reason:
                validation.reason,

            detectionLatencyMs:
                validation.detectionLatencyMs,

            timestamp:
                Date.now()

        });


        saveApprovalState(
            state
        );


        try {

            recordRejection(
                observerId
            );

        } catch (error) {
            // Ignore if observer was removed.
        }


        audit(

            "OBSERVER_APPROVAL_REJECTED",

            {

                rid,

                observerId,

                reason:
                    validation.reason,

                detectionLatencyMs:
                    validation.detectionLatencyMs

            }

        );


        return {

            success:
                false,

            approved:
                false,

            reason:
                validation.reason,

            rid,

            observerId,

            approvalCount:
                state.approvalCount,

            threshold:
                state.threshold,

            detectionLatencyMs:
                validation.detectionLatencyMs

        };

    }


    // --------------------------------------------------------
    // Observer approved
    // --------------------------------------------------------

    state.approvalCount += 1;


    state.observers.push({

        observerId,

        decision:
            "APPROVED",

        stake:
            validation.stake,

        detectionLatencyMs:
            validation.detectionLatencyMs,

        timestamp:
            Date.now()

    });


    // Update observer statistics

    try {

        recordApproval(
            observerId
        );

        updateReputation(
            observerId,
            1
        );

    } catch (error) {
        // Continue protocol even if local statistics fail.
    }


    // --------------------------------------------------------
    // Threshold verification
    // --------------------------------------------------------

    if (
        state.approvalCount
        >=
        state.threshold
    ) {

        state.approved =
            true;

        state.completedAt =
            Date.now();

    }


    saveApprovalState(
        state
    );


    const protocolEnd =
        process.hrtime.bigint();


    const approvalLatencyMs =

        Number(
            protocolEnd -
            protocolStart
        ) / 1e6;


    const detectionLatencyMs =
        validation.detectionLatencyMs;


    audit(

        "OBSERVER_APPROVAL_SUBMITTED",

        {

            rid,

            observerId,

            approvalCount:
                state.approvalCount,

            threshold:
                state.threshold,

            thresholdReached:
                state.approved,

            detectionLatencyMs,

            approvalLatencyMs

        }

    );


    return {

        success:
            true,

        approved:
            state.approved,

        rid,

        observerId,

        approvalCount:
            state.approvalCount,

        threshold:
            state.threshold,

        remainingApprovals:
            Math.max(

                0,

                state.threshold -
                state.approvalCount

            ),

        detectionLatencyMs,

        approvalLatencyMs,

        thresholdReached:
            state.approved

    };

}


// ============================================================
// Batch Observer Approval
// ============================================================

/**
 * Runs the approval protocol over all observers.
 *
 * This corresponds closely to Algorithm 2:
 *
 * for each observer Oi:
 *      Verify registration
 *      Check stake
 *      Approve
 *
 */

function runApprovalProtocol(
    rid,
    threshold = null
) {

    const protocolStart =
        process.hrtime.bigint();


    let state =
        initializeApproval(
            rid,
            threshold
        );


    const observers =
        getObservers();


    const results = [];


    for (
        const observer of observers
    ) {

        if (
            state.approved
        ) {

            break;

        }


        const result =
            approveRequest(

                rid,

                observer.id

            );


        results.push(
            result
        );


        state =
            getApprovalState(
                rid
            );

    }


    const protocolEnd =
        process.hrtime.bigint();


    const totalLatencyMs =

        Number(
            protocolEnd -
            protocolStart
        ) / 1e6;


    const detectionLatencies =
        results

            .filter(
                result =>
                    result.detectionLatencyMs !==
                    undefined
            )

            .map(
                result =>
                    result.detectionLatencyMs
            );


    const averageDetectionLatencyMs =

        detectionLatencies.length > 0

            ?

            detectionLatencies.reduce(
                (a, b) => a + b,
                0
            )
            /
            detectionLatencies.length

            :

            0;


    const firstApprovalTime =
        state.observers.length > 0
            ? state.observers[0].timestamp
            : null;


    const thresholdReachedTime =
        state.approved
            ? state.completedAt
            : null;


    const thresholdDetectionLatencyMs =

        thresholdReachedTime &&
        firstApprovalTime

            ?

            thresholdReachedTime -
            firstApprovalTime

            :

            null;


    const finalResult = {

        rid,

        threshold:
            state.threshold,

        observerCount:
            observers.length,

        approvalCount:
            state.approvalCount,

        rejectedCount:
            state.rejectedCount,

        approved:
            state.approved,

        results,

        metrics: {

            totalLatencyMs,

            averageDetectionLatencyMs,

            thresholdDetectionLatencyMs,

            observersProcessed:
                results.length

        },

        completedAt:
            new Date()
                .toISOString()

    };


    audit(

        "APPROVAL_PROTOCOL_COMPLETED",

        finalResult

    );


    return finalResult;

}


// ============================================================
// Get Approval Count
// ============================================================

function getApprovalCount(
    rid
) {

    const state =
        getApprovalState(
            rid
        );


    return state.approvalCount;

}


// ============================================================
// Get Threshold
// ============================================================

function getThreshold(
    rid
) {

    const state =
        getApprovalState(
            rid
        );


    return state.threshold;

}


// ============================================================
// Check Threshold
// ============================================================

function isThresholdReached(
    rid
) {

    const state =
        getApprovalState(
            rid
        );


    return (

        state.approvalCount
        >=
        state.threshold

    );

}


// ============================================================
// Get Approval Status
// ============================================================

function getApprovalStatus(
    rid
) {

    const state =
        getApprovalState(
            rid
        );


    return {

        rid,

        threshold:
            state.threshold,

        approvalCount:
            state.approvalCount,

        rejectedCount:
            state.rejectedCount,

        remaining:

            Math.max(

                0,

                state.threshold -
                state.approvalCount

            ),

        approved:
            state.approved,

        expired:
            state.expired,

        observers:
            state.observers,

        startedAt:
            state.startedAt,

        completedAt:
            state.completedAt

    };

}


// ============================================================
// Reject Request
// ============================================================

function rejectRequest(
    rid,
    reason
) {

    const state =
        getApprovalState(
            rid
        );


    state.approved =
        false;


    state.expired =
        true;


    state.completedAt =
        Date.now();


    state.rejectionReason =
        reason ||
        "Request rejected";


    saveApprovalState(
        state
    );


    audit(

        "REQUEST_REJECTED",

        {

            rid,

            reason:
                state.rejectionReason

        }

    );


    return state;

}


// ============================================================
// Timeout Detection
// ============================================================

/**
 * Implements the timeout part of the extended observer
 * algorithm.
 *
 * If an observer approved but does not submit its share,
 * the observer can later be flagged.
 */

function detectNonSubmittingObservers(
    rid,
    timeoutMs
) {

    const state =
        getApprovalState(
            rid
        );


    if (
        !state.startedAt
    ) {

        return {

            detected:
                false,

            reason:
                "Approval protocol not initialized"

        };

    }


    const elapsed =
        Date.now() -
        state.startedAt;


    if (
        elapsed <= timeoutMs
    ) {

        return {

            detected:
                false,

            elapsedMs:
                elapsed,

            timeoutMs,

            reason:
                "Timeout has not expired"

        };

    }


    const flagged = [];


    for (
        const observer of state.observers
    ) {

        if (
            observer.decision ===
            "APPROVED"
        ) {

            /*
             * Share submission is tracked separately.
             * If ShareSubmission.js later marks the observer
             * as submitted, this flag should be updated.
             */

            if (
                !observer.shareSubmitted
            ) {

                try {

                    flagMaliciousObserver(

                        observer.observerId,

                        10

                    );

                } catch (error) {
                    // Ignore missing observer.
                }


                flagged.push(
                    observer.observerId
                );

            }

        }

    }


    audit(

        "NON_SUBMITTING_OBSERVERS_DETECTED",

        {

            rid,

            elapsedMs:
                elapsed,

            timeoutMs,

            flaggedObservers:
                flagged

        }

    );


    return {

        detected:
            true,

        elapsedMs:
            elapsed,

        timeoutMs,

        flaggedObservers:
            flagged,

        count:
            flagged.length

    };

}


// ============================================================
// Calculate Approval Overhead
// ============================================================

function calculateApprovalOverhead(
    rid
) {

    const state =
        getApprovalState(
            rid
        );


    let totalBytes = 0;


    for (
        const observer of state.observers
    ) {

        totalBytes +=
            Buffer.byteLength(

                JSON.stringify(
                    observer
                ),

                "utf8"

            );

    }


    return {

        observerResponses:
            state.observers.length,

        overheadBytes:
            totalBytes

    };

}


// ============================================================
// Export
// ============================================================

module.exports = {

    initializeApproval,

    validateObserverForApproval,

    approveRequest,

    runApprovalProtocol,

    getApprovalCount,

    getThreshold,

    isThresholdReached,

    getApprovalStatus,

    rejectRequest,

    detectNonSubmittingObservers,

    calculateApprovalOverhead

};


// ============================================================
// Standalone Demonstration
// ============================================================

if (
    require.main === module
) {

    console.log(
        "\n=================================================="
    );

    console.log(
        " OBSERVER APPROVAL PROTOCOL"
    );

    console.log(
        "==================================================\n"
    );


    try {

        // ----------------------------------------------------
        // Generate demo RID
        // ----------------------------------------------------

        const rid =
            "RID-DEMO-" +
            Date.now();


        console.log(
            "Request ID:",
            rid
        );


        // ----------------------------------------------------
        // Run protocol
        // ----------------------------------------------------

        const result =
            runApprovalProtocol(
                rid
            );


        // ----------------------------------------------------
        // Display result
        // ----------------------------------------------------

        console.log(
            "\nApproval Result:"
        );


        console.table({

            RID:
                result.rid,

            Observers:
                result.observerCount,

            Threshold:
                result.threshold,

            Approvals:
                result.approvalCount,

            Rejections:
                result.rejectedCount,

            Approved:
                result.approved,

            "Total Latency (ms)":
                result.metrics
                    .totalLatencyMs,

            "Average Detection Latency (ms)":
                result.metrics
                    .averageDetectionLatencyMs,

            "Threshold Detection Latency (ms)":
                result.metrics
                    .thresholdDetectionLatencyMs

        });


        // ----------------------------------------------------
        // Approval overhead
        // ----------------------------------------------------

        const overhead =
            calculateApprovalOverhead(
                rid
            );


        console.log(
            "\nCommunication Overhead:"
        );


        console.table(
            overhead
        );


        // ----------------------------------------------------
        // Individual observer results
        // ----------------------------------------------------

        console.log(
            "\nObserver Decisions:"
        );


        console.table(

            result.results.map(
                item => ({

                    Observer:
                        item.observerId,

                    Approved:
                        item.success,

                    ApprovalCount:
                        item.approvalCount,

                    Threshold:
                        item.threshold,

                    "Detection Latency (ms)":
                        item.detectionLatencyMs

                })
            )

        );


        console.log(
            "\nApproval protocol completed."
        );


    } catch (error) {

        console.error(
            "\nApproval protocol failed:"
        );

        console.error(
            error.message
        );

        process.exitCode = 1;

    }

}