/**
 * ============================================================
 * bridge/Bridge.js
 * ============================================================
 *
 * Cross-Chain Bridge / Observer Gateway
 *
 * Chain Y:
 *   HospitalRequest.sol
 *
 * Chain X:
 *   MedicalRecord.sol
 *   ConsentManager.sol
 *   ObserverManager.sol
 *
 * Flow:
 *
 * Hospital Y
 *     |
 *     v
 * Chain Y
 *     |
 *     v
 * Bridge
 *     |
 *     +----> Verify Hospital Request
 *     |
 *     +----> Retrieve Alice Consent from Chain X
 *     |
 *     +----> Validate Consent / Request
 *     |
 *     +----> Trigger Observers
 *     |
 *     v
 * Observer Approval
 *
 * ============================================================
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");


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

const RECORD_FILE =
    path.join(
        DATABASE_DIR,
        "records.json"
    );

const OBSERVER_FILE =
    path.join(
        DATABASE_DIR,
        "observers.json"
    );

const BRIDGE_FILE =
    path.join(
        DATABASE_DIR,
        "bridge.json"
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


    if (!fs.existsSync(RECORD_FILE)) {

        fs.writeFileSync(
            RECORD_FILE,
            "[]",
            "utf8"
        );

    }


    if (!fs.existsSync(OBSERVER_FILE)) {

        fs.writeFileSync(
            OBSERVER_FILE,
            "[]",
            "utf8"
        );

    }


    if (!fs.existsSync(BRIDGE_FILE)) {

        fs.writeFileSync(
            BRIDGE_FILE,
            "[]",
            "utf8"
        );

    }

}


// ============================================================
// JSON Utilities
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

    } catch (
        error
    ) {

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
            "Bridge",

        action,

        data

    });


    writeJSON(
        AUDIT_FILE,
        records
    );

}


// ============================================================
// Utility: SHA-256
// ============================================================

function sha256(
    value
) {

    return crypto
        .createHash("sha256")
        .update(
            String(value)
        )
        .digest("hex");

}


// ============================================================
// Utility: Normalize Address
// ============================================================

function normalizeAddress(
    address
) {

    if (
        !address
    ) {

        return "";

    }


    return String(
        address
    )
    .trim()
    .toLowerCase();

}


// ============================================================
// Utility: Compare Addresses
// ============================================================

function addressesMatch(
    address1,
    address2
) {

    return (

        normalizeAddress(
            address1
        )
        ===
        normalizeAddress(
            address2
        )

    );

}


// ============================================================
// Utility: Scope Validation
// ============================================================

function validateScope(
    consentScope,
    requestedScope
) {

    if (
        !requestedScope
    ) {

        return {

            valid:
                true,

            reason:
                "No specific scope requested"

        };

    }


    if (
        !Array.isArray(
            requestedScope
        )
    ) {

        return {

            valid:
                false,

            reason:
                "Invalid requested scope"

        };

    }


    if (
        !Array.isArray(
            consentScope
        )
    ) {

        return {

            valid:
                false,

            reason:
                "Consent scope is unavailable"

        };

    }


    const unauthorized =
        requestedScope.filter(

            item =>

                !consentScope.includes(
                    item
                )

        );


    if (
        unauthorized.length > 0
    ) {

        return {

            valid:
                false,

            reason:
                "Requested scope exceeds patient consent",

            unauthorized

        };

    }


    return {

        valid:
            true,

        reason:
            "Requested scope is within consent"

    };

}


// ============================================================
// Purpose Validation
// ============================================================

function validatePurpose(
    consentPurpose,
    requestPurpose
) {

    if (
        !consentPurpose ||
        !requestPurpose
    ) {

        return {

            valid:
                false,

            reason:
                "Purpose information is missing"

        };

    }


    const consent =
        String(
            consentPurpose
        )
        .trim()
        .toLowerCase();


    const request =
        String(
            requestPurpose
        )
        .trim()
        .toLowerCase();


    if (
        consent !== request
    ) {

        return {

            valid:
                false,

            reason:
                "Purpose mismatch",

            consentPurpose,

            requestPurpose

        };

    }


    return {

        valid:
            true,

        reason:
            "Purpose matched"

    };

}


// ============================================================
// Duration Validation
// ============================================================

function validateDuration(
    consent,
    request
) {

    /*
     * Supported representations:
     *
     * consent.expiresAt
     * consent.validUntil
     * request.duration
     * request.expiresAt
     *
     */

    const now =
        Date.now();


    let consentExpiry =
        null;


    let requestExpiry =
        null;


    // --------------------------------------------------------
    // Consent expiry
    // --------------------------------------------------------

    if (
        consent.expiresAt
    ) {

        consentExpiry =
            new Date(
                consent.expiresAt
            ).getTime();

    }
    else if (
        consent.validUntil
    ) {

        consentExpiry =
            new Date(
                consent.validUntil
            ).getTime();

    }


    // --------------------------------------------------------
    // Request expiry
    // --------------------------------------------------------

    if (
        request.expiresAt
    ) {

        requestExpiry =
            new Date(
                request.expiresAt
            ).getTime();

    }
    else if (
        request.durationMs
    ) {

        requestExpiry =
            now +
            Number(
                request.durationMs
            );

    }
    else if (
        request.duration
    ) {

        requestExpiry =
            now +
            Number(
                request.duration
            ) *
            60 *
            1000;

    }


    // --------------------------------------------------------
    // Current consent expiry
    // --------------------------------------------------------

    if (
        consentExpiry !== null
        &&
        now >
        consentExpiry
    ) {

        return {

            valid:
                false,

            reason:
                "Patient consent has expired"

        };

    }


    // --------------------------------------------------------
    // Request must not exceed consent
    // --------------------------------------------------------

    if (
        consentExpiry !== null &&
        requestExpiry !== null
    ) {

        if (
            requestExpiry >
            consentExpiry
        ) {

            return {

                valid:
                    false,

                reason:
                    "Requested duration exceeds consent duration",

                consentExpiry:
                    new Date(
                        consentExpiry
                    ).toISOString(),

                requestExpiry:
                    new Date(
                        requestExpiry
                    ).toISOString()

            };

        }

    }


    return {

        valid:
            true,

        reason:
            "Duration validated",

        consentExpiry,

        requestExpiry

    };

}


// ============================================================
// Hospital Identity Validation
// ============================================================

function validateHospitalIdentity(
    request,
    registeredHospital
) {

    const start =
        process.hrtime.bigint();


    if (
        !request
    ) {

        return {

            valid:
                false,

            reason:
                "Hospital request not found",

            detectionLatencyMs:

                Number(

                    process.hrtime.bigint()
                    -
                    start

                ) / 1e6

        };

    }


    const hospital =
        request.hospital ||
        request.hospitalAddress ||
        request.requester;


    if (
        !hospital
    ) {

        return {

            valid:
                false,

            reason:
                "Hospital identity missing",

            detectionLatencyMs:

                Number(

                    process.hrtime.bigint()
                    -
                    start

                ) / 1e6

        };

    }


    if (
        registeredHospital
    ) {

        if (
            !addressesMatch(
                hospital,
                registeredHospital
            )
        ) {

            return {

                valid:
                    false,

                reason:
                    "Hospital identity does not match registered hospital",

                detectionLatencyMs:

                    Number(

                        process.hrtime.bigint()
                        -
                        start

                    ) / 1e6

            };

        }

    }


    /*
     * If a request signature is supplied, the caller can
     * perform actual ECDSA verification using ethers.js.
     *
     * This bridge layer verifies the presence of the
     * signature and leaves cryptographic address recovery
     * to HospitalRequest.sol / HospitalY.js.
     */

    if (
        request.signature
    ) {

        if (
            String(
                request.signature
            ).length < 10
        ) {

            return {

                valid:
                    false,

                reason:
                    "Invalid hospital request signature",

                detectionLatencyMs:

                    Number(

                        process.hrtime.bigint()
                        -
                        start

                    ) / 1e6

            };

        }

    }


    const end =
        process.hrtime.bigint();


    return {

        valid:
            true,

        hospital,

        reason:
            "Hospital identity validated",

        detectionLatencyMs:

            Number(
                end -
                start
            ) / 1e6

    };

}


// ============================================================
// Retrieve Consent from Chain X
// ============================================================

/**
 * In production this function should call:
 *
 * ConsentManager.sol
 *
 * using Web3/Ethers.
 *
 * For the local Ganache demonstration, it first checks
 * records.json.
 */

function getConsentFromChainX(
    cid
) {

    const records =
        readJSON(
            RECORD_FILE
        );


    /*
     * Consent can be stored either as:
     *
     * {
     *    type: "CONSENT",
     *    cid: "CID-001"
     * }
     *
     * or directly with cid.
     */

    return records.find(

        record =>

            record.cid === cid
            ||
            (
                record.type === "CONSENT" &&
                record.consentId === cid
            )

    );

}


// ============================================================
// Retrieve Hospital Request
// ============================================================

function getRequestFromChainY(
    rid
) {

    /*
     * Hospital requests can be stored in bridge.json
     * during local simulation.
     *
     * When Web3 is connected, this function can instead
     * call HospitalRequest.sol.
     */

    const bridgeRecords =
        readJSON(
            BRIDGE_FILE
        );


    return bridgeRecords.find(

        record =>

            record.rid === rid

    );

}


// ============================================================
// Validate Cross-Chain Request
// ============================================================

function validateCrossChainRequest(
    request,
    consent,
    registeredHospital
) {

    const start =
        process.hrtime.bigint();


    const errors = [];


    // ========================================================
    // Step 1: Hospital Identity
    // ========================================================

    const hospitalValidation =
        validateHospitalIdentity(

            request,

            registeredHospital

        );


    if (
        !hospitalValidation.valid
    ) {

        errors.push(
            hospitalValidation.reason
        );

    }


    // ========================================================
    // Step 2: Recipient Match
    // ========================================================

    if (
        consent.recipient
    ) {

        const requester =
            request.hospital ||
            request.hospitalAddress ||
            request.requester;


        if (
            !addressesMatch(
                consent.recipient,
                requester
            )
        ) {

            errors.push(
                "Consent recipient does not match requester"
            );

        }

    }


    // ========================================================
    // Step 3: Purpose Match
    // ========================================================

    const purposeValidation =
        validatePurpose(

            consent.purpose,

            request.purpose

        );


    if (
        !purposeValidation.valid
    ) {

        errors.push(
            purposeValidation.reason
        );

    }


    // ========================================================
    // Step 4: Scope Match
    // ========================================================

    const scopeValidation =
        validateScope(

            consent.scope,

            request.scope

        );


    if (
        !scopeValidation.valid
    ) {

        errors.push(
            scopeValidation.reason
        );

    }


    // ========================================================
    // Step 5: Duration Match
    // ========================================================

    const durationValidation =
        validateDuration(

            consent,

            request

        );


    if (
        !durationValidation.valid
    ) {

        errors.push(
            durationValidation.reason
        );

    }


    // ========================================================
    // Final Result
    // ========================================================

    const end =
        process.hrtime.bigint();


    const detectionLatencyMs =

        Number(
            end -
            start
        ) / 1e6;


    return {

        valid:
            errors.length === 0,

        errors,

        hospitalValidation,

        purposeValidation,

        scopeValidation,

        durationValidation,

        detectionLatencyMs

    };

}


// ============================================================
// Calculate Communication Overhead
// ============================================================

function calculateOverhead(
    request,
    consent,
    validation
) {

    const requestBytes =
        Buffer.byteLength(

            JSON.stringify(
                request || {}
            ),

            "utf8"

        );


    const consentBytes =
        Buffer.byteLength(

            JSON.stringify(
                consent || {}
            ),

            "utf8"

        );


    const validationBytes =
        Buffer.byteLength(

            JSON.stringify(
                validation || {}
            ),

            "utf8"

        );


    const bridgeMessage = {

        rid:
            request &&
            request.rid,

        cid:
            consent &&
            (
                consent.cid ||
                consent.consentId
            ),

        valid:
            validation.valid,

        timestamp:
            Date.now()

    };


    const bridgeMessageBytes =
        Buffer.byteLength(

            JSON.stringify(
                bridgeMessage
            ),

            "utf8"

        );


    return {

        requestBytes,

        consentBytes,

        validationBytes,

        bridgeMessageBytes,

        totalBytes:

            requestBytes +
            consentBytes +
            validationBytes +
            bridgeMessageBytes

    };

}


// ============================================================
// Store Bridge Event
// ============================================================

function storeBridgeEvent(
    event
) {

    const records =
        readJSON(
            BRIDGE_FILE
        );


    records.push(
        event
    );


    writeJSON(
        BRIDGE_FILE,
        records
    );

}


// ============================================================
// Trigger Observer Protocol
// ============================================================

async function triggerObservers(
    rid,
    observerManager,
    observers = []
) {

    const start =
        process.hrtime.bigint();


    /*
     * If an ObserverManager contract object is provided,
     * the bridge can invoke its request/notification method.
     *
     * Otherwise the observers are notified through the
     * local simulation layer.
     */


    let notified =
        0;


    const notificationResults = [];


    for (
        const observer of observers
    ) {

        const observerId =
            observer.observerId ||
            observer.id ||
            observer.address;


        if (
            !observerId
        ) {

            continue;

        }


        try {

            if (
                typeof observer.notify ===
                "function"
            ) {

                await observer.notify(
                    rid
                );

            }


            notified++;


            notificationResults.push({

                observerId,

                notified:
                    true,

                timestamp:
                    new Date()
                        .toISOString()

            });

        } catch (
            error
        ) {

            notificationResults.push({

                observerId,

                notified:
                    false,

                error:
                    error.message

            });

        }

    }


    // --------------------------------------------------------
    // Contract notification
    // --------------------------------------------------------

    if (
        observerManager
    ) {

        try {

            if (
                typeof observerManager.notifyObservers ===
                "function"
            ) {

                await observerManager.notifyObservers(
                    rid
                );

            }

        } catch (
            error
        ) {

            audit(

                "OBSERVER_CONTRACT_NOTIFICATION_FAILED",

                {

                    rid,

                    error:
                        error.message

                }

            );

        }

    }


    const end =
        process.hrtime.bigint();


    const notificationLatencyMs =

        Number(
            end -
            start
        ) / 1e6;


    audit(

        "OBSERVERS_TRIGGERED",

        {

            rid,

            notified,

            notificationLatencyMs

        }

    );


    return {

        rid,

        notified,

        notificationResults,

        notificationLatencyMs

    };

}


// ============================================================
// Main Bridge Function
// ============================================================

/**
 * ============================================================
 * processCrossChainRequest()
 * ============================================================
 *
 * Main bridge operation.
 *
 * ============================================================
 */

async function processCrossChainRequest({

    rid,

    cid,

    request,

    consent,

    registeredHospital,

    observerManager,

    observers = []

}) {

    const start =
        process.hrtime.bigint();


    // ========================================================
    // Validate input
    // ========================================================

    if (
        !rid
    ) {

        throw new Error(
            "Request ID (RID) is required"
        );

    }


    if (
        !cid
    ) {

        throw new Error(
            "Consent ID (CID) is required"
        );

    }


    // ========================================================
    // If request wasn't supplied, retrieve it
    // ========================================================

    if (
        !request
    ) {

        request =
            getRequestFromChainY(
                rid
            );

    }


    // ========================================================
    // If consent wasn't supplied, retrieve it
    // ========================================================

    if (
        !consent
    ) {

        consent =
            getConsentFromChainX(
                cid
            );

    }


    // ========================================================
    // Missing request
    // ========================================================

    if (
        !request
    ) {

        audit(

            "BRIDGE_REJECTED_REQUEST_NOT_FOUND",

            {

                rid,

                cid

            }

        );


        return {

            success:
                false,

            status:
                "REJECTED",

            reason:
                "Hospital request not found on Chain Y"

        };

    }


    // ========================================================
    // Missing consent
    // ========================================================

    if (
        !consent
    ) {

        audit(

            "BRIDGE_REJECTED_CONSENT_NOT_FOUND",

            {

                rid,

                cid

            }

        );


        return {

            success:
                false,

            status:
                "REJECTED",

            reason:
                "Patient consent not found on Chain X"

        };

    }


    // ========================================================
    // Cross-chain validation
    // ========================================================

    const validation =
        validateCrossChainRequest(

            request,

            consent,

            registeredHospital

        );


    // ========================================================
    // Communication overhead
    // ========================================================

    const overhead =
        calculateOverhead(

            request,

            consent,

            validation

        );


    // ========================================================
    // Reject invalid request
    // ========================================================

    if (
        !validation.valid
    ) {

        const end =
            process.hrtime.bigint();


        const bridgeLatencyMs =

            Number(
                end -
                start
            ) / 1e6;


        const result = {

            success:
                false,

            status:
                "REJECTED",

            rid,

            cid,

            reason:
                "Cross-chain validation failed",

            errors:
                validation.errors,

            detectionLatencyMs:
                validation.detectionLatencyMs,

            bridgeLatencyMs,

            overheadBytes:
                overhead.totalBytes,

            overhead

        };


        audit(

            "CROSS_CHAIN_VALIDATION_FAILED",

            result

        );


        storeBridgeEvent({

            timestamp:
                new Date()
                    .toISOString(),

            type:
                "CROSS_CHAIN_VALIDATION_FAILED",

            rid,

            cid,

            result

        });


        return result;

    }


    // ========================================================
    // Trigger Observer Nodes
    // ========================================================

    const observerResult =
        await triggerObservers(

            rid,

            observerManager,

            observers

        );


    // ========================================================
    // Final latency
    // ========================================================

    const end =
        process.hrtime.bigint();


    const bridgeLatencyMs =

        Number(
            end -
            start
        ) / 1e6;


    // ========================================================
    // Bridge Event
    // ========================================================

    const bridgeEvent = {

        bridgeId:

            "BRIDGE-" +
            Date.now() +
            "-" +
            sha256(
                rid + cid
            ).substring(
                0,
                12
            ),

        timestamp:
            new Date()
                .toISOString(),

        rid,

        cid,

        sourceChain:
            "Chain-Y",

        destinationChain:
            "Chain-X",

        status:
            "VALIDATED",

        observerTriggered:
            true,

        observerCount:
            observerResult.notified,

        metrics: {

            bridgeLatencyMs,

            detectionLatencyMs:
                validation
                    .detectionLatencyMs,

            observerNotificationLatencyMs:
                observerResult
                    .notificationLatencyMs,

            overheadBytes:
                overhead.totalBytes,

            requestBytes:
                overhead.requestBytes,

            consentBytes:
                overhead.consentBytes,

            validationBytes:
                overhead.validationBytes,

            bridgeMessageBytes:
                overhead.bridgeMessageBytes

        }

    };


    storeBridgeEvent(
        bridgeEvent
    );


    // ========================================================
    // Audit
    // ========================================================

    audit(

        "CROSS_CHAIN_REQUEST_VALIDATED",

        bridgeEvent

    );


    // ========================================================
    // Return
    // ========================================================

    return {

        success:
            true,

        status:
            "VALIDATED",

        rid,

        cid,

        bridgeId:
            bridgeEvent.bridgeId,

        sourceChain:
            "Chain-Y",

        destinationChain:
            "Chain-X",

        observerTriggered:
            true,

        observerCount:
            observerResult.notified,

        validation,

        metrics:
            bridgeEvent.metrics

    };

}


// ============================================================
// Register Request in Bridge Database
// ============================================================

function registerRequest(
    request
) {

    if (
        !request ||
        !request.rid
    ) {

        throw new Error(
            "Valid request with RID is required"
        );

    }


    const records =
        readJSON(
            BRIDGE_FILE
        );


    const existingIndex =
        records.findIndex(

            record =>
                record.rid ===
                request.rid

        );


    if (
        existingIndex !== -1
    ) {

        records[
            existingIndex
        ] = {

            ...records[
                existingIndex
            ],

            ...request,

            updatedAt:
                new Date()
                    .toISOString()

        };

    } else {

        records.push({

            ...request,

            registeredAt:
                new Date()
                    .toISOString()

        });

    }


    writeJSON(
        BRIDGE_FILE,
        records
    );


    audit(

        "HOSPITAL_REQUEST_REGISTERED_BRIDGE",

        {

            rid:
                request.rid

        }

    );


    return request;

}


// ============================================================
// Get Bridge Event
// ============================================================

function getBridgeEvent(
    bridgeId
) {

    const records =
        readJSON(
            BRIDGE_FILE
        );


    return records.find(

        record =>

            record.bridgeId ===
            bridgeId

    );

}


// ============================================================
// Get Request Bridge History
// ============================================================

function getRequestHistory(
    rid
) {

    const records =
        readJSON(
            BRIDGE_FILE
        );


    return records.filter(

        record =>
            record.rid ===
            rid

    );

}


// ============================================================
// Get Bridge Metrics
// ============================================================

function getBridgeMetrics(
    rid
) {

    const history =
        getRequestHistory(
            rid
        );


    if (
        history.length === 0
    ) {

        return null;

    }


    const events =
        history.filter(

            event =>
                event.metrics

        );


    if (
        events.length === 0
    ) {

        return null;

    }


    const totalLatency =
        events.reduce(

            (
                sum,
                event
            ) =>

                sum +
                Number(
                    event.metrics
                        .bridgeLatencyMs ||
                    0
                ),

            0

        );


    const totalOverhead =
        events.reduce(

            (
                sum,
                event
            ) =>

                sum +
                Number(
                    event.metrics
                        .overheadBytes ||
                    0
                ),

            0

        );


    return {

        rid,

        eventCount:
            events.length,

        averageBridgeLatencyMs:

            totalLatency /
            events.length,

        totalCommunicationOverheadBytes:
            totalOverhead,

        averageCommunicationOverheadBytes:

            totalOverhead /
            events.length

    };

}


// ============================================================
// Export
// ============================================================

module.exports = {

    processCrossChainRequest,

    validateCrossChainRequest,

    validateHospitalIdentity,

    validatePurpose,

    validateScope,

    validateDuration,

    calculateOverhead,

    triggerObservers,

    registerRequest,

    getRequestFromChainY,

    getConsentFromChainX,

    getBridgeEvent,

    getRequestHistory,

    getBridgeMetrics

};