/**
 * ============================================================
 * observer/ShareSubmission.js
 * ============================================================
 *
 * Algorithm 3: Observer Share Submission
 *
 * Require:
 *   Request RID
 *   Observer Oi
 *   Share (xi, yi)
 *
 * Steps:
 *
 * 1. Verify observer approval status
 * 2. If approved:
 *      Submit share to storage
 * 3. Store Share(RID, Oi) = (xi, yi)
 * 4. Append observer to submitted list
 * 5. Emit ShareSubmitted event
 * 6. Update share counter
 *
 * ============================================================
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const {
    getObserver,
    recordShareSubmission
} = require("./Observer");

const {
    getApprovalStatus
} = require("./Approval");


// ============================================================
// Database Paths
// ============================================================

const DATABASE_DIR =
    path.join(
        __dirname,
        "..",
        "database"
    );

const SHARES_FILE =
    path.join(
        DATABASE_DIR,
        "shares.json"
    );

const AUDIT_FILE =
    path.join(
        DATABASE_DIR,
        "audit.json"
    );

const SUBMISSION_FILE =
    path.join(
        DATABASE_DIR,
        "share_submissions.json"
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

    if (!fs.existsSync(SHARES_FILE)) {

        fs.writeFileSync(
            SHARES_FILE,
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

    if (!fs.existsSync(SUBMISSION_FILE)) {

        fs.writeFileSync(
            SUBMISSION_FILE,
            "[]",
            "utf8"
        );

    }

}


// ============================================================
// JSON Read
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
// JSON Write
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
// Audit Function
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
// Generate Submission ID
// ============================================================

function generateSubmissionId() {

    return (

        "SHARE-" +

        Date.now() +

        "-" +

        crypto
            .randomBytes(4)
            .toString("hex")

    );

}


// ============================================================
// Validate Share
// ============================================================

/**
 * Validates a Shamir share.
 *
 * Share format:
 *
 * {
 *     x: xi,
 *     y: yi
 * }
 *
 * x must be non-zero.
 * y must be an integer.
 *
 * The prime-field range is checked when p is supplied.
 */

function validateShare(
    share,
    prime = null
) {

    if (!share) {

        return {

            valid:
                false,

            reason:
                "Share is missing"

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

    const x =
        BigInt(
            share.x
        );

    const y =
        BigInt(
            share.y
        );


    if (
        x <= 0n
    ) {

        return {

            valid:
                false,

            reason:
                "x must be non-zero"

        };

    }


    if (
        y < 0n
    ) {

        return {

            valid:
                false,

            reason:
                "y cannot be negative"

        };

    }


    if (
        prime !== null
    ) {

        const p =
            BigInt(
                prime
            );


        if (
            x >= p
        ) {

            return {

                valid:
                    false,

                reason:
                    "x must be less than prime p"

            };

        }


        if (
            y >= p
        ) {

            return {

                valid:
                    false,

                reason:
                    "y must be less than prime p"

            };

        }

    }


    return {

        valid:
            true,

        x:
            x.toString(),

        y:
            y.toString()

    };

}


// ============================================================
// Check Duplicate Share
// ============================================================

function shareAlreadySubmitted(
    rid,
    observerId
) {

    const submissions =
        readJSON(
            SUBMISSION_FILE
        );

    return submissions.some(

        item =>

            item.rid === rid &&
            item.observerId === observerId

    );

}


// ============================================================
// Get Submitted Shares
// ============================================================

function getSubmittedShares(
    rid
) {

    return readJSON(
        SHARES_FILE
    ).filter(

        share =>
            share.rid === rid

    );

}


// ============================================================
// Get Submitted Observers
// ============================================================

function getSubmittedObservers(
    rid
) {

    return getSubmittedShares(
        rid
    ).map(

        share =>
            share.observerId

    );

}


// ============================================================
// Share Count
// ============================================================

function getShareCount(
    rid
) {

    return getSubmittedShares(
        rid
    ).length;

}


// ============================================================
// Verify Observer Approval
// ============================================================

function verifyApproval(
    rid,
    observerId
) {

    const status =
        getApprovalStatus(
            rid
        );


    if (!status) {

        return {

            approved:
                false,

            reason:
                "Approval state not found"

        };

    }


    const observer =
        status.observers.find(

            item =>
                item.observerId ===
                observerId

        );


    if (!observer) {

        return {

            approved:
                false,

            reason:
                "Observer has not submitted an approval"

        };

    }


    if (
        observer.decision !==
        "APPROVED"
    ) {

        return {

            approved:
                false,

            reason:
                "Observer approval was rejected"

        };

    }


    return {

        approved:
            true,

        observer

    };

}


// ============================================================
// Submit Share
// ============================================================

/**
 * Main Algorithm 3 function.
 *
 * submitShare(
 *     RID,
 *     ObserverID,
 *     { x, y }
 * )
 */

function submitShare(
    rid,
    observerId,
    share,
    prime = null
) {

    const start =
        process.hrtime.bigint();


    // --------------------------------------------------------
    // Validate RID
    // --------------------------------------------------------

    if (!rid) {

        throw new Error(
            "Request ID (RID) is required"
        );

    }


    // --------------------------------------------------------
    // Validate observer
    // --------------------------------------------------------

    const observer =
        getObserver(
            observerId
        );


    if (!observer) {

        return {

            success:
                false,

            reason:
                "Observer is not registered",

            rid,

            observerId

        };

    }


    // --------------------------------------------------------
    // Verify approval
    // --------------------------------------------------------

    const approval =
        verifyApproval(
            rid,
            observerId
        );


    if (!approval.approved) {

        const end =
            process.hrtime.bigint();


        return {

            success:
                false,

            reason:
                approval.reason,

            rid,

            observerId,

            detectionLatencyMs:

                Number(
                    end - start
                ) / 1e6

        };

    }


    // --------------------------------------------------------
    // Verify threshold has already been achieved
    // --------------------------------------------------------

    const approvalStatus =
        getApprovalStatus(
            rid
        );


    if (
        approvalStatus.approved !== true
    ) {

        return {

            success:
                false,

            reason:
                "Observer threshold has not yet been reached",

            rid,

            observerId,

            approvalCount:
                approvalStatus.approvalCount,

            threshold:
                approvalStatus.threshold

        };

    }


    // --------------------------------------------------------
    // Validate share
    // --------------------------------------------------------

    const validation =
        validateShare(
            share,
            prime
        );


    if (!validation.valid) {

        const end =
            process.hrtime.bigint();


        audit(

            "INVALID_SHARE_REJECTED",

            {

                rid,

                observerId,

                reason:
                    validation.reason

            }

        );


        return {

            success:
                false,

            reason:
                validation.reason,

            rid,

            observerId,

            detectionLatencyMs:

                Number(
                    end - start
                ) / 1e6

        };

    }


    // --------------------------------------------------------
    // Prevent duplicate share
    // --------------------------------------------------------

    if (
        shareAlreadySubmitted(
            rid,
            observerId
        )
    ) {

        return {

            success:
                false,

            reason:
                "Observer has already submitted a share",

            rid,

            observerId

        };

    }


    // --------------------------------------------------------
    // Check duplicate x-coordinate
    // --------------------------------------------------------

    const existingShares =
        getSubmittedShares(
            rid
        );


    const duplicateX =
        existingShares.find(

            item =>

                String(item.x) ===
                String(validation.x)

        );


    if (duplicateX) {

        return {

            success:
                false,

            reason:
                "Duplicate x-coordinate detected",

            rid,

            observerId,

            x:
                validation.x

        };

    }


    // ========================================================
    // Create Submission
    // ========================================================

    const submissionId =
        generateSubmissionId();


    const submissionTime =
        Date.now();


    const submission = {

        submissionId,

        rid,

        observerId,

        x:
            validation.x,

        y:
            validation.y,

        timestamp:
            new Date()
                .toISOString(),

        submittedAt:
            submissionTime,

        verified:
            true

    };


    // ========================================================
    // Store Share
    // ========================================================

    const shares =
        readJSON(
            SHARES_FILE
        );


    shares.push(
        submission
    );


    writeJSON(
        SHARES_FILE,
        shares
    );


    // ========================================================
    // Store Submission Metadata
    // ========================================================

    const submissions =
        readJSON(
            SUBMISSION_FILE
        );


    submissions.push({

        submissionId,

        rid,

        observerId,

        submittedAt:
            submissionTime,

        status:
            "SUBMITTED"

    });


    writeJSON(
        SUBMISSION_FILE,
        submissions
    );


    // ========================================================
    // Update Observer
    // ========================================================

    try {

        recordShareSubmission(
            observerId
        );

    } catch (error) {

        console.warn(

            "Warning: observer statistics could not be updated:",

            error.message

        );

    }


    // ========================================================
    // Calculate Metrics
    // ========================================================

    const end =
        process.hrtime.bigint();


    const submissionLatencyMs =

        Number(
            end - start
        ) / 1e6;


    const updatedShares =
        getSubmittedShares(
            rid
        );


    const shareCount =
        updatedShares.length;


    const threshold =
        approvalStatus.threshold;


    const thresholdReached =
        shareCount >= threshold;


    // ========================================================
    // Communication Overhead
    // ========================================================

    const overheadBytes =
        Buffer.byteLength(

            JSON.stringify(
                submission
            ),

            "utf8"

        );


    // ========================================================
    // Audit
    // ========================================================

    audit(

        "SHARE_SUBMITTED",

        {

            submissionId,

            rid,

            observerId,

            x:
                validation.x,

            shareCount,

            threshold,

            thresholdReached,

            submissionLatencyMs,

            overheadBytes

        }

    );


    // ========================================================
    // Result
    // ========================================================

    return {

        success:
            true,

        submissionId,

        rid,

        observerId,

        share: {

            x:
                validation.x,

            y:
                validation.y

        },

        shareCount,

        threshold,

        thresholdReached,

        remainingShares:

            Math.max(

                0,

                threshold -
                shareCount

            ),

        submissionLatencyMs,

        overheadBytes,

        timestamp:
            submission.timestamp

    };

}


// ============================================================
// Submit Multiple Shares
// ============================================================

function submitShares(
    rid,
    shareList,
    prime = null
) {

    if (
        !Array.isArray(
            shareList
        )
    ) {

        throw new Error(
            "shareList must be an array"
        );

    }


    const start =
        process.hrtime.bigint();


    const results = [];


    for (
        const item of shareList
    ) {

        const result =
            submitShare(

                rid,

                item.observerId,

                {

                    x:
                        item.x,

                    y:
                        item.y

                },

                prime

            );


        results.push(
            result
        );

    }


    const end =
        process.hrtime.bigint();


    const totalLatencyMs =

        Number(
            end - start
        ) / 1e6;


    const successful =
        results.filter(
            item =>
                item.success
        );


    const totalOverheadBytes =
        successful.reduce(

            (sum, item) =>
                sum +
                Number(
                    item.overheadBytes ||
                    0
                ),

            0

        );


    return {

        rid,

        results,

        successfulShares:
            successful.length,

        totalShares:
            shareList.length,

        totalLatencyMs,

        totalOverheadBytes,

        thresholdReached:
            successful.length >=
            (
                getApprovalStatus(
                    rid
                ).threshold || Infinity
            )

    };

}


// ============================================================
// Get Share Submission Status
// ============================================================

function getShareSubmissionStatus(
    rid
) {

    const approval =
        getApprovalStatus(
            rid
        );


    const shares =
        getSubmittedShares(
            rid
        );


    const threshold =
        approval.threshold;


    return {

        rid,

        threshold,

        approvalCount:
            approval.approvalCount,

        submittedShareCount:
            shares.length,

        remainingShares:

            Math.max(

                0,

                threshold -
                shares.length

            ),

        thresholdReached:
            shares.length >=
            threshold,

        observers:
            shares.map(

                share => ({

                    observerId:
                        share.observerId,

                    x:
                        share.x,

                    submittedAt:
                        share.timestamp

                })

            )

    };

}


// ============================================================
// Mark Observer Share as Submitted
// ============================================================

/**
 * Updates Approval.js state so the timeout mechanism
 * knows that an approved observer actually submitted
 * its share.
 */

function markApprovalShareSubmitted(
    rid,
    observerId
) {

    const approvalFile =
        path.join(
            DATABASE_DIR,
            "approvals.json"
        );


    if (!fs.existsSync(approvalFile)) {

        return false;

    }


    const approvals =
        readJSON(
            approvalFile
        );


    const request =
        approvals.find(
            item =>
                item.rid === rid
        );


    if (!request) {

        return false;

    }


    const observer =
        request.observers.find(

            item =>
                item.observerId ===
                observerId

        );


    if (!observer) {

        return false;

    }


    observer.shareSubmitted =
        true;


    observer.shareSubmittedAt =
        Date.now();


    writeJSON(
        approvalFile,
        approvals
    );


    return true;

}


// ============================================================
// Remove Shares for Request
// ============================================================

function deleteShares(
    rid
) {

    const shares =
        readJSON(
            SHARES_FILE
        );


    const remaining =
        shares.filter(
            share =>
                share.rid !== rid
        );


    writeJSON(
        SHARES_FILE,
        remaining
    );


    const submissions =
        readJSON(
            SUBMISSION_FILE
        );


    const remainingSubmissions =
        submissions.filter(
            submission =>
                submission.rid !== rid
        );


    writeJSON(
        SUBMISSION_FILE,
        remainingSubmissions
    );


    audit(

        "REQUEST_SHARES_DELETED",

        {

            rid

        }

    );


    return true;

}


// ============================================================
// Export
// ============================================================

module.exports = {

    validateShare,

    verifyApproval,

    submitShare,

    submitShares,

    getSubmittedShares,

    getSubmittedObservers,

    getShareCount,

    getApprovalStatus,

    getShareSubmissionStatus,

    markApprovalShareSubmitted,

    deleteShares

};



// ============================================================
// Standalone Automatic Test
// ============================================================

if (require.main === module) {

    console.log(
        "\n=================================================="
    );

    console.log(
        " OBSERVER SHARE SUBMISSION - AUTOMATIC"
    );

    console.log(
        "==================================================\n"
    );

    try {

        // ----------------------------------------------------
        // IMPORTANT:
        // This is the REQUEST ID, not the RECORD ID.
        // ----------------------------------------------------

        const rid =
            "RID-DEMO-1787911962683";


        // ----------------------------------------------------
        // Read Alice's generated Shamir shares
        // ----------------------------------------------------

        const allShares =
            readJSON(
                SHARES_FILE
            );


        if (!Array.isArray(allShares)) {

            throw new Error(
                "database/shares.json must contain an array"
            );

        }


        // ----------------------------------------------------
        // Automatically select O1, O2 and O3
        // because threshold = 3
        // ----------------------------------------------------

        const observerMap = {

            1: "O1",
            2: "O2",
            3: "O3"

        };


        const shareList = [];


        for (
            const observerIndex of [1, 2, 3]
        ) {

            const share =
                allShares.find(

                    item =>

                        item.recordId &&
                        Number(
                            item.observerIndex
                        ) === observerIndex

                );


            if (!share) {

                throw new Error(

                    `Share for observer index ` +
                    `${observerIndex} not found`

                );

            }


            shareList.push({

                observerId:
                    observerMap[
                        observerIndex
                    ],

                x:
                    share.x,

                y:
                    share.y

            });

        }


        console.log(
            "Request ID:",
            rid
        );

        console.log(
            "Shares found:",
            shareList.length
        );


        // ----------------------------------------------------
        // Check approval
        // ----------------------------------------------------

        const approval =
            getApprovalStatus(
                rid
            );


        console.log(
            "\nApproval status:"
        );

        console.log(
            "Threshold:",
            approval.threshold
        );

        console.log(
            "Approval count:",
            approval.approvalCount
        );

        console.log(
            "Threshold reached:",
            approval.approved
        );


        if (
            !approval.approved
        ) {

            throw new Error(
                "Observer threshold has not been reached"
            );

        }


        // ----------------------------------------------------
        // Automatically submit O1, O2 and O3
        // ----------------------------------------------------

        console.log(
            "\nSubmitting observer shares..."
        );


        const result =
            submitShares(

                rid,

                shareList

            );


        // ----------------------------------------------------
        // Display individual results
        // ----------------------------------------------------

        for (
            const item of result.results
        ) {

            console.log(
                "\n----------------------------------------------"
            );

            console.log(
                "Observer:",
                item.observerId
            );

            console.log(
                "Success:",
                item.success
            );

            if (
                item.success
            ) {

                console.log(
                    "Share count:",
                    item.shareCount
                );

                console.log(
                    "Threshold:",
                    item.threshold
                );

                console.log(
                    "Threshold reached:",
                    item.thresholdReached
                );

            } else {

                console.log(
                    "Reason:",
                    item.reason
                );

            }

        }


        // ----------------------------------------------------
        // Final status
        // ----------------------------------------------------

        const finalStatus =
            getShareSubmissionStatus(
                rid
            );


        console.log(
            "\n=================================================="
        );

        console.log(
            " FINAL SHARE SUBMISSION STATUS"
        );

        console.log(
            "=================================================="
        );

        console.log(
            "Request ID:",
            rid
        );

        console.log(
            "Threshold:",
            finalStatus.threshold
        );

        console.log(
            "Submitted shares:",
            finalStatus.submittedShareCount
        );

        console.log(
            "Remaining shares:",
            finalStatus.remainingShares
        );

        console.log(
            "Threshold reached:",
            finalStatus.thresholdReached
        );


        if (
            finalStatus.thresholdReached
        ) {

            console.log(
                "\nSUCCESS: Threshold reached."
            );

            console.log(
                "Ready for secret reconstruction."
            );

        } else {

            console.log(
                "\nThreshold has not yet been reached."
            );

        }


    } catch (error) {

        console.error(
            "\nShare submission failed:"
        );

        console.error(
            error.message
        );

        process.exitCode = 1;

    }

}





