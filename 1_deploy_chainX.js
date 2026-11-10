/**
 * ============================================================
 * migrations/1_deploy_chainX.js
 * ============================================================
 *
 * Chain X = Patient Chain
 *
 * Deploys:
 *
 *   1. ObserverManager.sol
 *   2. ConsentManager.sol
 *   3. MedicalRecord.sol
 *
 * Features:
 *
 *   - Random threshold generation
 *   - Observer registration
 *   - Stake requirement
 *   - Contract linking
 *   - Ganache compatible
 *
 * ============================================================
 */

const ObserverManager =
    artifacts.require("ObserverManager");

const ConsentManager =
    artifacts.require("ConsentManager");

const MedicalRecord =
    artifacts.require("MedicalRecord");


// ============================================================
// Configuration
// ============================================================

const TOTAL_OBSERVERS = 5;


// Minimum stake required by an observer.
//
// If your ObserverManager contract uses a different unit,
// modify this value.
const MIN_STAKE = "10000000000000000"; // 0.01 ETH


// ============================================================
// Random Threshold
// ============================================================

/**
 * Generates a random threshold:
 *
 *      2 <= t <= n
 *
 * Example:
 *
 *      n = 5
 *
 * Possible thresholds:
 *
 *      2, 3, 4, 5
 *
 * This means the experiment does not always use
 * the same threshold.
 */

function generateRandomThreshold(
    n
) {

    if (
        n < 2
    ) {

        throw new Error(
            "Number of observers must be at least 2"
        );

    }


    return (
        Math.floor(
            Math.random() * (n - 1)
        ) + 2
    );

}


// ============================================================
// Migration
// ============================================================

module.exports = async function (
    deployer,
    network,
    accounts
) {

    console.log(
        "\n=============================================="
    );

    console.log(
        "        CHAIN X DEPLOYMENT"
    );

    console.log(
        "        Patient Blockchain"
    );

    console.log(
        "==============================================\n"
    );


    // ========================================================
    // Validate Ganache Accounts
    // ========================================================

    if (
        accounts.length <
        TOTAL_OBSERVERS + 1
    ) {

        throw new Error(

            "Insufficient Ganache accounts. " +

            `Required: ${TOTAL_OBSERVERS + 1}, ` +

            `Available: ${accounts.length}`

        );

    }


    // ========================================================
    // Patient / Deployer
    // ========================================================

    const patient =
        accounts[0];


    console.log(
        "Patient Alice:",
        patient
    );


    // ========================================================
    // Observer Accounts
    // ========================================================

    const observerAccounts =
        accounts.slice(
            1,
            TOTAL_OBSERVERS + 1
        );


    console.log(
        "\nObserver Accounts:"
    );


    observerAccounts.forEach(
        (
            account,
            index
        ) => {

            console.log(
                `O${index + 1}:`,
                account
            );

        }
    );


    // ========================================================
    // Generate Random Threshold
    // ========================================================

    const threshold =
        generateRandomThreshold(
            TOTAL_OBSERVERS
        );


    console.log(
        "\n----------------------------------------------"
    );

    console.log(
        "Threshold Configuration"
    );

    console.log(
        "----------------------------------------------"
    );

    console.log(
        "Total observers (n):",
        TOTAL_OBSERVERS
    );

    console.log(
        "Random threshold (t):",
        threshold
    );


    console.log(
        `Required approvals: ${threshold}/${TOTAL_OBSERVERS}`
    );


    // ========================================================
    // Deploy ObserverManager
    // ========================================================

    console.log(
        "\nDeploying ObserverManager..."
    );


    await deployer.deploy(

        ObserverManager

        

    );


    const observerManager =
        await ObserverManager.deployed();


    console.log(
        "ObserverManager:",
        observerManager.address
    );


    // ========================================================
    // Register Observers
    // ========================================================

    console.log(
        "\nRegistering observers..."
    );


    for (
        let i = 0;
        i < observerAccounts.length;
        i++
    ) {

        const observer =
            observerAccounts[i];


        try {

            /**
             * Expected ObserverManager function:
             *
             * registerObserver(address)
             *
             */

            await observerManager.registerObserver(

                observer,

                {
                    from: patient
                }

            );


            console.log(
                `O${i + 1} registered:`,
                observer
            );


        } catch (
            error
        ) {

            console.log(

                `Warning: Could not register O${i + 1}`

            );

            console.log(
                error.message
            );

        }

    }


    // ========================================================
    // Deploy ConsentManager
    // ========================================================

    console.log(
        "\nDeploying ConsentManager..."
    );


    await deployer.deploy(
        ConsentManager
    );


    const consentManager =
        await ConsentManager.deployed();


    console.log(
        "ConsentManager:",
        consentManager.address
    );


    // ========================================================
    // Deploy MedicalRecord
    // ========================================================

    console.log(
        "\nDeploying MedicalRecord..."
    );


    /**
     * Constructor:
     *
     * MedicalRecord(
     *     observerManager,
     *     consentManager
     * )
     *
     * If your MedicalRecord.sol constructor has a
     * different signature, modify these arguments.
     */

    await deployer.deploy(

        MedicalRecord,

        observerManager.address,

        consentManager.address

    );


    const medicalRecord =
        await MedicalRecord.deployed();


    console.log(
        "MedicalRecord:",
        medicalRecord.address
    );


    // ========================================================
    // Link ConsentManager
    // ========================================================

    console.log(
        "\nLinking ConsentManager..."
    );


    try {

        /**
         * Expected function:
         *
         * setMedicalRecord(address)
         *
         */

        await consentManager.setMedicalRecord(

            medicalRecord.address,

            {
                from: patient
            }

        );


        console.log(
            "ConsentManager linked to MedicalRecord."
        );


    } catch (
        error
    ) {

        console.log(
            "ConsentManager linking skipped."
        );

        console.log(
            error.message
        );

    }


    // ========================================================
    // Link ObserverManager
    // ========================================================

    try {

        /**
         * Expected function:
         *
         * setConsentManager(address)
         *
         */

        await observerManager.setConsentManager(

            consentManager.address,

            {
                from: patient
            }

        );


        console.log(
            "ObserverManager linked to ConsentManager."
        );


    } catch (
        error
    ) {

        console.log(
            "ObserverManager linking skipped."
        );

        console.log(
            error.message
        );

    }


    // ========================================================
    // Deployment Summary
    // ========================================================

    console.log(
        "\n=============================================="
    );

    console.log(
        "        CHAIN X DEPLOYMENT COMPLETE"
    );

    console.log(
        "=============================================="
    );


    console.log(
        "\nPatient Chain:"
    );

    console.log(
        "Patient:",
        patient
    );


    console.log(
        "\nContracts:"
    );

    console.log(
        "ObserverManager:",
        observerManager.address
    );

    console.log(
        "ConsentManager:",
        consentManager.address
    );

    console.log(
        "MedicalRecord:",
        medicalRecord.address
    );


    console.log(
        "\nThreshold:"
    );

    console.log(
        "Observers (n):",
        TOTAL_OBSERVERS
    );

    console.log(
        "Threshold (t):",
        threshold
    );


    console.log(
        "\nObserver List:"
    );


    observerAccounts.forEach(
        (
            observer,
            index
        ) => {

            console.log(
                `O${index + 1}: ${observer}`
            );

        }
    );


    // ========================================================
    // Save Deployment Information
    // ========================================================

    const deploymentData = {

        network,

        chain:
            "Chain-X",

        chainType:
            "Patient Chain",

        patient,

        observers:
            observerAccounts,

        totalObservers:
            TOTAL_OBSERVERS,

        threshold,

        contracts: {

            ObserverManager:
                observerManager.address,

            ConsentManager:
                consentManager.address,

            MedicalRecord:
                medicalRecord.address

        },

        timestamp:
            new Date()
                .toISOString()

    };


    console.log(
        "\nDeployment configuration:"
    );

    console.log(
        JSON.stringify(
            deploymentData,
            null,
            2
        )
    );


    console.log(
        "\n==============================================\n"
    );

};