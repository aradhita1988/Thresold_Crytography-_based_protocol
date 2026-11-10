
require("dotenv").config();

module.exports = {

    networks: {

        // ====================================================
        // Chain X - Patient Blockchain
        // ====================================================

        chainX: {

            host: "127.0.0.1",
            port: 7545,

            network_id:
                process.env.CHAIN_X_NETWORK_ID || "5777",

            gas: 6000000,

            gasPrice: 20000000000,

            confirmations: 0,

            timeout: 100000,

            skipDryRun: true
        },


        // ====================================================
        // Chain Y - Hospital Blockchain
        // ====================================================

        chainY: {

            host: "127.0.0.1",
            port: 7546,

            network_id:
                process.env.CHAIN_Y_NETWORK_ID || "5777",

            gas: 6000000,

            gasPrice: 20000000000,

            confirmations: 0,

            timeout: 100000,

            skipDryRun: true
        }
    },


    // ========================================================
    // Solidity Compiler
    // ========================================================

    compilers: {

        solc: {

            version: "0.8.20",

            settings: {

                optimizer: {

                    enabled: true,

                    runs: 200
                },

                // REQUIRED by ConsentManager.sol
                viaIR: true,

                // Helps compatibility with Ganache
                evmVersion: "paris"
            }
        }
    },


    // ========================================================
    // Directories
    // ========================================================

    contracts_directory:
        "./contracts",

    contracts_build_directory:
        "./build/contracts",

    migrations_directory:
        "./migrations",


    mocha: {

        timeout: 120000
    },


    db: {

        enabled: false
    }
};

