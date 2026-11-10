const HospitalRequest =
    artifacts.require("HospitalRequest");

module.exports = async function (
    deployer,
    network,
    accounts
) {

    console.log("\n==============================================");
    console.log("        CHAIN Y DEPLOYMENT");
    console.log("        Hospital Blockchain");
    console.log("==============================================\n");

    const hospital =
        accounts[0];

    console.log(
        "Hospital account:",
        hospital
    );

    console.log(
        "\nDeploying HospitalRequest..."
    );

    await deployer.deploy(
        HospitalRequest
    );

    const hospitalRequest =
        await HospitalRequest.deployed();

    console.log(
        "HospitalRequest:",
        hospitalRequest.address
    );

    console.log(
        "\n=============================================="
    );

    console.log(
        "        CHAIN Y DEPLOYMENT COMPLETE"
    );

    console.log(
        "==============================================\n"
    );

    console.log(
        "Hospital:",
        hospital
    );

    console.log(
        "HospitalRequest:",
        hospitalRequest.address
    );

    console.log(
        "Network:",
        network
    );

    console.log("");
};
