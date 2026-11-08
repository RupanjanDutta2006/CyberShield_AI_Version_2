const hre = require("hardhat");

async function main() {
    console.log("Deploying ThreatReportRegistry...\n");

    const Registry = await hre.ethers.getContractFactory(
        "ThreatReportRegistry"
    );

    const registry = await Registry.deploy();
    await registry.waitForDeployment();

    const address = await registry.getAddress();

    console.log("═══════════════════════════════════════════");
    console.log("  ThreatReportRegistry deployed!");
    console.log("  Address:", address);
    console.log("  Network:", hre.network.name);
    console.log("═══════════════════════════════════════════");

    // Write deployment info to a JSON file for Python integration
    const fs = require("fs");
    const deploymentInfo = {
        contractAddress: address,
        network: hre.network.name,
        deployedAt: new Date().toISOString(),
        chainId: hre.network.config.chainId || 31337,
    };

    fs.writeFileSync(
        "deployment.json",
        JSON.stringify(deploymentInfo, null, 4)
    );
    console.log("\nDeployment info saved to deployment.json");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
