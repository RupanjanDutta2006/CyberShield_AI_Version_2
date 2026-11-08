require("@nomicfoundation/hardhat-toolbox");

const privateKey =
    process.env.BLOCKCHAIN_PRIVATE_KEY ||
    process.env.DEPLOYER_PRIVATE_KEY ||
    "";

const accounts = privateKey ? [privateKey] : [];

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
    solidity: {
        version: "0.8.24",
        settings: {
            optimizer: {
                enabled: true,
                runs: 200,
            },
        },
    },
    networks: {
        hardhat: {
            chainId: 31337,
        },
        localhost: {
            url: process.env.BLOCKCHAIN_RPC_URL || "http://127.0.0.1:8545",
            chainId: 31337,
        },
        sepolia: {
            url: process.env.SEPOLIA_RPC_URL || "",
            accounts: accounts,
            chainId: 11155111,
        },
    },
};
