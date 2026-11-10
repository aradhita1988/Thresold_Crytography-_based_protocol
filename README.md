# ThreshX: Secure Cross-Chain Communication Using Threshold Cryptography

## 1. Project Overview

ThreshX is an observer node-based framework for secure cross-chain communication and healthcare data access using threshold cryptography.

The framework employs Shamir Secret Sharing (SSS) to distribute cryptographic secrets among multiple observer nodes. A predefined threshold of valid shares is required to reconstruct the secret and authorize data access.

It also incorporates a griefing attack detection and mitigation mechanism to improve security and reliability.

## 2. Key Features

- Secure cross-chain communication.
- Observer node-based architecture.
- Threshold cryptography using Shamir Secret Sharing.
- Threshold-based secret reconstruction.
- Griefing attack detection and prevention.
- Secure healthcare data access.
- Performance evaluation under normal and griefing conditions.

## 3. Technologies Used

- Solidity
- Ethereum Blockchain
- Ganache
- Truffle Suite
- Node.js
- Web3.js
- JavaScript

## 4. Project Structure

```text
Healthcare-Observer-Threshold/
├── contracts/       # Solidity smart contracts
├── scripts/         # Experiment and execution scripts
├── migrations/      # Contract deployment scripts
├── test/            # Smart contract tests
├── results/         # Experimental result CSV files
├── charts/          # Performance evaluation graphs
├── .gitignore
├── package.json
├── truffle-config.js
└── README.md
```
### Install dependencies

```bash
npm install
```

### Compile smart contracts

```bash
truffle compile
```

### Deploy contracts and run experiments

Run Normal Access Experiments:
Execute the normal access experiment: node scripts/normalAccess.js
This experiment evaluates legitimate cross-chain data access and records the associated performance metrics.

Run Griefing Attack Experiment:
Execute the griefing attack experiment: node scripts/griefingAttack.js
This experiment evaluates the framework's ability to detect and mitigate griefing attacks involving incomplete or malicious observer participation.

Execute the metrics and aggregation scripts, if configured:
node scripts/metrics.js
node aggregate_result.js




