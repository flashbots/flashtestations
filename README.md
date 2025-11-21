# Flashtestations

A protocol for allowing any [TDX device](https://collective.flashbots.net/t/building-secure-ethereum-blocks-on-minimal-intel-tdx-confidential-vms/3795) to prove its output onchain

Its first use case will be for proving that blocks on the Unichain L2 were built [using fair and transparent ordering rules](https://blog.uniswap.org/rollup-boost-is-live-on-unichain)

You can find a [specification for the protocol here](https://github.com/flashbots/rollup-boost/blob/main/specs/flashtestations.md)

## System Components

1. **TEE Devices**: Identified by their measurement registers which policies use to compute WorkloadIds
1. **TEE-controlled Public Keys**: Used to identify and verify TEEs and their outputs
1. **TEE Attestations**: Also called Quotes, managed by the [FlashtestationRegistry.sol](src/FlashtestationRegistry.sol)
1. **Extended Registration Data**: Application-specific data that is attested to alongside the TEE address
1. **Automata DCAP**: Flashtestations uses [Automata's DCAP library](https://github.com/automata-network/automata-dcap-attestation) for onchain TDX attestation verification
1. **Policies**: Specifically [BlockBuilderPolicy.sol](src/BlockBuilderPolicy.sol), which:
   - Compute WorkloadIds from TEE measurement registers
   - Store Governance-approved WorkloadIds
   - Associate WorkloadIds with vetted versions of TEE software
1. **Block Signature Transaction**: See [BlockBuilderPolicy's `verifyBlockBuilderProof`](src/BlockBuilderPolicy.sol)
1. **Governance Values**: Permissioned entities that can add WorkloadIds to Policies

## System Flows

1. **Registering a TEE Device**

   a. Should only be callable from a TEE-controlled address

   b. Verify TEE Quote

   c. Extract and store:

   - TEE address (from reportData[0:20])
   - Extended registration data for the application to use (keccak of the extended data must match reportData[20:52])
   - Full parsed report body for cheap access to TD report data fields
   - Raw quote for future invalidation

1. **Verify Flashtestation Transaction**

   a. Policy contract checks sender's signature against registry of registered TEEs

   b. Policy computes WorkloadId from the stored report body

   c. Checks if computed WorkloadId is in the approved list

   d. Emit an event indicating the block was built by a particular TEE device

1. **Invalidating a TEE Device**

   a. Mark TEE device as invalid when underlying DCAP collateral values are invalidated

   b. Affects all policies using that TEE

1. **Adding a WorkloadId to a Policy**

   a. Can only be done by the policy owner

   b. WorkloadId is computed from TEE's report body

   c. Once added, TEEs with matching WorkloadId can prove they built blocks via "Verify Flashtestation Transaction"

1. **Removing a WorkloadId from a Policy**

   a. Executed when the TEE software for this workloadId is outdated or has bugs

   b. Can only be done by the policy owner

   c. WorkloadId must already exist in the Policy

   d. Removed WorkloadIds can no longer prove block building

## Deploy

Before deploying anything, create your own `.env` file:

```bash
# fill in the necessary values for your .env. The values you fill in depend on the script that
# you're trying to execute.
# If confused, you can reference
# https://getfoundry.sh/guides/scripting-with-solidity
# for more context
cp env.sample .env
```

Then, provide correct values for the following env vars, which all the forge scripts below will use:

- ETHERSCAN_API_KEY
- RPC_URL

### DeployAll

Deploys both the FlashtestationsRegistry and the BlockBuilderPolicy. This is the simplest and best way to deploy the necessary contracts in the flashtestations repository

```bash
# add the RPC_URL and ETHERSCAN_API_KEY's to your environment. Make sure RPC_URL is set to the intended network (e.g. unichain sepolia)
source .env

# Deploy script/DeployAll.s.sol:DeployAllScript expects run(address owner, address automataAttestationContract)
# See https://github.com/automata-network/automata-dcap-attestation/tree/4c579aff71562afe254de4009f5235873fdcc953?tab=readme-ov-file#deployment
# for the appropriate `AutomataDcapAttestationFee.sol` contract that matches your $RPC_URL's network
forge script script/DeployAll.s.sol:DeployAllScript \
  --sig "run(address,address)" <FLASHTESTATIONS CONTRACT OWNER ADDRESS> <AutomataDcapAttestationFee CONTRACT ADDRESS> \
  --rpc-url $RPC_URL --interactives 1 -vvvv --broadcast --verify
```

### FlashtestationsRegistry

This is the primary contract of this repository. It allows TDX v4 devices to register themselves onchain with an Ethereum address/public key, such that later transactions from that address can be trusted to originate from a TEE.

Before deploying provide correct values for the following env vars:

```
# you can find the deployed values here: https://github.com/automata-network/automata-dcap-attestation?tab=readme-ov-file#testnet
AUTOMATA_DCAP_ATTESTATION_FEE_ADDRESS=0x0000000000000000000000000000000000000042

# this is the contract that can upgrade the registry's code
FLASHTESTATION_REGISTRY_OWNER=0x0000000000000000000000000000000000000042
```

Then, to deploy, run:

```
forge script --chain 1301 script/FlashtestationRegistry.s.sol:FlashtestationRegistryScript --rpc-url $RPC_URL --broadcast --verify --interactives 1 -vvvv
```

### BlockBuilderPolicy

A simple contract that allows your organization (e.g. Flashbots) to permission TEE's and their registered Ethereum addresses + workloadIds

Before deploying provide correct values for the following env vars:

```
# this is the contract FlashtestationRegistry you deployed up above
FLASHTESTATION_REGISTRY_ADDRESS=0x0000000000000000000000000000000000000042

# this is the contract that can upgrade the policy's code
OWNER_BLOCK_BUILDER_POLICY=0x0000000000000000000000000000000000000042
```

Then, to deploy, run:

```
forge script --chain 1301 script/BlockBuilderPolicy.s.sol:BlockBuilderPolicyScript --rpc-url $RPC_URL --broadcast --verify --interactives 1 -vvvv
```

### MockQuotes

#### FetchRemoteQuote

Create a raw attestation quote and store it in `script/raw_tdx_quotes/`. This is needed for the `RegisterTEEScript` script for its $PATH_TO_ATTESTATION_QUOTE argument

Before executing this script, provide correct values for the following env vars:

```
# the TEE-controlled address you want to fetch a remote quote for
# this address will be embedded in the quote's report data.
# Note: **you should control the private key for this address** because
# later on you will need to send transactions using this address
TEE_ADDRESS=0x0000000000000000000000000000000000000042

```

Then, to fetch the quote, run:

```
forge script script/MockQuotes.s.sol:FetchRemoteQuote --rpc-url $RPC_URL -vvvv
```

### Interactions

#### RegisterTEEScript

This registers a TEE-controlled address using a quote generated by a v4 TDX device

Before executing this script, provide correct values for the following env vars:

```
# this is the contract FlashtestationRegistry you deployed up above
FLASHTESTATION_REGISTRY_ADDRESS=0x0000000000000000000000000000000000000042

# this is an absolute path to the raw attestation quote, see the example at: script/raw_tdx_quotes/0x12c14e56d585Dcf3B36f37476c00E78bA9363742/quote.bin.
# If you used `FetchRemoteQuote` script above, you can use the path that the quote was written to by that script for this env var
PATH_TO_ATTESTATION_QUOTE=/some/path/quote.bin
```

Then, to execute, run:

```
# Note: we pass '--skip-simulation' because of a bug where the forge EVM does not contain the precompiles necessary
# to execute the FlashtestationRegistry.registerTEEService, and so we need to skip simulating it locally
#
# Note: we need to use a RPC provider like Alchemy for the $RPC_URL argument, and we can't
# use https://sepolia.unichain.org, because this script makes so many gas-heavy calls that it will last
# longer than 128 blocks worth of time, at which point the full nodes at sepolia.unichain.org will start
# to return errors. We must use RPC provider like Alchemy because they can service calls to archive nodes,
# which get around this problem.
forge script --chain 1301 script/Interactions.s.sol:RegisterTEEScript --rpc-url $RPC_URL --broadcast --verify --interactives 1 -vvvv --skip-simulation
```

#### ComputeWorkloadIdScript

Prints out the WorkloadId for a TEE registered by TEE-controlled address (like in the `RegisterTEEScript` above).

This is needed for the `AddWorkloadToPolicyScript` and `RemoveWorkloadToPolicyScript` scripts below

Before executing this script, provide correct values for the following env vars:

```
# the TEE-controlled address that is embedded in the first 20 bytes of the report data from the
# attestation quote passed in `RegisterTEEScript`. Look at the $PATH_TO_ATTESTATION_QUOTE env var
# you used in `RegisterTEEScript` and use the address from that path
TEE_ADDRESS=0x0000000000000000000000000000000000000042

# this is the proxy address of the FlashtestationRegistry contract you deployed in FlashtestationRegistryScript
FLASHTESTATION_REGISTRY_ADDRESS=0x0000000000000000000000000000000000000042

# this is the proxy address of the BlockBuilderPolicy contract you deployed in BlockBuilderPolicyScript
ADDRESS_BLOCK_BUILDER_POLICY=0x0000000000000000000000000000000000000042
```

Then, to execute, run:

```
forge script --chain 1301 script/Interactions.s.sol:ComputeWorkloadIdScript --rpc-url $RPC_URL
```

#### AddWorkloadToPolicyScript

Add a workloadId computed from the `ComputeWorkloadIdScript` script above

Before executing this script, provide correct values for the following env vars:

```

# this is the contract BlockBuilderPolicy you deployed up above

ADDRESS_BLOCK_BUILDER_POLICY=0x0000000000000000000000000000000000000042

# this is the workload ID computed from the TEE's measurement registers

# You can compute this from a registered TEE's report body using BlockBuilderPolicy.workloadIdForTDRegistration

WORKLOAD_ID=0xeee**************************\*\*\*\***************************9164e

# this is the commit hash of the source code that was used to build the TEE image

# identified by the WORKLOAD_ID above

COMMIT_HASH=1234567890abcdef1234567890abcdef12345678

# a comma-separated list of URLs that point to the source code that was used to build the TEE image identified by the WORKLOAD_ID above

RECORD_LOCATORS="https://github.com/flashbots/flashbots-images/commit/a5aa6c75fbecc4b88faf4886cbd3cb2c667f4a8c, https://ipfs.io/ipfs/bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly"

```

Then, to execute, run:

```
forge script --chain 1301 script/Interactions.s.sol:AddWorkloadToPolicyScript --rpc-url $RPC_URL --broadcast --verify --interactives 1 -vvvv
```

## Upgrade

### UpgradeBlockBuilderFromV1

#### Reason For Upgrade

This is nearly identical to the latest version of the policy contract located at src/BlockBuilderPolicy contract, except in the latest has had the logic around the xfam and tdattributes bit masking removed. This was done because there was a bug in the bit masking logic, and we want to fix the bug and simplify the contract by removing the bit masking logic.

#### Deploy Command

Run the command below, then paste in the private key of the address you want to use to pay for gas and execute the deployment:

```
forge script script/UpgradeBlockBuilderFromV1.s.sol:UpgradeBlockBuilderPolicyV1 \
  --sig "run(address)" <POLICY_PROXY_ADDRESS> \
  --rpc-url <RPC_URL> \
  -vvvvv --verify --broadcast --interactives 1
```

