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

   a. Policy contract checks signature against registry of registered TEEs

   b. Policy computes WorkloadId from the stored report body

   c. Checks if computed WorkloadId is in the approved list

   d. Emit an event indicating the block was built by a particular TEE device

1. **Invalidating a TEE Device**

   a. Mark TEE device as invalid when underlying DCAP collateral values are invalidated

   b. Affects all policies using that TEE

1. **Adding a WorkloadId to a Policy**

   a. Can only be done by the policy owner

   b. WorkloadId is computed externally from TEE's report body

   c. Once added, TEEs with matching WorkloadId can prove they built blocks via "Verify Flashtestation Transaction"

1. **Removing a WorkloadId from a Policy**

   a. Done when TEE software is outdated or has bugs

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
- UNICHAIN_SEPOLIA_RPC_URL

### Unichain Sepolia

#### FlashtestationsRegistry

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
forge script --chain 1301 script/FlashtestationRegistry.s.sol:FlashtestationRegistryScript --rpc-url $UNICHAIN_SEPOLIA_RPC_URL --broadcast --verify --interactives 1 -vvvv
```

#### BlockBuilderPolicy

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
forge script --chain 1301 script/BlockBuilderPolicy.s.sol:BlockBuilderPolicyScript --rpc-url $UNICHAIN_SEPOLIA_RPC_URL --broadcast --verify --interactives 1 -vvvv
```

#### Interactions

**RegisterTEEScript**

This registers a TEE-controlled address using a quote generated by a v4 TDX device

Before executing this script, provide correct values for the following env vars:

```
# this is the contract FlashtestationRegistry you deployed up above
FLASHTESTATION_REGISTRY_ADDRESS=0x0000000000000000000000000000000000000042

# this is an absolute path to the raw attestation quote, see the example at: script/raw_tdx_quotes/342ad26adb6185cda1aea67ee5f35e9cb5c9cec32b03e8d4382492ca35d53331e906b20edbe46d9337b7b2b2248c633cc2a3aeb3a0ce480dd22b5950860c8a2c
PATH_TO_ATTESTATION_QUOTE=/some/path/quote.bin
```

Then, to execute, run:

```
# Note: we pass '--skip-simulation' because of a bug where the forge EVM does not contain the precompiles necessary
# to execute the FlashtestationRegistry.registerTEEService, and so we need to skip simulating it locally
#
# Note: we need to use a RPC provider like Alchemy for the $UNICHAIN_SEPOLIA_RPC_URL argument, and we can't
# use https://sepolia.unichain.org, because this script makes so many gas-heavy calls that it will last
# longer than 128 blocks worth of time, at which point the full nodes at sepolia.unichain.org will start
# to return errors. We must use RPC provider like Alchemy because they can service calls to archive nodes,
# which get around this problem.
forge script --chain 1301 script/Interactions.s.sol:RegisterTEEScript --rpc-url $UNICHAIN_SEPOLIA_RPC_URL --broadcast --verify --interactives 1 -vvvv --skip-simulation
```

**AddWorkloadToPolicyScript**

Add a workloadId that was previously registered with the `RegisterTEEScript` script above

Before executing this script, provide correct values for the following env vars:

```
# this is the contract BlockBuilderPolicy you deployed up above
ADDRESS_BLOCK_BUILDER_POLICY=0x0000000000000000000000000000000000000042

# this is the workload ID computed from the TEE's measurement registers
# You can compute this from a registered TEE's report body using BlockBuilderPolicy.workloadIdForTDRegistration
WORKLOAD_ID=0xeee********************************************************9164e
```

Then, to execute, run:

```
forge script --chain 1301 script/Interactions.s.sol:AddWorkloadToPolicyScript --rpc-url $UNICHAIN_SEPOLIA_RPC_URL --broadcast --verify --interactives 1 -vvvv
```
