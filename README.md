# Flashtestations

A protocol for allowing any [TDX device](https://collective.flashbots.net/t/building-secure-ethereum-blocks-on-minimal-intel-tdx-confidential-vms/3795) to prove its output onchain

Its first use case will be for proving that blocks on the Unichain L2 were built [using fair and transparent ordering rules](https://blog.uniswap.org/rollup-boost-is-live-on-unichain)

You can find a [specification for the protocol here](https://github.com/flashbots/rollup-boost/blob/main/specs/flashtestations.md)

## System Components

1. TEE Devices: identified uniquely by their WorkloadId, see [QuoteParser's `extractWorkloadId`](src/utils/QuoteParser.sol)
1. TEE-controlled Public Keys: these are used to identify and verify TEEs and their outputs
1. TEE Attestations: also called Quotes, which are managed by the [FlashtestationRegistry.sol](src/FlashtestationRegistry.sol)
1. Automata DCAP Protocol: Flashtestations uses [Automata's protocol](https://github.com/automata-network/automata-dcap-attestation) to perform onchain verification of TDX attestations
1. Policies: specifically [BlockBuilderPolicy.sol](src/BlockBuilderPolicy.sol), which store Governance-approved WorkloadIds that are associated with vetted versions of Flashbot's TEE-builder software, [op-rbuilder](https://github.com/flashbots/rbuilder/blob/08f6ece0f270c15653a0f19ca9cbd86d332ea78c/crates/op-rbuilder/README.md?plain=1)
1. Block Signature Transaction: see [BlockBuilderPolicy's `verifyBlockBuilderProof`](src/utils/QuoteParser.sol)
1. Governance Values: The permissioned entities that are the only ones able to add WorkloadIds to Policies

## System Flows

1. Registering a TEE Device (also referred to as a block builder)

   a. Should only be callable from a TEE-controlled address

   b. Verify TEE Quote

   c. extract and store TEE address and workload info

1. Verify Flashtestation Transaction

   a. Check signature of transactions against registry of live builder keys

   b. emit an event indicating the block was built by a particular TEE device (identified by its WorkloadId)

1. Invalidating a TEE Device

   a. Mark TEE device as invalid, which should be done if it's underlying DCAP collateral values have been invalidated

1. Adding a WorkloadId to a Policy

   a. Can only be done by the owner of the Policy

   b. Only registered TEE's can have their WorkloadIds added to a Policy

   c. Once its WorkloadId has been added to a Policy, the TEE will be able to prove it built a block using the "Verify Flashtestation Transaction" flow above

1. Removing a WorkloadId from a Policy

   a. This is done when the block builder software running on this TEE is no longer correct (either because of newer versions replacing it, or bugs that have been found)

   b. Can only be done by the owner of the Policy

   c. The WorkloadId must already exist on the Policy

   d. Once its WorkloadId has been removed from a Policy, it will no longer be able to prove it built a block.

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

# this is the workload ID emitted in the event from the RegisterTEEScript up above
WORKLOAD_ID=0xeee********************************************************9164e
```

Then, to execute, run:

```
forge script --chain 1301 script/Interactions.s.sol:AddWorkloadToPolicyScript --rpc-url $UNICHAIN_SEPOLIA_RPC_URL --broadcast --verify --interactives 1 -vvvv
```
