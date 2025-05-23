# Flashtestations

A protocol for allowing any [TDX device](https://collective.flashbots.net/t/building-secure-ethereum-blocks-on-minimal-intel-tdx-confidential-vms/3795) to prove its output onchain

Its first use case will be for proving that blocks on the Unichain L2 were built [using fair and transparent ordering rules](https://blog.uniswap.org/rollup-boost-is-live-on-unichain)


## System Components

1. TEE Devices
1. TEE Public Keys (these are used to identify and verify TEEs and their outputs)
1. TEE Attestations (also called Quotes)
1. Block Signature Transaction
1. Governance Values

## System Flows

1. Initialize Governance values
    
    a. Governance (e.g. UNI DAO) is the only address than can register and de-register TEE devices
    
    b. Governance is the only address that can wipe the Registry (this exists only as a nuclear option to protect against system compromise)
1. Registering a TEE Device (also referred to as a block builder)
    
    a. Should only be callable by governance
    
    b. Verify TEE Quote
    
    c. extract and store TEE public key
    
    d. set liveness (we want a way to indicate that a TEE device has not been active for a long period of time, and for that we use liveness)
    
    e. Mark TEE device as "active"
1. Verify Flashtestation transaction
    
    a. Check signature of transactions against registry of live builder keys
    
    b. update TEE device liveness
1. Deregistering a TEE Device
    
    a. Should only be callable by governance
    
    b. Mark TEE device as "retired"

## Deploy

This will perform a simple test to see if onchain verification of a tdx attestation works

`forge script --chain 11155111 --rpc-url $ETHEREUM_SEPOLIA_RPC_URL script/AllowList.s.sol:AllowListScript`

## TODOs

- [X] Implement TEE Device Registry
- [] Implement Flashtestation transaction verification

## Open Questions
- Should it be Upgradeable?
    Pros: 
        - very simple to account for changes to the Automata DCAP Attestation contract, contract bugs, contract upgrades
        - Doesn't really impact the trust model, because we already expect to have some Security Council of Unichain + Flashbots in the beginning that manages which workloadIDs to trust (via the setting of Policies)
    Cons:
        - trust model now relies on owner (probably a security council of Unichain + Flashbots) to remain not collude. If they do collude, they can upgrade the contract to emit a malicious `Registered` event and trick users into incorrectly trusting that blocks are being verified by a trusted TEE


## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
