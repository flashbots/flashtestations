# Raw TDX Quotes (For Testing)

This directory contains TDX quote and serialized Output values that we use for testing

## File Structure

Each directory within `raw_tdx_quotes/` is named by the 64-byte hex uncompressed public key that was used for the `TD10ReportBody.reportData` field. Each of these public key directories contains a 

- `quote.bin`: which is a TDX quote binary file whose `TD10ReportBody.reportData` is the public key named by its parent directory.
- `output.bin`: which is the [Output](https://github.com/automata-network/automata-dcap-attestation/blob/evm-v1.0.0/evm/contracts/types/CommonStruct.sol#L113) returned by `AutomataDcapAttestationFee.verifyAndAttestOnChain` when called on the Ethereum Sepolia network

### Helpers

- `hex2bin.py`: a simple python script for writing string hex data (such as `0xdeadbeef`) in its binary form to a file. We use this to take the hex string of the serialized [Output](https://github.com/automata-network/automata-dcap-attestation/blob/evm-v1.0.0/evm/contracts/types/CommonStruct.sol#L113) emitted by the `AttestationEntrypointBase.AttestationSubmitted` event, which you place in `quote_event.htx` non-0x-prefixed, and write it in to `output.bin`, so we can use it to mock return values in our tests for different TDX quotes