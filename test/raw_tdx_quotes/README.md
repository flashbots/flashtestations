# Raw TDX Quotes (For Testing)

This directory contains TDX quote and serialized Output values that we use for testing

## File Structure

Each directory within `raw_tdx_quotes/` is named by the 64-byte hex uncompressed public key that was used for the `TD10ReportBody.reportData` field. Each of these public key directories contains a 

- `quote.bin`: which is a TDX quote binary file whose `TD10ReportBody.reportData` is the public key named by its parent directory
- `output.bin`: which is the binary output returned by `AutomataDcapAttestationFee.verifyAndAttestOnChain` when called on the Ethereum Sepolia network

### Helpers

- `hex2bin.py`: a simple python script for writing string hex data (such as `0xdeadbeef`) in its binary form to a file. We use this to take the 0x-prefixed hex string data given to us in events from running Forge scripts and write it in file form that can be read with the Forge cheatcode `vm.readFileBinary`