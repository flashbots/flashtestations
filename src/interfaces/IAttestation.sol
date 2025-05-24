// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IAttestation {
    function verifyAndAttestOnChain(bytes calldata rawQuote) external returns (bool, bytes memory);
}
