// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title IAttestation
 * @dev Interface for the Automata DCAPattestation contract, which verifies TEE quotes
 */
interface IAttestation {
    function verifyAndAttestOnChain(bytes calldata rawQuote) external payable returns (bool, bytes memory);
}
