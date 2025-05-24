// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title MockAutomataDcapAttestationFee
 * @dev A mock implementation of the AutomataDcapAttestationFee contract for testing
 * @dev This mock allows us to control the output of the verifyAndAttestOnChain function,
 *      and skip dealing with the vast complexity of Automata's DCAP Attestation contract
 * @dev This is useful for testing the AllowList contract with different quote and output values
 *      without having to deploy the AutomataDcapAttestationFee contract
 */
contract MockAutomataDcapAttestationFee {
    bool public success;
    bytes public output;

    constructor() {}

    function verifyAndAttestOnChain(bytes calldata /* rawQuote */ ) external view returns (bool, bytes memory) {
        return (success, output);
    }

    function setSuccess(bool _success) public {
        success = _success;
    }

    function setOutput(bytes memory _output) public {
        output = _output;
    }
}
