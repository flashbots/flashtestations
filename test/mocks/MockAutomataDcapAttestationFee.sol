// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title MockAutomataDcapAttestationFee
 * @dev A mock implementation of the AutomataDcapAttestationFee contract for testing
 * @dev This mock allows us to control the output of the verifyAndAttestOnChain function,
 *      and skip dealing with the vast complexity of Automata's DCAP Attestation contract
 * @dev This is useful for testing the FlashtestationRegistry contract with different quote and output values
 *      without having to deploy the AutomataDcapAttestationFee contract
 * @dev This is also useful for unblocking Unichain + Flashbots from testing in a devnet, where we do not
 *      want to deal with the complexity of deploying the many contracts that are required for the DCAP Attestation
 */
contract MockAutomataDcapAttestationFee {
    struct QuoteResult {
        bool success;
        bytes output;
    }

    mapping(bytes => QuoteResult) public quoteResults;
    uint256 public baseFee; // fixed fee in wei

    error InsufficientFee(uint256 required, uint256 provided);

    function verifyAndAttestOnChain(bytes calldata rawQuote) external payable returns (bool, bytes memory) {
        require(msg.value >= baseFee, InsufficientFee(baseFee, msg.value));

        QuoteResult memory result = quoteResults[rawQuote];
        return (result.success, result.output);
    }

    function setQuoteResult(bytes calldata rawQuote, bool _success, bytes memory _output) public {
        quoteResults[rawQuote] = QuoteResult(_success, _output);
    }

    function setBaseFee(uint256 _baseFee) public {
        baseFee = _baseFee;
    }
}
