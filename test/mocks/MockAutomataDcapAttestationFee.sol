// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

/**
 * @title MockAutomataDcapAttestationFee
 * @dev A mock implementation of the AutomataDcapAttestationFee contract for testing
 * @dev This mock allows us to control the output of the verifyAndAttestOnChain function,
 *      and skip dealing with the vast complexity of Automata's DCAP Attestation contract
 * @dev This is useful for testing the FlashtestationRegistry contract with different quote and output values
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

    /**
     * @notice Creates a mock TD10ReportBody with arbitrary field values for testing
     * @param teeTcbSvn bytes16
     * @param mrSeam bytes (48 bytes)
     * @param mrsignerSeam bytes (48 bytes)
     * @param seamAttributes bytes8
     * @param tdAttributes bytes8
     * @param xFAM bytes8
     * @param mrTd bytes (48 bytes)
     * @param mrConfigId bytes (48 bytes)
     * @param mrOwner bytes (48 bytes)
     * @param mrOwnerConfig bytes (48 bytes)
     * @param rtMr0 bytes (48 bytes)
     * @param rtMr1 bytes (48 bytes)
     * @param rtMr2 bytes (48 bytes)
     * @param rtMr3 bytes (48 bytes)
     * @param reportData bytes (64 bytes)
     * @return report TD10ReportBody
     */
    function createMockTD10ReportBody(
        bytes16 teeTcbSvn,
        bytes memory mrSeam,
        bytes memory mrsignerSeam,
        bytes8 seamAttributes,
        bytes8 tdAttributes,
        bytes8 xFAM,
        bytes memory mrTd,
        bytes memory mrConfigId,
        bytes memory mrOwner,
        bytes memory mrOwnerConfig,
        bytes memory rtMr0,
        bytes memory rtMr1,
        bytes memory rtMr2,
        bytes memory rtMr3,
        bytes memory reportData
    ) public pure returns (TD10ReportBody memory report) {
        report.teeTcbSvn = teeTcbSvn;
        report.mrSeam = mrSeam;
        report.mrsignerSeam = mrsignerSeam;
        report.seamAttributes = seamAttributes;
        report.tdAttributes = tdAttributes;
        report.xFAM = xFAM;
        report.mrTd = mrTd;
        report.mrConfigId = mrConfigId;
        report.mrOwner = mrOwner;
        report.mrOwnerConfig = mrOwnerConfig;
        report.rtMr0 = rtMr0;
        report.rtMr1 = rtMr1;
        report.rtMr2 = rtMr2;
        report.rtMr3 = rtMr3;
        report.reportData = reportData;
    }
}
