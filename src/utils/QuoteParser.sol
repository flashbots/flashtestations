// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

library QuoteParser {
    // Intel TDX V4 byte lengths
    uint256 internal constant REPORT_DATA_FIELD_SIZE = 64;

    error InvalidReportDataLength(uint256 length);

    // Extracts the 64-byte Ethereum uncompressed public key (X-coordinate || Y-coordinate) from the
    // report data field of a TDXQuote
    function extractPublicKeyFromTDXQuote(TD10ReportBody calldata tdReportBody) internal pure returns (bytes memory) {
        if (tdReportBody.reportData.length != REPORT_DATA_FIELD_SIZE) {
            revert InvalidReportDataLength(tdReportBody.reportData.length);
        }
        return tdReportBody.reportData;
    }

    // Extracts and calculates the address from the public key in the TDXQuote
    function extractAddressFromTDXQuote(TD10ReportBody calldata tdReportBody) internal pure returns (address) {
        bytes memory publicKey = extractPublicKeyFromTDXQuote(tdReportBody);
        return address(uint160(uint256(keccak256(publicKey))));
    }

    function calculateWorkloadId(TD10ReportBody calldata tdReportBody) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                tdReportBody.mrTd,
                tdReportBody.rtMr0,
                tdReportBody.rtMr1,
                tdReportBody.rtMr2,
                tdReportBody.rtMr3,
                tdReportBody.mrOwner,
                tdReportBody.mrOwnerConfig,
                tdReportBody.mrConfigId
            )
        );
    }
}
