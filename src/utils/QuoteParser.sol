// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";

library QuoteParser {
    // Intel TDX V4 byte lengths
    uint256 internal constant REPORT_DATA_FIELD_SIZE = 64;
    uint256 internal constant MIN_TD_REPORT_BODY_LENGTH = 584; // 584 bytes

    // Extracts the Ethereum address from the REPORTDATA field of a TDReport
    // Assumes the first 20 bytes of REPORTDATA contain the address.
    function extractAddressFromReportDataBytes(bytes calldata reportDataBytes) internal pure returns (address) {
        require(reportDataBytes.length == REPORT_DATA_FIELD_SIZE, "QuoteParser: ReportData must be 64 bytes");
        address addr;
        // Extract the first 20 bytes for the address
        assembly {
            addr := mload(add(reportDataBytes.offset, 0x14)) // Load 32 bytes, address is in lower 20
            addr := shr(96, addr) // Right shift remaining 12 bytesto get the address (most significant 12 bytes are zeroed out)
        }
        return addr;
    }

    function calculateWorkloadIdRaw(
        bytes memory mrtd,
        bytes memory rtmr0,
        bytes memory rtmr1,
        bytes memory rtmr2,
        bytes memory rtmr3,
        bytes memory mrowner,
        bytes memory mrownerconfig,
        bytes memory mrconfigid
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(mrtd, rtmr0, rtmr1, rtmr2, rtmr3, mrowner, mrownerconfig, mrconfigid));
    }

    function calculateWorkloadId(TD10ReportBody calldata tdReportBody) internal pure returns (bytes32) {
        return calculateWorkloadIdRaw(
            tdReportBody.mrTd,
            tdReportBody.rtMr0,
            tdReportBody.rtMr1,
            tdReportBody.rtMr2,
            tdReportBody.rtMr3,
            tdReportBody.mrOwner,
            tdReportBody.mrOwnerConfig,
            tdReportBody.mrConfigId
        );
    }
}