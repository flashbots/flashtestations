// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {TCBStatus} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";
import {Output} from "automata-dcap-attestation/contracts/types/CommonStruct.sol";
import {BytesUtils} from "@automata-network/on-chain-pccs/utils/BytesUtils.sol";

library Helper {
    using BytesUtils for bytes;

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
    ) pure internal returns (TD10ReportBody memory report) {
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

    /**
    * @title TD10ReportBodyBuilder
    * @notice Builder pattern for TD10ReportBody to allow incremental construction for testing
    */
    struct TD10ReportBodyBuilder {
        bytes16 teeTcbSvn;
        bytes mrSeam;
        bytes mrsignerSeam;
        bytes8 seamAttributes;
        bytes8 tdAttributes;
        bytes8 xFAM;
        bytes mrTd;
        bytes mrConfigId;
        bytes mrOwner;
        bytes mrOwnerConfig;
        bytes rtMr0;
        bytes rtMr1;
        bytes rtMr2;
        bytes rtMr3;
        bytes reportData;
    }

    function newTD10ReportBodyBuilder() pure internal returns (TD10ReportBodyBuilder memory) {
        return TD10ReportBodyBuilder({
            teeTcbSvn: bytes16(0),
            mrSeam: new bytes(0),
            mrsignerSeam: new bytes(0),
            seamAttributes: bytes8(0),
            tdAttributes: bytes8(0),
            xFAM: bytes8(0),
            mrTd: new bytes(0),
            mrConfigId: new bytes(0),
            mrOwner: new bytes(0),
            mrOwnerConfig: new bytes(0),
            rtMr0: new bytes(0),
            rtMr1: new bytes(0),
            rtMr2: new bytes(0),
            rtMr3: new bytes(0),
            reportData: new bytes(0)
        });
    }

    function withTeeTcbSvn(TD10ReportBodyBuilder memory builder, bytes16 value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.teeTcbSvn = value;
        return builder;
    }

    function withMrSeam(TD10ReportBodyBuilder memory builder, bytes memory value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.mrSeam = value;
        return builder;
    }

    function withMrsignerSeam(TD10ReportBodyBuilder memory builder, bytes memory value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.mrsignerSeam = value;
        return builder;
    }

    function withSeamAttributes(TD10ReportBodyBuilder memory builder, bytes8 value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.seamAttributes = value;
        return builder;
    }

    function withTdAttributes(TD10ReportBodyBuilder memory builder, bytes8 value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.tdAttributes = value;
        return builder;
    }

    function withXFAM(TD10ReportBodyBuilder memory builder, bytes8 value) pure internal returns (TD10ReportBodyBuilder memory) {
        builder.xFAM = value;
        return builder;
    }

    function withMrTd(TD10ReportBodyBuilder memory builder, bytes memory value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.mrTd = value;
        return builder;
    }

    function withMrConfigId(TD10ReportBodyBuilder memory builder, bytes memory value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.mrConfigId = value;
        return builder;
    }

    function withMrOwner(TD10ReportBodyBuilder memory builder, bytes memory value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.mrOwner = value;
        return builder;
    }

    function withMrOwnerConfig(TD10ReportBodyBuilder memory builder, bytes memory value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.mrOwnerConfig = value;
        return builder;
    }

    function withRtMr0(TD10ReportBodyBuilder memory builder, bytes memory value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.rtMr0 = value;
        return builder;
    }

    function withRtMr1(TD10ReportBodyBuilder memory builder, bytes memory value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.rtMr1 = value;
        return builder;
    }

    function withRtMr2(TD10ReportBodyBuilder memory builder, bytes memory value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.rtMr2 = value;
        return builder;
    }

    function withRtMr3(TD10ReportBodyBuilder memory builder, bytes memory value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.rtMr3 = value;
        return builder;
    }

    function withReportData(TD10ReportBodyBuilder memory builder, bytes memory value)
        pure
        internal
        returns (TD10ReportBodyBuilder memory)
    {
        builder.reportData = value;
        return builder;
    }

    function build(TD10ReportBodyBuilder memory builder) pure internal returns (TD10ReportBody memory report) {
        report.teeTcbSvn = builder.teeTcbSvn;
        report.mrSeam = builder.mrSeam;
        report.mrsignerSeam = builder.mrsignerSeam;
        report.seamAttributes = builder.seamAttributes;
        report.tdAttributes = builder.tdAttributes;
        report.xFAM = builder.xFAM;
        report.mrTd = builder.mrTd;
        report.mrConfigId = builder.mrConfigId;
        report.mrOwner = builder.mrOwner;
        report.mrOwnerConfig = builder.mrOwnerConfig;
        report.rtMr0 = builder.rtMr0;
        report.rtMr1 = builder.rtMr1;
        report.rtMr2 = builder.rtMr2;
        report.rtMr3 = builder.rtMr3;
        report.reportData = builder.reportData;
    }

    function serializeTD10ReportBody(TD10ReportBody memory report) pure internal returns (bytes memory) {
        // Validate field lengths
        require(report.mrSeam.length == 48, "mrSeam must be 48 bytes");
        require(report.mrsignerSeam.length == 48, "mrsignerSeam must be 48 bytes");
        require(report.mrTd.length == 48, "mrTd must be 48 bytes");
        require(report.mrConfigId.length == 48, "mrConfigId must be 48 bytes");
        require(report.mrOwner.length == 48, "mrOwner must be 48 bytes");
        require(report.mrOwnerConfig.length == 48, "mrOwnerConfig must be 48 bytes");
        require(report.rtMr0.length == 48, "rtMr0 must be 48 bytes");
        require(report.rtMr1.length == 48, "rtMr1 must be 48 bytes");
        require(report.rtMr2.length == 48, "rtMr2 must be 48 bytes");
        require(report.rtMr3.length == 48, "rtMr3 must be 48 bytes");
        require(report.reportData.length == 64, "reportData must be 64 bytes");

        return bytes.concat(
            report.teeTcbSvn,
            report.mrSeam,
            report.mrsignerSeam,
            report.seamAttributes,
            report.tdAttributes,
            report.xFAM,
            report.mrTd,
            report.mrConfigId,
            report.mrOwner,
            report.mrOwnerConfig,
            report.rtMr0,
            report.rtMr1,
            report.rtMr2,
            report.rtMr3,
            report.reportData
        );
    }

    // Output builder pattern for test construction
    struct OutputBuilder {
        uint16 quoteVersion;
        bytes4 tee;
        TCBStatus tcbStatus;
        bytes6 fmspcBytes;
        bytes quoteBody;
        string[] advisoryIDs;
    }

    function newOutputBuilder() pure internal returns (OutputBuilder memory) {
        string[] memory emptyAdvisoryIDs;
        return OutputBuilder({
            quoteVersion: 0,
            tee: bytes4(0),
            tcbStatus: TCBStatus.OK,
            fmspcBytes: bytes6(0),
            quoteBody: new bytes(0),
            advisoryIDs: emptyAdvisoryIDs
        });
    }

    function withQuoteVersion(OutputBuilder memory builder, uint16 value) pure internal returns (OutputBuilder memory) {
        builder.quoteVersion = value;
        return builder;
    }
    function withTee(OutputBuilder memory builder, bytes4 value) pure internal returns (OutputBuilder memory) {
        builder.tee = value;
        return builder;
    }
    function withTcbStatus(OutputBuilder memory builder, TCBStatus value) pure internal returns (OutputBuilder memory) {
        builder.tcbStatus = value;
        return builder;
    }
    function withFmspcBytes(OutputBuilder memory builder, bytes6 value) pure internal returns (OutputBuilder memory) {
        builder.fmspcBytes = value;
        return builder;
    }
    function withQuoteBody(OutputBuilder memory builder, bytes memory value) pure internal returns (OutputBuilder memory) {
        builder.quoteBody = value;
        return builder;
    }
    function withAdvisoryIDs(OutputBuilder memory builder, string[] memory value) pure internal returns (OutputBuilder memory) {
        builder.advisoryIDs = value;
        return builder;
    }

    function build(OutputBuilder memory builder) pure internal returns (Output memory output) {
        output.quoteVersion = builder.quoteVersion;
        output.tee = builder.tee;
        output.tcbStatus = builder.tcbStatus;
        output.fmspcBytes = builder.fmspcBytes;
        output.quoteBody = builder.quoteBody;
        output.advisoryIDs = builder.advisoryIDs;
    }

    function deserializeOutput(bytes memory rawQuote) pure internal returns (Output memory output) {
        // Offsets based on src/utils/QuoteParser.sol and Output struct definition
        // 0:2   - quoteVersion (uint16, BE)
        // 2:6   - tee (bytes4)
        // 6:7   - tcbStatus (TCBStatus, uint8)
        // 7:13  - fmspcBytes (bytes6)
        // 13:   - quoteBody (bytes)
        require(rawQuote.length >= 13, "rawQuote too short");
        
        uint16 quoteVersion = uint16(leBytesToBeUint(rawQuote.substring(0, 2)));
        bytes4 tee = bytes4(rawQuote.substring(2, 6));
        uint8 tcbStatusByte = uint8(rawQuote[6]);
        bytes6 fmspcBytes = bytes6(rawQuote.substring(7, 13));
        
        // Copy quoteBody
        bytes memory quoteBody = rawQuote.substring(13, rawQuote.length - 13);
        
        string[] memory advisoryIDs;
        output.quoteVersion = quoteVersion;
        output.tee = tee;
        output.tcbStatus = TCBStatus(tcbStatusByte);
        output.fmspcBytes = fmspcBytes;
        output.quoteBody = quoteBody;
        output.advisoryIDs = advisoryIDs;
    }

    // taken from
    // https://github.com/automata-network/automata-dcap-attestation/blob/evm-v1.0.0/evm/contracts/utils/BELE.sol
    function leBytesToBeUint(bytes memory encoded) pure internal returns (uint256 decoded) {
        for (uint256 i = 0; i < encoded.length; i++) {
            uint256 digits = uint256(uint8(bytes1(encoded[i])));
            uint256 upperDigit = digits / 16;
            uint256 lowerDigit = digits % 16;

            uint256 acc = lowerDigit * (16 ** (2 * i));
            acc += upperDigit * (16 ** ((2 * i) + 1));

            decoded += acc;
        }
    }
}