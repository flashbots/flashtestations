// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {AllowList, RegisteredTEE} from "../src/AllowList.sol";
import {QuoteParser, WorkloadId} from "../src/utils/QuoteParser.sol";
import {MockAutomataDcapAttestationFee} from "./mocks/MockAutomataDcapAttestationFee.sol";
import {
    Helper
} from "./helpers/Helper.sol";
import {TD10ReportBody} from "automata-dcap-attestation/contracts/types/V4Structs.sol";
import {Output} from "automata-dcap-attestation/contracts/types/CommonStruct.sol";


contract AllowListTest is Test {
    AllowList public allowlist;
    MockAutomataDcapAttestationFee public attestationContract;
    string public bf42quotePath =
        "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/";
    address public userAddress = 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03; // this is the forge-provided address that makes all the function calls

    function setUp() public {
        // deploy a fresh set of test contracts before each test
        attestationContract = new MockAutomataDcapAttestationFee();
        allowlist = new AllowList(address(attestationContract));
    }

    function test_succesful_registerTEEService() public {
        // first get a valid attestation quote stored
        attestationContract.setSuccess(true);
        bytes memory output = vm.readFileBinary(string(abi.encodePacked(bf42quotePath, "output.bin")));
        attestationContract.setOutput(output);

        address expectedAddress = userAddress;
        uint64 expectedRegisteredAt = uint64(block.timestamp);
        // note: this is taken directly from the output of QuoteParser.extractWorkloadId, so it's not
        // a good test of the QuoteParser.extractWorkloadId function, but it's a good regression test
        WorkloadId expectedWorkloadId =
            WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e);

        bytes memory quote = vm.readFileBinary(string(abi.encodePacked(bf42quotePath, "quote.bin")));
        vm.expectEmit(address(allowlist));
        emit AllowList.TEEServiceRegistered(expectedAddress, expectedWorkloadId, quote, false);
        allowlist.registerTEEService(quote);

        (uint64 registeredAt, WorkloadId workloadId, bytes memory rawQuote) = allowlist.registeredTEEs(expectedAddress);
        vm.assertEq(registeredAt, expectedRegisteredAt, "Registered at mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(rawQuote, quote, "Raw quote mismatch");
    }

    function test_reverts_with_invalid_quote_registerTEEService() public {
        attestationContract.setSuccess(false);
        // don't bother setting the output, since it should revert before it's used

        vm.expectPartialRevert(AllowList.InvalidQuote.selector); // the "partial" just means we don't care about the bytes argument to InvalidQuote(bytes)
        bytes memory quote = vm.readFileBinary(string(abi.encodePacked(bf42quotePath, "quote.bin")));
        allowlist.registerTEEService(quote);
    }

    function test_quote_parsing() public {
        // first get a valid attestation quote stored
        attestationContract.setSuccess(true);
        bytes memory mockOutput = vm.readFileBinary(string(abi.encodePacked(bf42quotePath, "output.bin")));
        attestationContract.setOutput(mockOutput);
        bytes memory quote = vm.readFileBinary(string(abi.encodePacked(bf42quotePath, "quote.bin")));
        allowlist.registerTEEService(quote);

        // now test parsing the quote by changing arbitrary values and seeing that
        // the effect is as we wish

        (uint64 registeredAt, WorkloadId workloadId, bytes memory rawQuote) = allowlist.registeredTEEs(userAddress);
        Output memory output = Helper.deserializeOutput(rawQuote);
        TD10ReportBody memory parsedReport = QuoteParser.parseV4VerifierOutput(output.quoteBody);
        vm.assertEq(parsedReport.teeTcbSvn, parsedReport.teeTcbSvn, "teeTcbSvn mismatch");
        vm.assertEq(parsedReport.mrSeam, parsedReport.mrSeam, "mrSeam mismatch");
        vm.assertEq(parsedReport.mrsignerSeam, parsedReport.mrsignerSeam, "mrsignerSeam mismatch");
        vm.assertEq(parsedReport.seamAttributes, parsedReport.seamAttributes, "seamAttributes mismatch");
        vm.assertEq(parsedReport.tdAttributes, parsedReport.tdAttributes, "tdAttributes mismatch");
        vm.assertEq(parsedReport.xFAM, parsedReport.xFAM, "xFAM mismatch");
        vm.assertEq(parsedReport.mrTd, parsedReport.mrTd, "mrTd mismatch");
        vm.assertEq(parsedReport.mrConfigId, parsedReport.mrConfigId, "mrConfigId mismatch");
        vm.assertEq(parsedReport.mrOwner, parsedReport.mrOwner, "mrOwner mismatch");
        vm.assertEq(parsedReport.mrOwnerConfig, parsedReport.mrOwnerConfig, "mrOwnerConfig mismatch");
        vm.assertEq(parsedReport.rtMr0, parsedReport.rtMr0, "rtMr0 mismatch");
        vm.assertEq(parsedReport.rtMr1, parsedReport.rtMr1, "rtMr1 mismatch");
        vm.assertEq(parsedReport.rtMr2, parsedReport.rtMr2, "rtMr2 mismatch");
        vm.assertEq(parsedReport.rtMr3, parsedReport.rtMr3, "rtMr3 mismatch");
        vm.assertEq(parsedReport.reportData, parsedReport.reportData, "reportData mismatch");
    }

    function testFuzz_registerTEEService(bytes memory _quote) public {
        /**
         * TODO: fuzz things that are fuzzable *
         */
    }
}
