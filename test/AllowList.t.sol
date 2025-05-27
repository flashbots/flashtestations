// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {AllowList, RegisteredTEE} from "../src/AllowList.sol";
import {QuoteParser, WorkloadId} from "../src/utils/QuoteParser.sol";
import {MockAutomataDcapAttestationFee} from "./mocks/MockAutomataDcapAttestationFee.sol";
import {Helper} from "./helpers/Helper.sol";
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

    function test_successful_registerTEEService() public {
        // first get a valid attestation quote stored
        bytes memory mockOutput = vm.readFileBinary(Helper.concat(bf42quotePath, "output.bin"));
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        address expectedAddress = userAddress;
        uint64 expectedRegisteredAt = uint64(block.timestamp);
        // note: this is taken directly from the output of QuoteParser.extractWorkloadId, so it's not
        // a good test of the QuoteParser.extractWorkloadId function, but it's a good regression test
        WorkloadId expectedWorkloadId =
            WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e);

        bytes memory mockQuote = vm.readFileBinary(Helper.concat(bf42quotePath, "quote.bin"));
        vm.expectEmit(address(allowlist));
        emit AllowList.TEEServiceRegistered(expectedAddress, expectedWorkloadId, mockQuote, false);
        allowlist.registerTEEService(mockQuote);

        (uint64 registeredAt, WorkloadId workloadId, bytes memory rawQuote) = allowlist.registeredTEEs(expectedAddress);
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(registeredAt, expectedRegisteredAt, "Registered at mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
    }

    function test_successful_re_registerTEEService() public {
        bytes memory mockOutput = vm.readFileBinary(Helper.concat(bf42quotePath, "output.bin"));
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        address expectedAddress = userAddress;
        uint64 expectedRegisteredAt = uint64(block.timestamp);
        // note: this is taken directly from the output of QuoteParser.extractWorkloadId, so it's not
        // a good test of the QuoteParser.extractWorkloadId function, but it's a good regression test
        WorkloadId expectedWorkloadId =
            WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e);

        bytes memory mockQuote = vm.readFileBinary(Helper.concat(bf42quotePath, "quote.bin"));
        vm.expectEmit(address(allowlist));
        emit AllowList.TEEServiceRegistered(expectedAddress, expectedWorkloadId, mockQuote, false);
        allowlist.registerTEEService(mockQuote);

        (uint64 registeredAt, WorkloadId workloadId, bytes memory rawQuote) = allowlist.registeredTEEs(expectedAddress);
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(registeredAt, expectedRegisteredAt, "Registered at mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
    }

    function test_reverts_with_invalid_quote_registerTEEService() public {
        attestationContract.setSuccess(false);
        // don't bother setting the output, since it should revert before it's used

        vm.expectPartialRevert(AllowList.InvalidQuote.selector); // the "partial" just means we don't care about the bytes argument to InvalidQuote(bytes)
        bytes memory quote = vm.readFileBinary(Helper.concat(bf42quotePath, "quote.bin"));
        allowlist.registerTEEService(quote);
    }

    function test_reverts_with_registering_same_quote_twice() public {
        bytes memory mockOutput = vm.readFileBinary(Helper.concat(bf42quotePath, "output.bin"));
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        bytes memory mockQuote = vm.readFileBinary(Helper.concat(bf42quotePath, "quote.bin"));
        allowlist.registerTEEService(mockQuote);

        address expectedAddress = userAddress;
        uint64 expectedRegisteredAt = uint64(block.timestamp);
        WorkloadId expectedWorkloadId =
            WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e);

        vm.expectRevert(
            abi.encodeWithSelector(AllowList.TEEServiceAlreadyRegistered.selector, expectedAddress, expectedWorkloadId)
        );
        allowlist.registerTEEService(mockQuote);
    }

    function test_reverts_with_invalid_quote_version_quote_parsing_helper() public {
        bytes memory mockOutput = vm.readFileBinary(Helper.concat(bf42quotePath, "output.bin"));

        Output memory output = Helper.deserializeOutput(mockOutput);
        output.quoteVersion = 0x0000;
        bytes memory serializedOutput = Helper.serializeOutput(output);

        attestationContract.setSuccess(true);
        attestationContract.setOutput(serializedOutput);
        bytes memory mockQuote = vm.readFileBinary(Helper.concat(bf42quotePath, "quote.bin"));
        vm.expectRevert(QuoteParser.InvalidTEEVersion.selector, 0);
        allowlist.registerTEEService(mockQuote);
    }

    function test_reverts_with_invalid_tee_type() public {
        bytes memory mockOutput = vm.readFileBinary(Helper.concat(bf42quotePath, "output.bin"));

        Output memory output = Helper.deserializeOutput(mockOutput);
        output.tee = bytes4(0x00000000);
        bytes memory serializedOutput = Helper.serializeOutput(output);

        attestationContract.setSuccess(true);
        attestationContract.setOutput(serializedOutput);
        bytes memory mockQuote = vm.readFileBinary(Helper.concat(bf42quotePath, "quote.bin"));
        vm.expectRevert(QuoteParser.InvalidTEEType.selector, 0);
        allowlist.registerTEEService(mockQuote);
    }

    function test_reverts_with_too_large_quote() public {
        // test parsing the quote by changing arbitrary values and seeing the changes
        // have the desired result
        bytes memory mockQuote = vm.readFileBinary(Helper.concat(bf42quotePath, "quote.bin"));

        // take a 4.9K file and concatenate it 5 times to make it over the 20KB limit
        bytes memory tooLargeQuote = abi.encodePacked(mockQuote, mockQuote, mockQuote, mockQuote, mockQuote);
        vm.expectRevert(abi.encodeWithSelector(AllowList.ByteSizeExceeded.selector, tooLargeQuote.length));
        allowlist.registerTEEService(tooLargeQuote);
    }

    function testFuzz_registerTEEService(bytes memory _quote) public {
        /**
         * TODO: fuzz things that are fuzzable *
         */
    }
}
