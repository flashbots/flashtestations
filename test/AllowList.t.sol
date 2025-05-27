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

    // creating this variable for easy access
    string public bf42quotePath =
        "test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/";
    
    // creating this variable for easy access
    WorkloadId expectedWorkloadId =
            WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e); // this is the workloadID of the TEE we used when writing our tests

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

        address expectedAddress = 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03; // this is the address derived from the quote.bin's public key
        uint64 expectedRegisteredAt = uint64(block.timestamp);
        bytes memory mockQuote = vm.readFileBinary(Helper.concat(bf42quotePath, "quote.bin"));
        vm.expectEmit(address(allowlist));
        emit AllowList.TEEServiceRegistered(expectedAddress, expectedWorkloadId, mockQuote, false);
        allowlist.registerTEEService(mockQuote);

        (uint64 registeredAt, WorkloadId workloadId, bytes memory rawQuote) = allowlist.registeredTEEs(expectedAddress);
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(registeredAt, expectedRegisteredAt, "registeredAt mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
    }

    // test that we can register the same TEEService again with a different quote
    function test_successful_re_registerTEEService() public {
        // do the first register of the TEEService with a valid quote
        bytes memory mockOutput = vm.readFileBinary(Helper.concat("test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/", "output.bin"));
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput);

        address expectedAddress = 0x12c14e56d585Dcf3B36f37476c00E78bA9363742; // this is the address derived from the quote.bin's public key
        uint64 expectedRegisteredAt = uint64(block.timestamp);
        bytes memory mockQuote = vm.readFileBinary(Helper.concat("test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/", "quote.bin"));
        vm.expectEmit(address(allowlist));
        emit AllowList.TEEServiceRegistered(expectedAddress, expectedWorkloadId, mockQuote, false);
        allowlist.registerTEEService(mockQuote);

        (uint64 registeredAt, WorkloadId workloadId, bytes memory rawQuote) = allowlist.registeredTEEs(expectedAddress);
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");
        vm.assertEq(registeredAt, expectedRegisteredAt, "registeredAt mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(rawQuote, mockQuote, "Raw quote mismatch");

        // now register the same TEEService again with a different quote

        bytes memory mockOutput2 = vm.readFileBinary(Helper.concat("test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/", "output2.bin"));
        attestationContract.setSuccess(true);
        attestationContract.setOutput(mockOutput2);

        bytes memory mockQuote2 = vm.readFileBinary(Helper.concat("test/raw_tdx_quotes/0xd204547069c53f9ecff9b30494eb9797615a2f46aa2785db6258104cebb92d48ff4dc0744c36d8470646f4813e61f9a831ffb54b937f7b233f32d271434ccca6/", "quote2.bin"));
        vm.expectEmit(address(allowlist));
        emit AllowList.TEEServiceRegistered(expectedAddress, expectedWorkloadId, mockQuote2, true);
        allowlist.registerTEEService(mockQuote2);

        (uint64 registeredAt2, WorkloadId workloadId2, bytes memory rawQuote2) = allowlist.registeredTEEs(expectedAddress);
        vm.assertEq(rawQuote2, mockQuote2, "Raw quote mismatch");
        vm.assertEq(registeredAt2, expectedRegisteredAt, "registeredAt mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId2), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(rawQuote2, mockQuote2, "Raw quote mismatch");
        vm.assertNotEq(mockQuote, mockQuote2, "Quotes should not be the same");
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

        address expectedAddress = 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03; // this is the address derived from the quote.bin's public key
        uint64 expectedRegisteredAt = uint64(block.timestamp);

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
