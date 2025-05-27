// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {AllowList, RegisteredTEE} from "../src/AllowList.sol";
import {QuoteParser, WorkloadId} from "../src/utils/QuoteParser.sol";
import {MockAutomataDcapAttestationFee} from "./mocks/MockAutomataDcapAttestationFee.sol";

contract AllowListTest is Test {
    AllowList public allowlist;
    MockAutomataDcapAttestationFee public attestationContract;

    function setUp() public {
        // deploy a fresh set of test contracts before each test
        attestationContract = new MockAutomataDcapAttestationFee();
        allowlist = new AllowList(address(attestationContract));
    }

    function test_succesful_registerTEEService() public {
        attestationContract.setSuccess(true);
        bytes memory output = vm.readFileBinary("test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/output.bin");
        attestationContract.setOutput(output);

        address expectedAddress = 0xf200f222043C5bC6c70AA6e35f5C5FDe079F3a03;
        uint64 expectedRegisteredAt = uint64(block.timestamp);
        // note: this is taken directly from the output of QuoteParser.extractWorkloadId, so it's not
        // a good test of the QuoteParser.extractWorkloadId function, but it's a good regression test
        WorkloadId expectedWorkloadId = WorkloadId.wrap(0xeee0d5f864e6d46d6da790c7d60baac5c8478eb89e86667336d3f17655e9164e);

        bytes memory quote = vm.readFileBinary("test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote.bin");
        vm.expectEmit(address(allowlist));
        emit AllowList.TEEServiceRegistered(expectedAddress, expectedWorkloadId, quote, false);
        allowlist.registerTEEService(quote);

        (uint64 registeredAt, WorkloadId workloadId, bytes memory rawQuote) =
            allowlist.registeredTEEs(expectedAddress);
        vm.assertEq(registeredAt, expectedRegisteredAt, "Registered at mismatch");
        vm.assertEq(WorkloadId.unwrap(workloadId), WorkloadId.unwrap(expectedWorkloadId), "Workload ID mismatch");
        vm.assertEq(rawQuote, quote, "Raw quote mismatch");
    }

    function test_reverts_with_invalid_quote_registerTEEService() public {
        attestationContract.setSuccess(false);
        // don't bother setting the output, since it should revert before it's used

        vm.expectPartialRevert(AllowList.InvalidQuote.selector); // the "partial" just means we don't care about the bytes argument to InvalidQuote(bytes)
        bytes memory quote = vm.readFileBinary("test/raw_tdx_quotes/bf42a348f49c9f8ab2ef750ddaffd294c45d8adf947e4d1a72158dcdbd6997c2ca7decaa1ad42648efebdfefe79cbc1b63eb2499fe2374648162fd8f5245f446/quote.bin");
        allowlist.registerTEEService(quote);
    }

    function testFuzz_registerTEEService(bytes memory _quote) public { /** TODO: fuzz things that are fuzzable **/}
}
