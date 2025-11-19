// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {FlashtestationRegistry} from "../src/FlashtestationRegistry.sol";
import {IFlashtestationRegistry} from "../src/interfaces/IFlashtestationRegistry.sol";

/// @title GetRegistrationScript
/// @notice Script to query the registration details of a TEE address from the FlashtestationRegistry
/// @notice Example usage:
/// @notice forge script script/GetRegistration.s.sol:GetRegistrationScript \
///   --sig "run(address,address)" <TEE_ADDRESS> <FLASHTESTATION_REGISTRY_ADDRESS> \
///   --rpc-url $RPC_URL
contract GetRegistrationScript is Script {
    function setUp() public {}

    function run(address teeAddress, address registryAddress) public view {
        // Log input addresses
        console.log("TEE_ADDRESS:");
        console.logAddress(teeAddress);
        console.log("FLASHTESTATION_REGISTRY_ADDRESS:");
        console.logAddress(registryAddress);
        console.log("");

        // Instantiate the registry contract
        FlashtestationRegistry registry = FlashtestationRegistry(registryAddress);

        // Call getRegistration
        (bool isValid, IFlashtestationRegistry.RegisteredTEE memory registration) = registry.getRegistration(teeAddress);

        // Output the registration details
        console.log("=== Registration Details ===");
        console.log("Is Valid:", isValid);
        console.log("");

        if (registration.rawQuote.length > 0) {
            console.log("Raw Quote Length:", registration.rawQuote.length);
            console.log("Quote Hash:");
            console.logBytes32(registration.quoteHash);
            console.log("");

            console.log("Extended Registration Data Length:", registration.extendedRegistrationData.length);
            if (registration.extendedRegistrationData.length > 0) {
                console.log("Extended Registration Data (hex):");
                console.logBytes(registration.extendedRegistrationData);
            }
            console.log("");

            // Log some parsed report body details
            console.log("=== Parsed Report Body ===");
            console.log("TEE TCB SVN:");
            console.logBytes16(registration.parsedReportBody.teeTcbSvn);
            console.log("MRSEAM:");
            console.logBytes(registration.parsedReportBody.mrSeam);
            console.log("MRSIGNERSEAM:");
            console.logBytes(registration.parsedReportBody.mrsignerSeam);
            console.log("SEAMATTRIBUTES:");
            console.logBytes8(registration.parsedReportBody.seamAttributes);
            console.log("TDATTRIBUTES:");
            console.logBytes8(registration.parsedReportBody.tdAttributes);
            console.log("XFAM:");
            console.logBytes8(registration.parsedReportBody.xFAM);
            console.log("MRTD:");
            console.logBytes(registration.parsedReportBody.mrTd);
            console.log("RTMR0:");
            console.logBytes(registration.parsedReportBody.rtMr0);
            console.log("RTMR1:");
            console.logBytes(registration.parsedReportBody.rtMr1);
            console.log("RTMR2:");
            console.logBytes(registration.parsedReportBody.rtMr2);
            console.log("RTMR3:");
            console.logBytes(registration.parsedReportBody.rtMr3);
            console.log("Report Data:");
            console.logBytes(registration.parsedReportBody.reportData);
        } else {
            console.log("TEE is not registered");
        }
    }
}

