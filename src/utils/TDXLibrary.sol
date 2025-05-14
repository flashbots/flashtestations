// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

library TDXLibrary {
    /**
     * @dev Represents the header of a TDX Quote containing version and attestation key information
     * @dev TODO: fill these in with the correct values
     */
    struct QuoteHeader {
        uint256 field1;
        uint256 field2;
        uint256 field3;
        uint256 field4;
    }

    /**
     * @dev Represents a TDX Report containing measurement registers and user-defined data
     */
    struct TDReport {
        bytes mrTd; // Measurement register for TD (initial code/data) 48 bytes
        bytes[4] rTMRs; // Runtime measurement registers 48 bytes each
        bytes mrOwner; // Measurement register for owner (policy) 48 bytes
        bytes mrConfigId; // Configuration ID 48 bytes
        bytes mrConfigOwner; // Owner-defined configuration 48 bytes
        bytes32[2] ReportData; // User-defined data (public key hash)
    }

    /**
     * @dev Represents a TDX Quote containing the TDReport, product information, and signature
     */
    struct TDXQuote {
        QuoteHeader Header; // Version and attestation key type info
        TDReport TDReport; // TD measurement registers
        uint16 TEEExtendedProductID; // TEE product identifier
        uint16 TEESecurityVersion; // Security patch level
        uint16 QESecurityVersion; // Quoting Enclave security version
        bytes16 QEVendorID; // Intel Quoting Enclave vendor ID
        bytes32[2] UserData; // User-defined report data (public key hash)
        bytes Signature; // ECDSA signature over the Quote
    }

    struct DCAPEvent {
        uint32 Index;
        uint32 EventType;
        bytes32 Digest;
        bytes EventPayload;
    }

    struct MAAReport {
        bytes32[24] PCRs;
    }
}
