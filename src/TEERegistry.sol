// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "solmate/src/utils/TransientReentrancyGuard.sol";
import "solmate/src/auth/Owned.sol";

struct DCAPEvent {
	uint32 Index;
	uint32 EventType;
	bytes EventPayload;
	bytes32 Digest;
}

struct DCAPReport {
    // All fields are expected to be 48 bytes
	bytes mrTd;          // Measurement register for TD
	bytes[4] RTMRs;      // Runtime measurement registers
	bytes mrOwner;       // Measurement register for owner
	bytes mrConfigId;    // Measurement register for config ID
	bytes mrConfigOwner; // Measurement register for config owner
}

struct MAAReport {
	bytes32[24] PCRs;
}

struct AppPKI {
	bytes ca;
	bytes pubkey;
	bytes attestation;
}

/**
 * @title TEERegistry
 * @dev A contract for managing trusted execution environment (TEE) identities and configurations
 * using Intel DCAP attestation.
 */
contract TEERegistry is Owned, TransientReentrancyGuard {
    // Maximum size for byte arrays to prevent DoS attacks
    uint256 public constant MAX_BYTES_SIZE = 20 * 1024; // 20KB limit

    // State variables
    string[] public instanceDomainNames;
	AppPKI public app_pki;

	// Notes config and secrets locations
	string[] public storageBackends;
    // Maps config hash to config data and secrets for onchain DA
    mapping(bytes32 => bytes) public artifacts;
    // Maps identity to config hash
    mapping(bytes32 => bytes32) public identityConfigMap;

    // Events
    event InstanceDomainRegistered(string domain, address registrar);
	event StorageBackendSet(string location, address setter);
	event StorageBackendRemoved(string location, address remover);
    event ArtifactAdded(bytes32 configHash, address adder);
    event PKIUpdated(address updater, AppPKI pki);
    event IdentityConfigSet(bytes32 identity, bytes32 configHash, address setter);

    error ByteSizeExceeded(uint256 size);
    
    /**
     * @dev Constructor to set up initial owner and roles
     */
    constructor(address initialOwner) Owned(initialOwner) {
        // TODO setup roles with solmate auth
    }

     /**
     * @dev Modifier to check if input bytes size is within limits
     */
    modifier limitBytesSize(bytes memory data) {
        require(data.length <= MAX_BYTES_SIZE, ByteSizeExceeded(data.length));
        _;
    }

    /**
     * @dev Set PKI and its attestation
     * @param pki The PKI (certificate authority, encryption pubkey, kms attestation)
     */
    function setPKI(AppPKI memory pki)
        public 
        onlyOwner 
        limitBytesSize(pki.ca)
        limitBytesSize(pki.pubkey)
        limitBytesSize(pki.attestation)
    {
		app_pki = pki;
        emit PKIUpdated(msg.sender, pki);
    }

    function getPKI() external view returns (AppPKI memory) {
		return app_pki;
	}

}
