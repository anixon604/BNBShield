// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title PEPAttestationContract
 * @notice This contract manages multi‐party attestation for AML records in two distinct phases.
 *
 * Phase 1: Attestation
 * --------------------
 * - A new PEP record is minted in the Pending state.
 * - Both the submitter and the agent must sign the attestation payload off-chain.
 * - Their EIP‑712 compliant signatures are verified on-chain.
 * - If both signatures are valid, the record’s state is updated from Pending to Attested.
 *
 * The Attested state indicates that both parties have confirmed the record details.
 *
 * Phase 2: Finalization
 * ---------------------
 * - After attestation, a trusted authority (the contract owner) reviews the attested record.
 * - The owner finalizes the record by setting its outcome to either:
 *     • Reward: indicating a positive outcome, or
 *     • Slash: indicating a negative outcome.
 *
 * Note: Although the finalization function is named `submitChallenge`, it serves to finalize the record.
 * Future smart contract reward systems will leverage this functionality.
 */
contract PEPAttestationContract {
    enum PEPStatus {
        Pending,    // Record is created and waiting for attestations.
        Attested,   // Both the submitter and agent have attested (signed) the record.
        Reward,     // Final outcome: positive result (record is rewarded).
        Slash       // Final outcome: negative result (record is penalized/slashed).
    }

    // Data stored on-chain for each PEP record.
    struct PEPRecord {
        uint256 id;
        string pointer;
        PEPStatus status;
    }

    // Mapping from record id to PEPRecord.
    mapping(uint256 => PEPRecord) public pepRecords;
    uint256 public nextId;

    // Owner of the contract (authorized to finalize records).
    address public owner;

    // ===============================================================
    // EIP-712 Domain Separator and Type Hash for PEPAttestation
    // ===============================================================
    bytes32 public DOMAIN_SEPARATOR;
    string public constant NAME = "PEPAttestationContract";
    string public constant VERSION = "1";

    // The attestation struct that both the submitter and agent must sign.
    // It includes the record id, addresses of both parties, a hash of the off-chain pointer,
    // and a nonce for replay protection.
    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "PEPAttestation(uint256 id,address submitter,address agent,bytes32 pointer,uint256 nonce)"
    );

    // ===============================================================
    // Events
    // ===============================================================
    event PEPRecordMinted(uint256 indexed id, string pointer);
    event RecordAttested(uint256 indexed id);
    event ChallengeSubmitted(uint256 indexed id, PEPStatus outcome);

    // ===============================================================
    // Modifiers
    // ===============================================================
    modifier onlyOwner() {
        require(msg.sender == owner, "PEPAttestationContract: Not authorized");
        _;
    }

    // ===============================================================
    // Constructor
    // ===============================================================
    constructor() {
        owner = msg.sender;
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                chainId,
                address(this)
            )
        );
    }

    // ===============================================================
    // Phase 1: Record Creation
    // ===============================================================
    /**
     * @notice Mint a new PEP record with a pointer to off-chain details.
     * @param pointer The pointer to the off-chain record details (e.g., an IPFS or Greenfield URI).
     * @return id The unique identifier for the minted record.
     *
     * The record is created in the Pending state, indicating that it is awaiting attestation.
     */
    function mintPEPRecord(string calldata pointer) external returns (uint256 id) {
        id = nextId;
        pepRecords[id] = PEPRecord({
            id: id,
            pointer: pointer,
            status: PEPStatus.Pending
        });
        nextId++;
        emit PEPRecordMinted(id, pointer);
    }

    // ===============================================================
    // Phase 1: Attestation
    // ===============================================================
    /**
     * @notice Attest to a PEP record by providing valid EIP‑712 signatures from both parties.
     * @param id The unique identifier of the PEP record.
     * @param submitter The address of the submitter (as specified in the attestation payload).
     * @param agent The address of the agent (as specified in the attestation payload).
     * @param pointer The off-chain pointer; it must match the stored pointer.
     * @param nonce A nonce value for replay protection.
     * @param signatureSubmitter The submitter's EIP‑712 signature.
     * @param signatureAgent The agent's EIP‑712 signature.
     *
     * When both signatures are successfully verified, the record’s status is updated from Pending to Attested.
     * The Attested state confirms that both the submitter and agent have validated the record details.
     */
    function attestRecord(
        uint256 id,
        address submitter,
        address agent,
        string calldata pointer,
        uint256 nonce,
        bytes calldata signatureSubmitter,
        bytes calldata signatureAgent
    ) external {
        // Ensure the record exists and is in the Pending state.
        require(pepRecords[id].id == id, "PEPAttestationContract: Record does not exist");
        require(pepRecords[id].status == PEPStatus.Pending, "PEPAttestationContract: Already attested or finalized");

        // Verify that the attestation pointer matches the stored pointer.
        require(
            keccak256(bytes(pepRecords[id].pointer)) == keccak256(bytes(pointer)),
            "PEPAttestationContract: Pointer mismatch"
        );

        // Compute the struct hash for the attestation payload.
        bytes32 structHash = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                id,
                submitter,
                agent,
                keccak256(bytes(pointer)),
                nonce
            )
        );

        // Compute the EIP‑712 digest.
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        // Verify the submitter's and agent's signatures.
        require(
            _recoverSigner(digest, signatureSubmitter) == submitter,
            "PEPAttestationContract: Invalid submitter signature"
        );
        require(
            _recoverSigner(digest, signatureAgent) == agent,
            "PEPAttestationContract: Invalid agent signature"
        );

        // Both signatures are valid: update the record status to Attested.
        pepRecords[id].status = PEPStatus.Attested;
        emit RecordAttested(id);
    }

    // ===============================================================
    // Phase 2: Finalization (Challenge Outcome)
    // ===============================================================
    /**
     * @notice Finalize a record’s outcome after attestation.
     * @param id The unique identifier of the PEP record.
     * @param outcome The final outcome, which must be either Reward (positive) or Slash (negative).
     *
     * After a record is attested (i.e., both parties have validated it), a trusted authority (the owner)
     * reviews and finalizes the record by setting its outcome to Reward or Slash.
     * Although this function is named `submitChallenge`, it represents the finalization step.
     */
    function submitChallenge(uint256 id, PEPStatus outcome) external onlyOwner {
        require(
            outcome == PEPStatus.Reward || outcome == PEPStatus.Slash,
            "PEPAttestationContract: Outcome must be Reward or Slash"
        );
        require(pepRecords[id].id == id, "PEPAttestationContract: Record does not exist");
        require(pepRecords[id].status == PEPStatus.Attested, "PEPAttestationContract: Record not attested");

        // Finalize the record by updating its status to the provided outcome.
        pepRecords[id].status = outcome;
        emit ChallengeSubmitted(id, outcome);
    }

    // ===============================================================
    // Internal Helper: Signature Recovery
    // ===============================================================
    /**
     * @notice Recover the signer of an EIP‑712 digest.
     * @param digest The EIP‑712 digest.
     * @param signature The signature bytes (65 bytes: r, s, v).
     * @return The address that signed the digest.
     */
    function _recoverSigner(bytes32 digest, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "PEPAttestationContract: Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        // Extract r, s, and v from the signature.
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        return ecrecover(digest, v, r, s);
    }
}