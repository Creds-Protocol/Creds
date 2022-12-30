// SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

import "./interfaces/ICredential.sol";
import "./interfaces/IVerifier.sol";
import "./base/CredentialCore.sol";
import "./base/CredentialCreds.sol";

/// @title Credential
contract Credential is ICredential, CredentialCore, CredentialCreds {

    /// Credential name
    string private _name;

    /// Credential symbol
    string private _symbol;

    /// @dev Gets a tree depth and returns its verifier address.
    mapping(uint256 => IVerifier) public verifiers;

    /// @dev Gets a credential id and returns the cred parameters.
    mapping(uint256 => Cred) public creds;

    /// @dev Gets a credential
    /// @dev Checks if the cred admin is the transaction sender.
    /// @param credId: Id of the cred.
    modifier onlyCredAdmin(uint256 credId) {
        if (creds[credId].admin != _msgSender()) {
            revert Credential__CallerIsNotTheCredAdmin();
        }
        _;
    }

    /// @dev Checks if there is a verifier for the given tree depth.
    /// @param merkleTreeDepth: Depth of the tree.
    modifier onlySupportedMerkleTreeDepth(uint256 merkleTreeDepth) {
        if (address(verifiers[merkleTreeDepth]) == address(0)) {
            revert Credential__MerkleTreeDepthIsNotSupported();
        }
        _;
    }

    /// @dev Initializes the Credential verifiers used to verify the user's ZK proofs.
    /// @param _verifiers: List of Credential verifiers (address and related Merkle tree depth).
    constructor(string memory name_, string memory symbol_, Verifier[] memory _verifiers) {
        for (uint8 i = 0; i < _verifiers.length; ) {
            verifiers[_verifiers[i].merkleTreeDepth] = IVerifier(_verifiers[i].contractAddress);

            unchecked {
                ++i;
            }
        }
        _name = name_;
        _symbol = symbol_;
    }

    /// @dev See {ICredential-name}.
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /// @dev See {ICredential-symbol}.
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /// @dev Creates a new cred. Only the admin will be able to add or remove members.
    /// @param credId: Id of the cred.
    /// @param merkleTreeDepth: Depth of the tree.
    /// @param zeroValue: Zero value of the tree.
    /// @param admin: Admin of the cred.
    /// @param credURI: URI for the cred.
    function createCred(
        uint256 credId,
        uint256 merkleTreeDepth,
        uint256 zeroValue,
        address admin,
        string memory credURI
    ) internal onlySupportedMerkleTreeDepth(merkleTreeDepth) {
        _createCred(credId, merkleTreeDepth, zeroValue);

        creds[credId].admin = admin;
        creds[credId].credURI = credURI;
        creds[credId].merkleRootDuration = 1 hours;

        emit credAdminUpdated(credId, address(0), admin);
    }

    /// @dev Creates a new cred. Only the admin will be able to add or remove members.
    /// @param credId: Id of the cred.
    /// @param merkleTreeDepth: Depth of the tree.
    /// @param zeroValue: Zero value of the tree.
    /// @param admin: Admin of the cred.
    /// @param credURI: URI for the cred.
    /// @param merkleTreeRootDuration: Time before the validity of a root expires.
    function createCred(
        uint256 credId,
        uint256 merkleTreeDepth,
        uint256 zeroValue,
        address admin,
        string memory credURI,
        uint256 merkleTreeRootDuration
    ) internal onlySupportedMerkleTreeDepth(merkleTreeDepth) {
        _createCred(credId, merkleTreeDepth, zeroValue);

        creds[credId].admin = admin;
        creds[credId].credURI = credURI;
        creds[credId].merkleRootDuration = merkleTreeRootDuration;

        emit credAdminUpdated(credId, address(0), admin);
    }

    /// @dev Updates the cred admin.
    /// @param credId: Id of the cred.
    /// @param newAdmin: New admin of the cred.
    function updateCredAdmin(uint256 credId, address newAdmin) internal onlyCredAdmin(credId) {
        creds[credId].admin = newAdmin;

        emit credAdminUpdated(credId, _msgSender(), newAdmin);
    }

    /// @dev Adds a new member to an existing cred.
    /// @param credId: Id of the cred.
    /// @param identityCommitment: New identity commitment.
    function addMember(uint256 credId, uint256 identityCommitment) internal {
        _addMember(credId, identityCommitment);

        uint256 merkleTreeRoot = getMerkleTreeRoot(credId);

        creds[credId].merkleRootCreationDates[merkleTreeRoot] = block.timestamp;
    }

    /// @dev Adds new members to an existing cred.
    /// @param credId: Id of the cred.
    /// @param identityCommitments: New identity commitments.
    function addMembers(uint256 credId, uint256[] calldata identityCommitments) internal {
        for (uint8 i = 0; i < identityCommitments.length; ) {
            _addMember(credId, identityCommitments[i]);

            unchecked {
                ++i;
            }
        }

        uint256 merkleTreeRoot = getMerkleTreeRoot(credId);

        creds[credId].merkleRootCreationDates[merkleTreeRoot] = block.timestamp;
    }

    /// @dev Updates an identity commitment of an existing cred. A proof of membership is
    /// needed to check if the node to be updated is part of the tree.
    /// @param credId: Id of the cred.
    /// @param identityCommitment: Existing identity commitment to be updated.
    /// @param newIdentityCommitment: New identity commitment.
    /// @param proofSiblings: Array of the sibling nodes of the proof of membership.
    /// @param proofPathIndices: Path of the proof of membership.
    function updateMember(
        uint256 credId,
        uint256 identityCommitment,
        uint256 newIdentityCommitment,
        uint256[] calldata proofSiblings,
        uint8[] calldata proofPathIndices
    ) internal {
        _updateMember(credId, identityCommitment, newIdentityCommitment, proofSiblings, proofPathIndices);
    }

    /// @dev Removes a member from an existing cred. A proof of membership is
    /// needed to check if the node to be removed is part of the tree.
    /// @param credId: Id of the cred.
    /// @param identityCommitment: Identity commitment to be removed.
    /// @param proofSiblings: Array of the sibling nodes of the proof of membership.
    /// @param proofPathIndices: Path of the proof of membership.
    function removeMember(
        uint256 credId,
        uint256 identityCommitment,
        uint256[] calldata proofSiblings,
        uint8[] calldata proofPathIndices
    ) internal {
        _removeMember(credId, identityCommitment, proofSiblings, proofPathIndices);
    }

    /// @dev See {ICredential-verifyProof}.
    function verifyProof(
        uint256 credId,
        uint256 merkleTreeRoot,
        bytes32 signal,
        uint256 nullifierHash,
        uint256 externalNullifier,
        uint256[8] calldata proof
    ) external override {
        uint256 currentMerkleTreeRoot = getMerkleTreeRoot(credId);

        if (currentMerkleTreeRoot == 0) {
            revert Credential__CredDoesNotExist();
        }

        if (merkleTreeRoot != currentMerkleTreeRoot) {
            uint256 merkleRootCreationDate = creds[credId].merkleRootCreationDates[merkleTreeRoot];
            uint256 merkleRootDuration = creds[credId].merkleRootDuration;

            if (merkleRootCreationDate == 0) {
                revert Credential__MerkleTreeRootIsNotPartOfTheCred();
            }

            if (block.timestamp > merkleRootCreationDate + merkleRootDuration) {
                revert Credential__MerkleTreeRootIsExpired();
            }
        }

        if (creds[credId].nullifierHashes[nullifierHash]) {
            revert Credential__YouAreUsingTheSameNillifierTwice();
        }

        uint256 merkleTreeDepth = getMerkleTreeDepth(credId);

        IVerifier verifier = verifiers[merkleTreeDepth];

        _verifyProof(signal, merkleTreeRoot, nullifierHash, externalNullifier, proof, verifier);

        creds[credId].nullifierHashes[nullifierHash] = true;

        emit ProofVerified(credId, merkleTreeRoot, nullifierHash, externalNullifier, signal);
    }
}
