//SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

import {SNARK_SCALAR_FIELD} from "./CredentialConstants.sol";
import "../interfaces/ICredentialCreds.sol";
import "@zk-kit/incremental-merkle-tree.sol/IncrementalBinaryTree.sol";
import "@openzeppelin/contracts/utils/Context.sol";

/// @title Credential Creds contract.
/// @dev The following code allows you to create Creds, add and remove members.
/// You can use getters to obtain informations about Creds (root, depth, number of leaves).
abstract contract CredentialCreds is Context, ICredentialCreds {
    using IncrementalBinaryTree for IncrementalTreeData;

    /// @dev Gets a Cred id and returns the tree data.
    mapping(uint256 => IncrementalTreeData) internal merkleTree;

    /// @dev Creates a new Cred by initializing the associated tree.
    /// @param credId: Id of the Cred.
    /// @param merkleTreeDepth: Depth of the tree.
    /// @param zeroValue: Zero value of the tree.
    function _createCred(
        uint256 credId,
        uint256 merkleTreeDepth,
        uint256 zeroValue
    ) internal virtual {
        if (credId >= SNARK_SCALAR_FIELD) {
            revert Credential__CredIdIsNotLessThanSnarkScalarField();
        }

        if (getMerkleTreeDepth(credId) != 0) {
            revert Credential__CredAlreadyExists();
        }

        merkleTree[credId].init(merkleTreeDepth, zeroValue);

        emit CredCreated(credId, merkleTreeDepth, zeroValue);
    }

    /// @dev Adds an identity commitment to an existing Cred.
    /// @param credId: Id of the Cred.
    /// @param identityCommitment: New identity commitment.
    function _addMember(uint256 credId, uint256 identityCommitment) internal virtual {
        if (getMerkleTreeDepth(credId) == 0) {
            revert Credential__CredDoesNotExist();
        }

        merkleTree[credId].insert(identityCommitment);

        uint256 merkleTreeRoot = getMerkleTreeRoot(credId);
        uint256 index = getNumberOfMerkleTreeLeaves(credId) - 1;

        emit MemberAdded(credId, index, identityCommitment, merkleTreeRoot);
    }

    /// @dev Updates an identity commitment of an existing Cred. A proof of membership is
    /// needed to check if the node to be updated is part of the tree.
    /// @param credId: Id of the Cred.
    /// @param identityCommitment: Existing identity commitment to be updated.
    /// @param newIdentityCommitment: New identity commitment.
    /// @param proofSiblings: Array of the sibling nodes of the proof of membership.
    /// @param proofPathIndices: Path of the proof of membership.
    function _updateMember(
        uint256 credId,
        uint256 identityCommitment,
        uint256 newIdentityCommitment,
        uint256[] calldata proofSiblings,
        uint8[] calldata proofPathIndices
    ) internal virtual {
        if (getMerkleTreeRoot(credId) == 0) {
            revert Credential__CredDoesNotExist();
        }

        merkleTree[credId].update(identityCommitment, newIdentityCommitment, proofSiblings, proofPathIndices);

        uint256 merkleTreeRoot = getMerkleTreeRoot(credId);
        uint256 index = proofPathIndicesToMemberIndex(proofPathIndices);

        emit MemberUpdated(credId, index, identityCommitment, newIdentityCommitment, merkleTreeRoot);
    }

    /// @dev Removes an identity commitment from an existing Cred. A proof of membership is
    /// needed to check if the node to be deleted is part of the tree.
    /// @param credId: Id of the Cred.
    /// @param identityCommitment: Existing identity commitment to be removed.
    /// @param proofSiblings: Array of the sibling nodes of the proof of membership.
    /// @param proofPathIndices: Path of the proof of membership.
    function _removeMember(
        uint256 credId,
        uint256 identityCommitment,
        uint256[] calldata proofSiblings,
        uint8[] calldata proofPathIndices
    ) internal virtual {
        if (getMerkleTreeRoot(credId) == 0) {
            revert Credential__CredDoesNotExist();
        }

        merkleTree[credId].remove(identityCommitment, proofSiblings, proofPathIndices);

        uint256 merkleTreeRoot = getMerkleTreeRoot(credId);
        uint256 index = proofPathIndicesToMemberIndex(proofPathIndices);

        emit MemberRemoved(credId, index, identityCommitment, merkleTreeRoot);
    }

    /// @dev See {ICredentialCreds-getMerkleTreeRoot}.
    function getMerkleTreeRoot(uint256 credId) public view virtual override returns (uint256) {
        return merkleTree[credId].root;
    }

    /// @dev See {ICredentialCreds-getMerkleTreeDepth}.
    function getMerkleTreeDepth(uint256 credId) public view virtual override returns (uint256) {
        return merkleTree[credId].depth;
    }

    /// @dev See {ICredentialCreds-getNumberOfMerkleTreeLeaves}.
    function getNumberOfMerkleTreeLeaves(uint256 credId) public view virtual override returns (uint256) {
        return merkleTree[credId].numberOfLeaves;
    }

    /// @dev Converts the path indices of a Merkle proof to the identity commitment index in the tree.
    /// @param proofPathIndices: Path of the proof of membership.
    /// @return Index of a Cred member.
    function proofPathIndicesToMemberIndex(uint8[] calldata proofPathIndices) private pure returns (uint256) {
        uint256 memberIndex = 0;

        for (uint8 i = uint8(proofPathIndices.length); i > 0; ) {
            if (memberIndex > 0 || proofPathIndices[i - 1] != 0) {
                memberIndex *= 2;

                if (proofPathIndices[i - 1] == 1) {
                    memberIndex += 1;
                }
            }

            unchecked {
                --i;
            }
        }

        return memberIndex;
    }
}
