//SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

/// @title CredentialsNullifiers interface.
/// @dev Interface of CredentialsNullifiers contract.
interface ICredentialsNullifiers {
    /// @dev Emitted when a external nullifier is added.
    /// @param externalNullifier: External Credentials nullifier.
    event ExternalNullifierAdded(uint256 externalNullifier);

    /// @dev Emitted when a external nullifier is removed.
    /// @param externalNullifier: External Credentials nullifier.
    event ExternalNullifierRemoved(uint256 externalNullifier);
}
