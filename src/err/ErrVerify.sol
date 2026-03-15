// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.25;

/// @dev Thrown when Verify is initialised with a zero address for admin.
error ZeroAdmin();

/// @dev Thrown when msg.sender is not approved at the current timestamp.
error NotApproved();

/// @dev Thrown when an account already exists in the system and is being added.
error AlreadyExists();

/// @dev Thrown when a NIL account attempts an action that requires the account
/// to have been previously added to the system.
error UnknownAccount();
