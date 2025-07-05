// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.25;

type VerifyStatus is uint256;

/// @dev Account has not interacted with the system yet or was removed.
VerifyStatus constant VERIFY_STATUS_NIL = VerifyStatus.wrap(0);
/// @dev Account has added evidence for themselves.
VerifyStatus constant VERIFY_STATUS_ADDED = VerifyStatus.wrap(1);
/// @dev Approver has reviewed added/approve evidence and approved the account.
VerifyStatus constant VERIFY_STATUS_APPROVED = VerifyStatus.wrap(2);
/// @dev Banner has reviewed a request to ban an account and banned it.
VerifyStatus constant VERIFY_STATUS_BANNED = VerifyStatus.wrap(3);

/// Structure of arbitrary evidence to support any action taken.
/// Privileged roles are expected to provide evidence just as applicants as an
/// audit trail will be preserved permanently in the logs.
/// @param account The account this evidence is relevant to.
/// @param data Arbitrary bytes representing evidence. MAY be e.g. a reference
/// to a sufficiently decentralised external system such as an IPFS hash.
struct Evidence {
    address account;
    bytes data;
}

interface IVerifyV1 {
    function accountStatusAtTime(address account, uint256 timestamp) external view returns (VerifyStatus);
}
