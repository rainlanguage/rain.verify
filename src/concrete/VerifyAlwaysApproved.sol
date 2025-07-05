// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {IVerifyV1, VerifyStatus, VERIFY_STATUS_APPROVED} from "src/interface/IVerifyV1.sol";

/// @title VerifyAlwaysApproved
/// @notice A concrete implementation of `IVerifyV1` that always returns
/// `VERIFY_STATUS_APPROVED` for any account at any timestamp. This can generally
/// be used as a "no-op" verifier that approves all accounts without any
/// conditions or checks.
contract VerifyAlwaysApproved is IVerifyV1 {
    /// Always returns `VERIFY_STATUS_APPROVED` for any account.
    /// @inheritdoc IVerifyV1
    function accountStatusAtTime(address, uint256) external pure override returns (VerifyStatus) {
        return VERIFY_STATUS_APPROVED;
    }
}
