// SPDX-License-Identifier: CAL
pragma solidity =0.8.25;

import {IVerifyV1, VerifyStatus, VERIFY_STATUS_APPROVED} from "src/interface/IVerifyV1.sol";

/// @title VerifyAlwaysApproved
/// @notice A concrete implementation of `IVerifyV1` that always returns
/// `VERIFY_STATUS_APPROVED` for any account at any timestamp. This can generally
/// be used as a "no-op" verifier that approves all accounts without any
/// conditions or checks.
contract VerifyAlwaysApproved is IVerifyV1 {
    /// @notice Always returns `VERIFY_STATUS_APPROVED` for any account.
    /// @param account The account to check the status of.
    /// @param timestamp The timestamp to check the status at.
    /// @return The status of the account at the given timestamp.
    function accountStatusAtTime(address account, uint256 timestamp) external pure override returns (VerifyStatus) {
        return VERIFY_STATUS_APPROVED;
    }
}
