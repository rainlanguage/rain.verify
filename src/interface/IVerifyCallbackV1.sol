// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.25;

import {Evidence} from "./IVerifyV1.sol";

/// Deployers of `Verify` contracts (e.g. via `VerifyFactory`) may want to
/// apply additional processing and/or restrictions to each of the basic
/// verification actions. Examples may be reading from onchain state or
/// requiring token transfers to complete before allowing an add/approve to
/// complete successfully. The reason this is an interface rather than
/// implementors extending `Verify` directly is that it allows for more
/// implementations to sit under a single `VerifyFactory` which in turn allows
/// a more readily composed ecosystem of verified accounts.
///
/// There's no reentrancy concerns for external calls from the `Verify`
/// contract to the `IVerifyCallbackV1` contract because:
/// - All the callbacks happen after state changes in `Verify`
/// - All `Verify` actions are bound to the authority of the `msg.sender`
/// The `IVerifyCallbackV1` contract can and should rollback transactions if
/// their restrictions/processing requirements are not met, but otherwise have
/// no more authority over the `Verify` state than anon users.
///
/// The security model for platforms consuming `Verify` contracts is that they
/// should index or otherwise filter children from the `VerifyFactory` down to
/// those that also set a supported `IVerifyCallbackV1` contract. The factory is
/// completely agnostic to callback concerns and doesn't even require that a
/// callback contract be set at all.
interface IVerifyCallbackV1 {
    /// Additional processing after a batch of additions.
    /// SHOULD revert/rollback transactions if processing fails.
    /// @param adder The `msg.sender` that authorized the additions.
    /// MAY be the addee without any specific role.
    /// @param evidences All evidences associated with the additions.
    function afterAdd(address adder, Evidence[] calldata evidences) external;

    /// Additional processing after a batch of approvals.
    /// SHOULD revert/rollback transactions if processing fails.
    /// @param approver The `msg.sender` that authorized the approvals.
    /// @param evidences All evidences associated with the approvals.
    function afterApprove(address approver, Evidence[] calldata evidences) external;

    /// Additional processing after a batch of bannings.
    /// SHOULD revert/rollback transactions if processing fails.
    /// @param banner The `msg.sender` that authorized the bannings.
    /// @param evidences All evidences associated with the bannings.
    function afterBan(address banner, Evidence[] calldata evidences) external;

    /// Additional processing after a batch of removals.
    /// SHOULD revert/rollback transactions if processing fails.
    /// @param remover The `msg.sender` that authorized the removals.
    /// @param evidences All evidences associated with the removals.
    function afterRemove(address remover, Evidence[] calldata evidences) external;
}
