// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Evidence} from "rain-verify-interface-0.1.0/src/interface/IVerifyV1.sol";
import {IVerifyCallbackV1} from "rain-verify-interface-0.1.0/src/interface/IVerifyCallbackV1.sol";

/// @dev Tracks which callback hooks were called and with what arguments.
/// Implements `IVerifyCallbackV1` directly (no access control) so the Verify
/// contract can call it without ownership setup. Suitable only for testing.
contract MockCallback is IVerifyCallbackV1 {
    /// @dev Incremented each time `afterAdd` is called.
    uint256 public afterAddCalls;
    /// @dev Incremented each time `afterApprove` is called.
    uint256 public afterApproveCalls;
    /// @dev Incremented each time `afterBan` is called.
    uint256 public afterBanCalls;
    /// @dev Incremented each time `afterRemove` is called.
    uint256 public afterRemoveCalls;

    /// @dev The `adder` from the most recent `afterAdd` call.
    address public lastAddAdder;
    /// @dev The evidences from the most recent `afterAdd` call.
    Evidence[] public lastAddEvidences;

    /// @dev The `approver` from the most recent `afterApprove` call.
    address public lastApproveApprover;
    /// @dev The evidences from the most recent `afterApprove` call.
    Evidence[] public lastApproveEvidences;

    /// @dev The `banner` from the most recent `afterBan` call.
    address public lastBanBanner;
    /// @dev The evidences from the most recent `afterBan` call.
    Evidence[] public lastBanEvidences;

    /// @dev The `remover` from the most recent `afterRemove` call.
    address public lastRemoveRemover;
    /// @dev The evidences from the most recent `afterRemove` call.
    Evidence[] public lastRemoveEvidences;

    /// @inheritdoc IVerifyCallbackV1
    function afterAdd(address adder, Evidence[] calldata evidences) external override {
        afterAddCalls++;
        lastAddAdder = adder;
        delete lastAddEvidences;
        for (uint256 i = 0; i < evidences.length; i++) {
            lastAddEvidences.push(evidences[i]);
        }
    }

    /// @inheritdoc IVerifyCallbackV1
    function afterApprove(address approver, Evidence[] calldata evidences) external override {
        afterApproveCalls++;
        lastApproveApprover = approver;
        delete lastApproveEvidences;
        for (uint256 i = 0; i < evidences.length; i++) {
            lastApproveEvidences.push(evidences[i]);
        }
    }

    /// @inheritdoc IVerifyCallbackV1
    function afterBan(address banner, Evidence[] calldata evidences) external override {
        afterBanCalls++;
        lastBanBanner = banner;
        delete lastBanEvidences;
        for (uint256 i = 0; i < evidences.length; i++) {
            lastBanEvidences.push(evidences[i]);
        }
    }

    /// @inheritdoc IVerifyCallbackV1
    function afterRemove(address remover, Evidence[] calldata evidences) external override {
        afterRemoveCalls++;
        lastRemoveRemover = remover;
        delete lastRemoveEvidences;
        for (uint256 i = 0; i < evidences.length; i++) {
            lastRemoveEvidences.push(evidences[i]);
        }
    }

    /// @dev Returns the number of evidences stored from the last `afterAdd`.
    function lastAddEvidencesLength() external view returns (uint256) {
        return lastAddEvidences.length;
    }

    /// @dev Returns the number of evidences stored from the last `afterApprove`.
    function lastApproveEvidencesLength() external view returns (uint256) {
        return lastApproveEvidences.length;
    }

    /// @dev Returns the number of evidences stored from the last `afterBan`.
    function lastBanEvidencesLength() external view returns (uint256) {
        return lastBanEvidences.length;
    }

    /// @dev Returns the number of evidences stored from the last `afterRemove`.
    function lastRemoveEvidencesLength() external view returns (uint256) {
        return lastRemoveEvidences.length;
    }
}
