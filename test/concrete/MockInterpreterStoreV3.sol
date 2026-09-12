// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {IInterpreterStoreV3} from "rainlang-interface-0.2.8/src/interface/IInterpreterStoreV3.sol";
import {
    StateNamespace,
    FullyQualifiedNamespace
} from "rainlang-interface-0.2.8/src/interface/deprecated/v2/IInterpreterV3.sol";

/// @dev Mock store that implements all required functions of
/// `IInterpreterStoreV3` as no-ops.
contract MockInterpreterStoreV3 is IInterpreterStoreV3 {
    /// @inheritdoc IInterpreterStoreV3
    function set(StateNamespace, bytes32[] calldata) external override {}

    /// @inheritdoc IInterpreterStoreV3
    function get(FullyQualifiedNamespace, bytes32) external pure override returns (bytes32) {
        return bytes32(0);
    }
}
