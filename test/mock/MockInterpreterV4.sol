// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {StackItem, EvalV4} from "rain-interpreter-interface-0.1.0/src/interface/IInterpreterV4.sol";

/// @dev Mock interpreter that returns a configurable stack value from `eval4`.
/// Does NOT inherit `IInterpreterV4` because the interface declares `calldata`
/// return types which cannot be produced from Solidity storage/memory. The ABI
/// encoding is identical so the caller (AutoApprove) can decode the response
/// through the interface pointer without issue.
contract MockInterpreterV4 {
    /// @dev The stack to return from `eval4`.
    StackItem[] public sStack;

    /// @dev Set the stack that `eval4` will return.
    function setStack(StackItem[] memory stack) external {
        delete sStack;
        for (uint256 i = 0; i < stack.length; i++) {
            sStack.push(stack[i]);
        }
    }

    /// @dev Convenience to set a single-element stack.
    function setReturnValue(StackItem value) external {
        delete sStack;
        sStack.push(value);
    }

    /// @dev Matches the `eval4` selector from `IInterpreterV4`.
    function eval4(EvalV4 calldata) external view returns (StackItem[] memory stack, bytes32[] memory kvs) {
        stack = sStack;
        kvs = new bytes32[](0);
    }
}
