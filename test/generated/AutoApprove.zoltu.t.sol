// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
import {LibRainDeploy} from "rain.deploy/lib/LibRainDeploy.sol";
import {AutoApprove} from "../../src/concrete/AutoApprove.sol";
import {
    DEPLOYED_ADDRESS as AUTO_APPROVE_DEPLOYED_ADDRESS,
    BYTECODE_HASH as AUTO_APPROVE_BYTECODE_HASH
} from "../../src/generated/AutoApprove.pointers.sol";

/// @title AutoApproveZoltuTest
/// @notice Verifies that the Zoltu deterministic deploy constants in
/// AutoApprove.pointers.sol match the actual deployment output.
contract AutoApproveZoltuTest is Test {
    /// The deployed address from the Zoltu factory MUST match the precommitted
    /// constant in AutoApprove.pointers.sol.
    function testAutoApproveZoltuAddress() external {
        LibRainDeploy.etchZoltuFactory(vm);
        address deployed = LibRainDeploy.deployZoltu(type(AutoApprove).creationCode);
        assertEq(deployed, AUTO_APPROVE_DEPLOYED_ADDRESS);
    }

    /// The bytecode hash of the deployed contract MUST match the precommitted
    /// constant in AutoApprove.pointers.sol.
    function testAutoApproveZoltuBytecodeHash() external {
        LibRainDeploy.etchZoltuFactory(vm);
        address deployed = LibRainDeploy.deployZoltu(type(AutoApprove).creationCode);
        assertEq(deployed.codehash, AUTO_APPROVE_BYTECODE_HASH);
    }
}
