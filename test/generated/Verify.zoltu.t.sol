// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
import {LibRainDeploy} from "rain.deploy/lib/LibRainDeploy.sol";
import {Verify} from "../../src/concrete/Verify.sol";
import {
    DEPLOYED_ADDRESS as VERIFY_DEPLOYED_ADDRESS,
    BYTECODE_HASH as VERIFY_BYTECODE_HASH
} from "../../src/generated/Verify.pointers.sol";

/// @title VerifyZoltuTest
/// @notice Verifies that the Zoltu deterministic deploy constants in
/// Verify.pointers.sol match the actual deployment output.
contract VerifyZoltuTest is Test {
    /// The deployed address from the Zoltu factory MUST match the precommitted
    /// constant in Verify.pointers.sol.
    function testVerifyZoltuAddress() external {
        LibRainDeploy.etchZoltuFactory(vm);
        address deployed = LibRainDeploy.deployZoltu(type(Verify).creationCode);
        assertEq(deployed, VERIFY_DEPLOYED_ADDRESS);
    }

    /// The bytecode hash of the deployed contract MUST match the precommitted
    /// constant in Verify.pointers.sol.
    function testVerifyZoltuBytecodeHash() external {
        LibRainDeploy.etchZoltuFactory(vm);
        address deployed = LibRainDeploy.deployZoltu(type(Verify).creationCode);
        assertEq(deployed.codehash, VERIFY_BYTECODE_HASH);
    }
}
