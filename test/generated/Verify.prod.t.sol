// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
import {LibRainDeploy} from "rain.deploy/lib/LibRainDeploy.sol";
import {
    DEPLOYED_ADDRESS as VERIFY_DEPLOYED_ADDRESS,
    BYTECODE_HASH as VERIFY_BYTECODE_HASH
} from "../../src/generated/Verify.pointers.sol";
import {
    DEPLOYED_ADDRESS as AUTO_APPROVE_DEPLOYED_ADDRESS,
    BYTECODE_HASH as AUTO_APPROVE_BYTECODE_HASH
} from "../../src/generated/AutoApprove.pointers.sol";

/// @title VerifyProdDeployTest
/// @notice Forks each supported network and verifies that Verify and
/// AutoApprove are deployed at the expected addresses with the expected
/// codehash.
contract VerifyProdDeployTest is Test {
    function _checkAllContracts() internal view {
        assertTrue(VERIFY_DEPLOYED_ADDRESS.code.length > 0, "Verify not deployed");
        assertEq(VERIFY_DEPLOYED_ADDRESS.codehash, VERIFY_BYTECODE_HASH);

        assertTrue(AUTO_APPROVE_DEPLOYED_ADDRESS.code.length > 0, "AutoApprove not deployed");
        assertEq(AUTO_APPROVE_DEPLOYED_ADDRESS.codehash, AUTO_APPROVE_BYTECODE_HASH);
    }

    /// Both contracts MUST be deployed on Arbitrum.
    function testProdDeployArbitrum() external {
        vm.createSelectFork(LibRainDeploy.ARBITRUM_ONE);
        _checkAllContracts();
    }

    /// Both contracts MUST be deployed on Base.
    function testProdDeployBase() external {
        vm.createSelectFork(LibRainDeploy.BASE);
        _checkAllContracts();
    }

    /// Both contracts MUST be deployed on Base Sepolia.
    function testProdDeployBaseSepolia() external {
        vm.createSelectFork(LibRainDeploy.BASE_SEPOLIA);
        _checkAllContracts();
    }

    /// Both contracts MUST be deployed on Flare.
    function testProdDeployFlare() external {
        vm.createSelectFork(LibRainDeploy.FLARE);
        _checkAllContracts();
    }

    /// Both contracts MUST be deployed on Polygon.
    function testProdDeployPolygon() external {
        vm.createSelectFork(LibRainDeploy.POLYGON);
        _checkAllContracts();
    }
}
