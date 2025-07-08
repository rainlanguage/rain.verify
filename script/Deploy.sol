// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Script} from "forge-std/Script.sol";

import {Verify} from "src/concrete/Verify.sol";

bytes32 constant DEPLOYMENT_SUITE_IMPLEMENTATIONS = keccak256("implementations");

/// @title Deploy
/// This is intended to be run on every commit by CI to a testnet such as mumbai,
/// then cross chain deployed to whatever mainnet is required, by users.
contract Deploy is Script {
    function deployImplementations(uint256 deploymentKey) internal {
        vm.startBroadcast(deploymentKey);

        new Verify();

        vm.stopBroadcast();
    }

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYMENT_KEY");
        bytes32 suite = keccak256(bytes(vm.envString("DEPLOYMENT_SUITE")));

        if (suite == DEPLOYMENT_SUITE_IMPLEMENTATIONS) {
            deployImplementations(deployerPrivateKey);
        } else {
            revert("Unknown deployment suite");
        }
    }
}
