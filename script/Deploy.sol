// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Script} from "forge-std-1.16.2/src/Script.sol";
import {LibRainDeploy} from "rain-deploy-0.1.7/src/lib/LibRainDeploy.sol";
import {Verify} from "../src/concrete/Verify.sol";
import {AutoApprove} from "../src/concrete/AutoApprove.sol";
import {
    DEPLOYED_ADDRESS as VERIFY_DEPLOYED_ADDRESS,
    BYTECODE_HASH as VERIFY_BYTECODE_HASH
} from "../src/generated/Verify.sol";
import {
    DEPLOYED_ADDRESS as AUTO_APPROVE_DEPLOYED_ADDRESS,
    BYTECODE_HASH as AUTO_APPROVE_BYTECODE_HASH
} from "../src/generated/AutoApprove.sol";

bytes32 constant DEPLOYMENT_SUITE_VERIFY = keccak256("verify");
bytes32 constant DEPLOYMENT_SUITE_AUTO_APPROVE = keccak256("auto-approve");

/// @title Deploy
/// @notice Deterministic deployment of Verify and AutoApprove implementation
/// contracts via the Zoltu factory across all supported networks.
contract Deploy is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYMENT_KEY");
        bytes32 suite = keccak256(bytes(vm.envString("DEPLOYMENT_SUITE")));

        if (suite == DEPLOYMENT_SUITE_VERIFY) {
            LibRainDeploy.deployAndBroadcast(
                vm,
                LibRainDeploy.supportedNetworks(),
                deployerPrivateKey,
                type(Verify).creationCode,
                "src/concrete/Verify.sol:Verify",
                VERIFY_DEPLOYED_ADDRESS,
                VERIFY_BYTECODE_HASH,
                new address[](0)
            );
        } else if (suite == DEPLOYMENT_SUITE_AUTO_APPROVE) {
            LibRainDeploy.deployAndBroadcast(
                vm,
                LibRainDeploy.supportedNetworks(),
                deployerPrivateKey,
                type(AutoApprove).creationCode,
                "src/concrete/AutoApprove.sol:AutoApprove",
                AUTO_APPROVE_DEPLOYED_ADDRESS,
                AUTO_APPROVE_BYTECODE_HASH,
                new address[](0)
            );
        } else {
            revert("Unknown deployment suite");
        }
    }
}
