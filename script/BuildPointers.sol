// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Script} from "forge-std-1.16.1/src/Script.sol";
import {LibRainDeploy} from "rain-deploy-0.1.2/src/lib/LibRainDeploy.sol";
import {LibCodeGen} from "rain-sol-codegen-0.1.0/src/lib/LibCodeGen.sol";
import {LibFs} from "rain-sol-codegen-0.1.0/src/lib/LibFs.sol";
import {Verify} from "../src/concrete/Verify.sol";
import {AutoApprove} from "../src/concrete/AutoApprove.sol";

/// @title BuildPointers
/// @notice Deploys Verify and AutoApprove via the Zoltu factory in a local
/// environment and generates `.pointers.sol` files with deterministic deploy
/// addresses and bytecode hashes.
contract BuildPointers is Script {
    function addressConstantString(address addr) internal pure returns (string memory) {
        return string.concat(
            "\n",
            "/// @dev The deterministic deploy address of the contract when deployed via\n",
            "/// the Zoltu factory.\n",
            "address constant DEPLOYED_ADDRESS = address(",
            vm.toString(addr),
            ");\n"
        );
    }

    function buildVerifyPointers() internal {
        address deployed = LibRainDeploy.deployZoltu(type(Verify).creationCode);

        LibFs.buildFileForContract(
            vm,
            deployed,
            "Verify",
            string.concat(
                addressConstantString(deployed),
                LibCodeGen.bytesConstantString(
                    vm, "/// @dev The creation bytecode of the contract.", "CREATION_CODE", type(Verify).creationCode
                )
            )
        );
    }

    function buildAutoApprovePointers() internal {
        address deployed = LibRainDeploy.deployZoltu(type(AutoApprove).creationCode);

        LibFs.buildFileForContract(
            vm,
            deployed,
            "AutoApprove",
            string.concat(
                addressConstantString(deployed),
                LibCodeGen.bytesConstantString(
                    vm,
                    "/// @dev The creation bytecode of the contract.",
                    "CREATION_CODE",
                    type(AutoApprove).creationCode
                )
            )
        );
    }

    function run() external {
        LibRainDeploy.etchZoltuFactory(vm);

        buildVerifyPointers();
        buildAutoApprovePointers();
    }
}
