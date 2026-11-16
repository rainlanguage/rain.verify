// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {BuildScript, GeneratedContract} from "rain-deploy-0.1.33/src/abstract/BuildScript.sol";
import {DeployDeclaration} from "rain-deploy-0.1.33/src/abstract/RainDeploySuitesBase.sol";
import {VerifyDeploySuites} from "../src/abstract/VerifyDeploySuites.sol";
import {LibRainDeploySnapshot} from "rain-deploy-0.1.33/src/lib/LibRainDeploySnapshot.sol";

/// @title Build
/// @notice Generates the deploy pins for every contract this repo deploys.
/// `generatedContracts` is the only list, read by every hook below.
///
/// `run()` (what CI regenerates against) rewrites the rolling
/// `src/generated/candidate/` snapshot, the alias lib and the released-suites
/// libs. `cutRelease()` freezes the candidate into `src/generated/<tag>/`
/// first. Frozen snapshots are append-only historical records, never
/// regenerated here.
contract Build is BuildScript, VerifyDeploySuites {
    /// @inheritdoc BuildScript
    function generatedContracts(DeployDeclaration memory d)
        internal
        pure
        override
        returns (GeneratedContract[] memory)
    {
        GeneratedContract[] memory contracts = new GeneratedContract[](2);
        contracts[0] = GeneratedContract({
            contractName: "Verify", constantPrefix: "VERIFY", candidate: declaredCandidate(d, VERIFY_SUITE)
        });
        contracts[1] = GeneratedContract({
            contractName: "AutoApprove",
            constantPrefix: "AUTO_APPROVE",
            candidate: declaredCandidate(d, AUTO_APPROVE_SUITE)
        });
        return contracts;
    }

    /// @inheritdoc BuildScript
    function regenerateSnapshots() internal override {
        GeneratedContract[] memory contracts = generatedContracts(declaration());
        for (uint256 i = 0; i < contracts.length; i++) {
            LibRainDeploySnapshot.writeSnapshot(
                vm,
                recordRoot(),
                LibRainDeploySnapshot.CANDIDATE,
                contracts[i].contractName,
                vm.getCode(contracts[i].candidate.snapshot.artifactPath),
                contracts[i].candidate.snapshot.dependencies
            );
        }
    }
}
