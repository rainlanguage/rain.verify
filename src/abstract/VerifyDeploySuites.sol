// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.25;

import {
    DeployCandidate,
    DeployDependency,
    DeployMechanism,
    DeploySuite,
    RainDeploySuitesBase
} from "rain-deploy-0.1.22/src/abstract/RainDeploySuitesBase.sol";
import {
    CREATION_CODE as VERIFY_CREATION_CODE_CANDIDATE,
    RUNTIME_CODE as VERIFY_RUNTIME_CODE_CANDIDATE
} from "../generated/candidate/Verify.sol";
import {
    CREATION_CODE as AUTO_APPROVE_CREATION_CODE_CANDIDATE,
    RUNTIME_CODE as AUTO_APPROVE_RUNTIME_CODE_CANDIDATE
} from "../generated/candidate/AutoApprove.sol";
import {LibVerifyDeploy} from "../lib/LibVerifyDeploy.sol";
import {LibAutoApproveDeploy} from "../lib/LibAutoApproveDeploy.sol";
import {LibReleasedSuites} from "../lib/LibReleasedSuites.sol";

/// @title VerifyDeploySuites
/// @notice Everything this repo deploys, declared once: the `verify` and
/// `auto-approve` candidates, and the released suites `script/Build.sol`
/// generates from the frozen record.
abstract contract VerifyDeploySuites is RainDeploySuitesBase {
    /// @inheritdoc RainDeploySuitesBase
    function releasedSuites() internal pure override returns (DeploySuite[] memory) {
        return LibReleasedSuites.releasedSuites();
    }

    /// @inheritdoc RainDeploySuitesBase
    function candidateSuites() internal pure override returns (DeployCandidate[] memory) {
        DeployCandidate[] memory candidates = new DeployCandidate[](2);
        candidates[0] = verifyCandidate();
        candidates[1] = autoApproveCandidate();
        return candidates;
    }

    /// The rolling `Verify` candidate. Its constructor only disables
    /// initializers, so it has no on-chain dependency.
    /// @return The candidate.
    function verifyCandidate() internal pure returns (DeployCandidate memory) {
        return DeployCandidate({
            snapshot: DeploySuite({
                suite: "verify",
                creationCode: VERIFY_CREATION_CODE_CANDIDATE,
                storedDeployedAddress: LibVerifyDeploy.VERIFY_DEPLOYED_ADDRESS,
                storedBytecodeHash: LibVerifyDeploy.VERIFY_DEPLOYED_CODEHASH,
                storedRuntimeCode: VERIFY_RUNTIME_CODE_CANDIDATE,
                artifactPath: "src/concrete/Verify.sol:Verify",
                dependencies: new DeployDependency[](0),
                mechanism: DeployMechanism.Zoltu,
                mechanismData: ""
            }),
            unanchorableReason: ""
        });
    }

    /// The rolling `AutoApprove` candidate. Its constructor only disables
    /// initializers, so it has no on-chain dependency.
    /// @return The candidate.
    function autoApproveCandidate() internal pure returns (DeployCandidate memory) {
        return DeployCandidate({
            snapshot: DeploySuite({
                suite: "auto-approve",
                creationCode: AUTO_APPROVE_CREATION_CODE_CANDIDATE,
                storedDeployedAddress: LibAutoApproveDeploy.AUTO_APPROVE_DEPLOYED_ADDRESS,
                storedBytecodeHash: LibAutoApproveDeploy.AUTO_APPROVE_DEPLOYED_CODEHASH,
                storedRuntimeCode: AUTO_APPROVE_RUNTIME_CODE_CANDIDATE,
                artifactPath: "src/concrete/AutoApprove.sol:AutoApprove",
                dependencies: new DeployDependency[](0),
                mechanism: DeployMechanism.Zoltu,
                mechanismData: ""
            }),
            unanchorableReason: ""
        });
    }
}
