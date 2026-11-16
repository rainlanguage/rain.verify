// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.25;

import {
    DeployCandidate,
    DeployDependency,
    DeployDeclaration,
    DeploySuite,
    ExternalDeployment,
    RainDeploySuitesBase,
    UnknownDeploymentSuite
} from "rain-deploy-0.1.33/src/abstract/RainDeploySuitesBase.sol";
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
import {LibRainDeployDeclaration} from "rain-deploy-0.1.33/src/lib/LibRainDeployDeclaration.sol";
import {LibRainDeployZoltuMechanism} from "rain-deploy-0.1.33/src/lib/LibRainDeployZoltuMechanism.sol";
import {Verify} from "../concrete/Verify.sol";
import {AutoApprove} from "../concrete/AutoApprove.sol";

/// @title VerifyDeploySuites
/// @notice Everything this repo deploys, declared once: the `verify` and
/// `auto-approve` candidates, and the released suites `script/Build.sol`
/// generates from the frozen record.
abstract contract VerifyDeploySuites is RainDeploySuitesBase {
    /// The `Verify` suite key.
    string constant VERIFY_SUITE = "verify";

    /// The `AutoApprove` suite key.
    string constant AUTO_APPROVE_SUITE = "auto-approve";

    /// @inheritdoc RainDeploySuitesBase
    function declaration() internal pure override returns (DeployDeclaration memory) {
        DeployDeclaration memory declared;
        LibRainDeployDeclaration.extend(declared);
        LibRainDeployZoltuMechanism.extend(declared);
        LibRainDeployDeclaration.addReleased(declared, LibReleasedSuites.releasedSuites());
        LibRainDeployDeclaration.addCandidates(declared, candidates());
        declared.externalDeployments = new ExternalDeployment[](0);
        declared.sourceCreationCode = sourceCreationCode;
        return declared;
    }

    /// Every candidate this repo deploys.
    /// @return The candidates.
    function candidates() internal pure returns (DeployCandidate[] memory) {
        DeployCandidate[] memory declared = new DeployCandidate[](2);
        declared[0] = verifyCandidate();
        declared[1] = autoApproveCandidate();
        return declared;
    }

    /// The creation code the current source compiles to for a suite.
    /// @param suite The suite key.
    /// @return The creation code.
    function sourceCreationCode(string memory suite) internal pure returns (bytes memory) {
        if (keccak256(bytes(suite)) == keccak256(bytes(VERIFY_SUITE))) {
            return type(Verify).creationCode;
        }
        if (keccak256(bytes(suite)) == keccak256(bytes(AUTO_APPROVE_SUITE))) {
            return type(AutoApprove).creationCode;
        }
        revert UnknownDeploymentSuite(suite, string.concat(VERIFY_SUITE, ", ", AUTO_APPROVE_SUITE));
    }

    /// The rolling `Verify` candidate. Its constructor only disables
    /// initializers, so it has no on-chain dependency.
    /// @return The candidate.
    function verifyCandidate() internal pure returns (DeployCandidate memory) {
        return DeployCandidate({
            snapshot: DeploySuite({
                suite: VERIFY_SUITE,
                creationCode: VERIFY_CREATION_CODE_CANDIDATE,
                storedDeployedAddress: LibVerifyDeploy.VERIFY_DEPLOYED_ADDRESS,
                storedBytecodeHash: LibVerifyDeploy.VERIFY_DEPLOYED_CODEHASH,
                storedRuntimeCode: VERIFY_RUNTIME_CODE_CANDIDATE,
                artifactPath: "src/concrete/Verify.sol:Verify",
                dependencies: new DeployDependency[](0),
                mechanismData: LibRainDeployZoltuMechanism.mechanismData(),
                networks: new string[](0),
                describedByMeta: ""
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
                suite: AUTO_APPROVE_SUITE,
                creationCode: AUTO_APPROVE_CREATION_CODE_CANDIDATE,
                storedDeployedAddress: LibAutoApproveDeploy.AUTO_APPROVE_DEPLOYED_ADDRESS,
                storedBytecodeHash: LibAutoApproveDeploy.AUTO_APPROVE_DEPLOYED_CODEHASH,
                storedRuntimeCode: AUTO_APPROVE_RUNTIME_CODE_CANDIDATE,
                artifactPath: "src/concrete/AutoApprove.sol:AutoApprove",
                dependencies: new DeployDependency[](0),
                mechanismData: LibRainDeployZoltuMechanism.mechanismData(),
                networks: new string[](0),
                describedByMeta: ""
            }),
            unanchorableReason: ""
        });
    }
}
