// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {RainDeployVerifyChain} from "rain-deploy-0.1.22/src/abstract/RainDeployVerifyChain.sol";
import {VerifyDeploySuites} from "src/abstract/VerifyDeploySuites.sol";

/// @title VerifyDeployChainTest
/// @notice Every suite is live, with the code it pins, on every supported
/// network.
contract VerifyDeployChainTest is VerifyDeploySuites, RainDeployVerifyChain {}
