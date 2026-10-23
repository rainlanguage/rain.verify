// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {RainDeployVerifySnapshot} from "rain-deploy-0.1.22/src/abstract/RainDeployVerifySnapshot.sol";
import {VerifyDeploySuites} from "src/abstract/VerifyDeploySuites.sol";

/// @title VerifyDeploySnapshotTest
/// @notice Every deploy-pin assertion over the suites that needs no network.
contract VerifyDeploySnapshotTest is VerifyDeploySuites, RainDeployVerifySnapshot {}
