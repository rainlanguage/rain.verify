// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.25;

import {Evidence} from "../interface/IVerifyV1.sol";

library LibEvidence {
    function _updateEvidenceRef(uint256[] memory refs, Evidence memory evidence, uint256 refsIndex) internal pure {
        assembly ("memory-safe") {
            mstore(add(refs, add(0x20, mul(0x20, refsIndex))), evidence)
        }
    }

    function asEvidences(uint256[] memory refs) internal pure returns (Evidence[] memory evidences) {
        assembly ("memory-safe") {
            evidences := refs
        }
    }
}
