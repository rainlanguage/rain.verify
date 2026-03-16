// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.25;

import {Evidence} from "rain.verify.interface/interface/IVerifyV1.sol";

library LibEvidence {
    /// Stores a memory pointer to `evidence` at `refs[refsIndex]` via assembly.
    /// Callers MUST ensure `refsIndex < refs.length`.
    /// @param refs The array to write the evidence pointer into.
    /// @param evidence The evidence to reference.
    /// @param refsIndex The index in `refs` to write to.
    function _updateEvidenceRef(uint256[] memory refs, Evidence memory evidence, uint256 refsIndex) internal pure {
        assembly ("memory-safe") {
            mstore(add(refs, add(0x20, mul(0x20, refsIndex))), evidence)
        }
    }

    /// Reinterprets a `uint256[]` of evidence pointers as `Evidence[]` via
    /// pointer aliasing. The array MUST have been populated exclusively by
    /// `_updateEvidenceRef`.
    /// @param refs The array of evidence pointers.
    /// @return evidences The same memory reinterpreted as `Evidence[]`.
    function asEvidences(uint256[] memory refs) internal pure returns (Evidence[] memory evidences) {
        assembly ("memory-safe") {
            evidences := refs
        }
    }
}
