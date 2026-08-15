// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Evidence} from "rain-verify-interface-0.1.0/src/interface/IVerifyV1.sol";
import {LibEvidence} from "../../src/lib/LibEvidence.sol";

/// @title LibEvidenceHarness
/// @notice Exposes `LibEvidence` internal functions as external calls so they
/// can be exercised from Foundry tests.
contract LibEvidenceHarness {
    using LibEvidence for uint256[];

    /// Wraps `LibEvidence._updateEvidenceRef`.
    function updateEvidenceRef(uint256[] memory refs, Evidence memory evidence, uint256 refsIndex)
        external
        pure
        returns (uint256[] memory)
    {
        refs._updateEvidenceRef(evidence, refsIndex);
        return refs;
    }

    /// Wraps `LibEvidence.asEvidences`.
    function asEvidences(uint256[] memory refs) external pure returns (Evidence[] memory) {
        return refs.asEvidences();
    }

    /// Convenience: update a ref then immediately convert to `Evidence[]`.
    function updateAndConvert(uint256[] memory refs, Evidence memory evidence, uint256 refsIndex)
        external
        pure
        returns (Evidence[] memory)
    {
        refs._updateEvidenceRef(evidence, refsIndex);
        return refs.asEvidences();
    }

    /// Batch update three refs then convert to `Evidence[]` in a single call.
    /// Required because `_updateEvidenceRef` stores memory pointers that don't
    /// survive ABI encoding across external call boundaries.
    function updateThreeAndConvert(Evidence memory e0, Evidence memory e1, Evidence memory e2)
        external
        pure
        returns (Evidence[] memory)
    {
        uint256[] memory refs = new uint256[](3);
        refs._updateEvidenceRef(e0, 0);
        refs._updateEvidenceRef(e1, 1);
        refs._updateEvidenceRef(e2, 2);
        return refs.asEvidences();
    }
}
