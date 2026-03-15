// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
import {Evidence} from "rain.verify.interface/interface/IVerifyV1.sol";
import {LibEvidence} from "../src/lib/LibEvidence.sol";

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
    function updateThreeAndConvert(
        Evidence memory e0,
        Evidence memory e1,
        Evidence memory e2
    ) external pure returns (Evidence[] memory) {
        uint256[] memory refs = new uint256[](3);
        refs._updateEvidenceRef(e0, 0);
        refs._updateEvidenceRef(e1, 1);
        refs._updateEvidenceRef(e2, 2);
        return refs.asEvidences();
    }
}

/// @title LibEvidenceTest
/// @notice Foundry fuzz tests for `LibEvidence._updateEvidenceRef` and
/// `LibEvidence.asEvidences`.
contract LibEvidenceTest is Test {
    LibEvidenceHarness internal immutable I_HARNESS;

    constructor() {
        I_HARNESS = new LibEvidenceHarness();
    }

    /// A single evidence ref stored at index 0 is retrievable via
    /// `asEvidences` with matching account and data.
    function testSingleEvidenceRefUpdateAndRetrieve(address account, bytes memory data) external view {
        uint256[] memory refs = new uint256[](1);
        Evidence memory evidence = Evidence(account, data);

        Evidence[] memory evidences = I_HARNESS.updateAndConvert(refs, evidence, 0);

        assertEq(evidences.length, 1);
        assertEq(evidences[0].account, account);
        assertEq(evidences[0].data, data);
    }

    /// Multiple evidence refs stored sequentially are all retrievable in the
    /// correct order via `asEvidences`. Uses a single external call because
    /// `_updateEvidenceRef` stores memory pointers that don't survive ABI
    /// encoding across call boundaries.
    function testMultipleEvidenceRefsSequential(
        address account0,
        bytes memory data0,
        address account1,
        bytes memory data1,
        address account2,
        bytes memory data2
    ) external view {
        Evidence[] memory evidences = I_HARNESS.updateThreeAndConvert(
            Evidence(account0, data0),
            Evidence(account1, data1),
            Evidence(account2, data2)
        );

        assertEq(evidences.length, 3);

        assertEq(evidences[0].account, account0);
        assertEq(evidences[0].data, data0);

        assertEq(evidences[1].account, account1);
        assertEq(evidences[1].data, data1);

        assertEq(evidences[2].account, account2);
        assertEq(evidences[2].data, data2);
    }

    /// Round-trip fuzz: create an `Evidence`, store its ref at a bounded
    /// index, convert back, and verify field-level equality.
    function testRoundTripFuzz(address account, bytes memory data, uint8 arrayLen, uint8 indexRaw) external view {
        // Bound array length to [1, 32] to keep memory reasonable.
        uint256 len = bound(uint256(arrayLen), 1, 32);
        uint256 index = bound(uint256(indexRaw), 0, len - 1);

        uint256[] memory refs = new uint256[](len);
        Evidence memory evidence = Evidence(account, data);

        Evidence[] memory evidences = I_HARNESS.updateAndConvert(refs, evidence, index);

        assertEq(evidences.length, len);
        assertEq(evidences[index].account, account);
        assertEq(evidences[index].data, data);
    }
}
