// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test, Vm} from "forge-std/Test.sol";
import {Verify, VerifyConfig, State} from "../../src/concrete/Verify.sol";
import {
    Evidence,
    VerifyStatus,
    VERIFY_STATUS_NIL,
    VERIFY_STATUS_ADDED,
    VERIFY_STATUS_APPROVED,
    VERIFY_STATUS_BANNED
} from "rain.verify.interface/interface/IVerifyV1.sol";
import {ICloneableV2, ICLONEABLE_V2_SUCCESS} from "rain.factory/interface/ICloneableV2.sol";
import {LibVerifyStatus} from "../../src/lib/LibVerifyStatus.sol";
import {Clones} from "rain.factory/../lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

/// @title VerifyStatusTest
/// @notice Tests that `statusAtTime` returns the correct status for any given
/// state and timestamp through the full account lifecycle: NIL -> ADDED ->
/// APPROVED -> BANNED -> removed (NIL again). Historical timestamps are
/// checked against the latest state before removal.
contract VerifyStatusTest is Test {
    using LibVerifyStatus for VerifyStatus;

    Verify internal immutable I_VERIFY;

    address internal constant ADMIN = address(uint160(uint256(keccak256("admin"))));

    bytes32 internal constant APPROVER_ROLE = keccak256("APPROVER");
    bytes32 internal constant BANNER_ROLE = keccak256("BANNER");
    bytes32 internal constant REMOVER_ROLE = keccak256("REMOVER");

    uint32 internal constant UNINITIALIZED = type(uint32).max;

    constructor() {
        Verify implementation = new Verify();
        address clone = Clones.clone(address(implementation));
        I_VERIFY = Verify(clone);
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(ADMIN, address(0))));
    }

    /// `statusAtTime` returns NIL for a state where `addedSince` is 0 (never
    /// added), regardless of the timestamp queried.
    function testStatusNilState(uint256 timestamp) external view {
        State memory nilState = State(0, 0, 0);
        assertTrue(I_VERIFY.statusAtTime(nilState, timestamp).eq(VERIFY_STATUS_NIL));
    }

    /// `statusAtTime` returns NIL when the query timestamp is before the
    /// `addedSince` time, because the account did not yet exist at that point.
    function testStatusNilBeforeAdded(uint32 addedSince, uint256 timestamp) external view {
        vm.assume(addedSince > 0);
        vm.assume(timestamp < uint256(addedSince));
        State memory lState = State(addedSince, UNINITIALIZED, UNINITIALIZED);
        assertTrue(I_VERIFY.statusAtTime(lState, timestamp).eq(VERIFY_STATUS_NIL));
    }

    /// `statusAtTime` returns ADDED when the query timestamp is at or after
    /// `addedSince` and the account has not been approved or banned.
    function testStatusAdded(uint32 addedSince, uint32 timestamp) external view {
        vm.assume(addedSince > 0);
        vm.assume(timestamp >= addedSince);
        vm.assume(timestamp < UNINITIALIZED);
        State memory lState = State(addedSince, UNINITIALIZED, UNINITIALIZED);
        assertTrue(I_VERIFY.statusAtTime(lState, uint256(timestamp)).eq(VERIFY_STATUS_ADDED));
    }

    /// `statusAtTime` returns APPROVED when the query timestamp is at or after
    /// `approvedSince` and the account has not been banned.
    function testStatusApproved(uint32 addedSince, uint32 approvedSince, uint32 timestamp) external view {
        vm.assume(addedSince > 0);
        vm.assume(approvedSince < UNINITIALIZED);
        vm.assume(approvedSince >= addedSince);
        vm.assume(timestamp >= approvedSince);
        vm.assume(timestamp < UNINITIALIZED);
        State memory lState = State(addedSince, approvedSince, UNINITIALIZED);
        assertTrue(I_VERIFY.statusAtTime(lState, uint256(timestamp)).eq(VERIFY_STATUS_APPROVED));
    }

    /// `statusAtTime` returns ADDED when the query timestamp is between
    /// `addedSince` and `approvedSince`, i.e. the account was added but not
    /// yet approved at the query time.
    function testStatusAddedBeforeApproval(uint32 addedSince, uint32 approvedSince, uint256 timestamp) external view {
        vm.assume(addedSince > 0);
        vm.assume(approvedSince < UNINITIALIZED);
        vm.assume(approvedSince > addedSince);
        vm.assume(timestamp >= uint256(addedSince));
        vm.assume(timestamp < uint256(approvedSince));
        State memory lState = State(addedSince, approvedSince, UNINITIALIZED);
        assertTrue(I_VERIFY.statusAtTime(lState, timestamp).eq(VERIFY_STATUS_ADDED));
    }

    /// `statusAtTime` returns BANNED when the query timestamp is at or after
    /// `bannedSince`, regardless of approval status.
    function testStatusBanned(uint32 addedSince, uint32 approvedSince, uint32 bannedSince, uint256 timestamp)
        external
        view
    {
        vm.assume(addedSince > 0);
        vm.assume(bannedSince < UNINITIALIZED);
        vm.assume(bannedSince >= addedSince);
        vm.assume(timestamp >= uint256(bannedSince));
        State memory lState = State(addedSince, approvedSince, bannedSince);
        assertTrue(I_VERIFY.statusAtTime(lState, timestamp).eq(VERIFY_STATUS_BANNED));
    }

    /// `statusAtTime` returns BANNED even when the approval happened before
    /// the ban and the query time is after both, confirming ban takes priority.
    function testStatusBannedOverridesApproved(
        uint32 addedSince,
        uint32 approvedSince,
        uint32 bannedSince,
        uint256 timestamp
    ) external view {
        vm.assume(addedSince > 0);
        vm.assume(approvedSince < UNINITIALIZED);
        vm.assume(bannedSince < UNINITIALIZED);
        vm.assume(approvedSince >= addedSince);
        vm.assume(bannedSince >= approvedSince);
        vm.assume(timestamp >= uint256(bannedSince));
        State memory lState = State(addedSince, approvedSince, bannedSince);
        assertTrue(I_VERIFY.statusAtTime(lState, timestamp).eq(VERIFY_STATUS_BANNED));
    }

    /// Full lifecycle integration test: walks an account through NIL -> ADDED
    /// -> APPROVED -> BANNED -> removed (NIL) and verifies `statusAtTime` at
    /// each historical timestamp using the state snapshot before removal.
    function testStatusFullLifecycle(
        address user,
        address approver,
        address banner,
        address remover,
        bytes memory data
    ) external {
        vm.assume(user != address(0));
        vm.assume(approver != address(0));
        vm.assume(banner != address(0));
        vm.assume(remover != address(0));
        vm.assume(user != approver);
        vm.assume(user != banner);
        vm.assume(user != remover);

        // Grant roles.
        vm.startPrank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);
        I_VERIFY.grantRole(BANNER_ROLE, banner);
        I_VERIFY.grantRole(REMOVER_ROLE, remover);
        vm.stopPrank();

        // --- NIL ---
        uint256 timestampBeforeAdd = block.timestamp;
        assertTrue(I_VERIFY.accountStatusAtTime(user, timestampBeforeAdd).eq(VERIFY_STATUS_NIL));

        // --- ADD ---
        vm.warp(block.timestamp + 1);
        uint256 addTimestamp = block.timestamp;
        vm.prank(user);
        I_VERIFY.add(data);
        assertTrue(I_VERIFY.accountStatusAtTime(user, addTimestamp).eq(VERIFY_STATUS_ADDED));
        // Historical: still NIL before add.
        assertTrue(I_VERIFY.accountStatusAtTime(user, timestampBeforeAdd).eq(VERIFY_STATUS_NIL));

        // --- APPROVE ---
        vm.warp(block.timestamp + 1);
        uint256 approveTimestamp = block.timestamp;
        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(approver);
        I_VERIFY.approve(evidences);
        assertTrue(I_VERIFY.accountStatusAtTime(user, approveTimestamp).eq(VERIFY_STATUS_APPROVED));
        // Historical: ADDED between add and approve.
        assertTrue(I_VERIFY.accountStatusAtTime(user, addTimestamp).eq(VERIFY_STATUS_ADDED));

        // --- BAN ---
        vm.warp(block.timestamp + 1);
        uint256 banTimestamp = block.timestamp;
        evidences[0] = Evidence(user, data);
        vm.prank(banner);
        I_VERIFY.ban(evidences);
        assertTrue(I_VERIFY.accountStatusAtTime(user, banTimestamp).eq(VERIFY_STATUS_BANNED));
        // Historical: APPROVED between approve and ban.
        assertTrue(I_VERIFY.accountStatusAtTime(user, approveTimestamp).eq(VERIFY_STATUS_APPROVED));
        // Historical: ADDED between add and approve.
        assertTrue(I_VERIFY.accountStatusAtTime(user, addTimestamp).eq(VERIFY_STATUS_ADDED));
        // Historical: NIL before add.
        assertTrue(I_VERIFY.accountStatusAtTime(user, timestampBeforeAdd).eq(VERIFY_STATUS_NIL));

        // --- REMOVE ---
        vm.warp(block.timestamp + 1);
        evidences[0] = Evidence(user, data);
        vm.prank(remover);
        I_VERIFY.remove(evidences);
        // After removal, all timestamps return NIL because state is zeroed.
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_NIL));
        assertTrue(I_VERIFY.accountStatusAtTime(user, banTimestamp).eq(VERIFY_STATUS_NIL));
        assertTrue(I_VERIFY.accountStatusAtTime(user, approveTimestamp).eq(VERIFY_STATUS_NIL));
        assertTrue(I_VERIFY.accountStatusAtTime(user, addTimestamp).eq(VERIFY_STATUS_NIL));
    }
}
