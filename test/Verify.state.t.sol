// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test, Vm} from "forge-std/Test.sol";
import {Verify, VerifyConfig, State} from "../src/concrete/Verify.sol";
import {
    Evidence,
    VerifyStatus,
    VERIFY_STATUS_NIL,
    VERIFY_STATUS_ADDED,
    VERIFY_STATUS_APPROVED,
    VERIFY_STATUS_BANNED
} from "rain.verify.interface/interface/IVerifyV1.sol";
import {ICloneableV2, ICLONEABLE_V2_SUCCESS} from "rain.factory/interface/ICloneableV2.sol";
import {LibVerifyStatus} from "../src/lib/LibVerifyStatus.sol";
import {Clones} from "rain.factory/../lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

/// @title VerifyStateTest
/// @notice Tests that `state()` returns the correct `State` struct for a given
/// account through the full lifecycle: NIL -> ADDED -> APPROVED -> BANNED ->
/// removed (NIL). Each transition is verified by inspecting the individual
/// `addedSince`, `approvedSince`, and `bannedSince` fields.
contract VerifyStateTest is Test {
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

    /// A NIL account has all state fields zeroed: `addedSince` = 0,
    /// `approvedSince` = 0, `bannedSince` = 0.
    function testStateNil(address user) external view {
        vm.assume(user != address(0));
        State memory s = I_VERIFY.state(user);
        assertEq(s.addedSince, 0);
        assertEq(s.approvedSince, 0);
        assertEq(s.bannedSince, 0);
    }

    /// After `add`, `addedSince` equals the block timestamp, while
    /// `approvedSince` and `bannedSince` are UNINITIALIZED (0xFFFFFFFF).
    function testStateAfterAdd(address user, bytes memory data) external {
        vm.assume(user != address(0));

        vm.prank(user);
        I_VERIFY.add(data);

        State memory s = I_VERIFY.state(user);
        assertEq(s.addedSince, uint32(block.timestamp));
        assertEq(s.approvedSince, UNINITIALIZED);
        assertEq(s.bannedSince, UNINITIALIZED);
    }

    /// After `approve`, `approvedSince` equals the approval timestamp,
    /// `addedSince` is preserved from the add, and `bannedSince` remains
    /// UNINITIALIZED.
    function testStateAfterApprove(address user, address approver, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(approver != address(0));
        vm.assume(user != approver);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);

        vm.prank(user);
        I_VERIFY.add(data);
        uint32 addedTime = uint32(block.timestamp);

        vm.warp(block.timestamp + 1);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(approver);
        I_VERIFY.approve(evidences);
        uint32 approvedTime = uint32(block.timestamp);

        State memory s = I_VERIFY.state(user);
        assertEq(s.addedSince, addedTime);
        assertEq(s.approvedSince, approvedTime);
        assertEq(s.bannedSince, UNINITIALIZED);
    }

    /// After `ban`, `bannedSince` equals the ban timestamp while `addedSince`
    /// and `approvedSince` are preserved from their respective transitions.
    function testStateAfterBan(address user, address approver, address banner, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(approver != address(0));
        vm.assume(banner != address(0));
        vm.assume(user != approver);
        vm.assume(user != banner);

        vm.startPrank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);
        I_VERIFY.grantRole(BANNER_ROLE, banner);
        vm.stopPrank();

        vm.prank(user);
        I_VERIFY.add(data);
        uint32 addedTime = uint32(block.timestamp);

        vm.warp(block.timestamp + 1);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(approver);
        I_VERIFY.approve(evidences);
        uint32 approvedTime = uint32(block.timestamp);

        vm.warp(block.timestamp + 1);

        evidences[0] = Evidence(user, data);
        vm.prank(banner);
        I_VERIFY.ban(evidences);
        uint32 bannedTime = uint32(block.timestamp);

        State memory s = I_VERIFY.state(user);
        assertEq(s.addedSince, addedTime);
        assertEq(s.approvedSince, approvedTime);
        assertEq(s.bannedSince, bannedTime);
    }

    /// After `remove`, all state fields are reset to 0 (the account returns
    /// to NIL).
    function testStateAfterRemove(address user, address approver, address banner, address remover, bytes memory data)
        external
    {
        vm.assume(user != address(0));
        vm.assume(approver != address(0));
        vm.assume(banner != address(0));
        vm.assume(remover != address(0));
        vm.assume(user != approver);
        vm.assume(user != banner);
        vm.assume(user != remover);

        vm.startPrank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);
        I_VERIFY.grantRole(BANNER_ROLE, banner);
        I_VERIFY.grantRole(REMOVER_ROLE, remover);
        vm.stopPrank();

        vm.prank(user);
        I_VERIFY.add(data);

        vm.warp(block.timestamp + 1);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(approver);
        I_VERIFY.approve(evidences);

        vm.warp(block.timestamp + 1);

        evidences[0] = Evidence(user, data);
        vm.prank(banner);
        I_VERIFY.ban(evidences);

        vm.warp(block.timestamp + 1);

        evidences[0] = Evidence(user, data);
        vm.prank(remover);
        I_VERIFY.remove(evidences);

        State memory s = I_VERIFY.state(user);
        assertEq(s.addedSince, 0);
        assertEq(s.approvedSince, 0);
        assertEq(s.bannedSince, 0);
    }

    /// Full lifecycle integration: walks an account through every state
    /// transition and verifies the `State` struct fields at each step.
    function testStateFullLifecycle(
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

        vm.startPrank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);
        I_VERIFY.grantRole(BANNER_ROLE, banner);
        I_VERIFY.grantRole(REMOVER_ROLE, remover);
        vm.stopPrank();

        // --- NIL ---
        State memory s = I_VERIFY.state(user);
        assertEq(s.addedSince, 0);
        assertEq(s.approvedSince, 0);
        assertEq(s.bannedSince, 0);

        // --- ADD ---
        vm.warp(block.timestamp + 1);
        vm.prank(user);
        I_VERIFY.add(data);
        uint32 addedTime = uint32(block.timestamp);

        s = I_VERIFY.state(user);
        assertEq(s.addedSince, addedTime);
        assertEq(s.approvedSince, UNINITIALIZED);
        assertEq(s.bannedSince, UNINITIALIZED);

        // --- APPROVE ---
        vm.warp(block.timestamp + 1);
        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(approver);
        I_VERIFY.approve(evidences);
        uint32 approvedTime = uint32(block.timestamp);

        s = I_VERIFY.state(user);
        assertEq(s.addedSince, addedTime);
        assertEq(s.approvedSince, approvedTime);
        assertEq(s.bannedSince, UNINITIALIZED);

        // --- BAN ---
        vm.warp(block.timestamp + 1);
        evidences[0] = Evidence(user, data);
        vm.prank(banner);
        I_VERIFY.ban(evidences);
        uint32 bannedTime = uint32(block.timestamp);

        s = I_VERIFY.state(user);
        assertEq(s.addedSince, addedTime);
        assertEq(s.approvedSince, approvedTime);
        assertEq(s.bannedSince, bannedTime);

        // --- REMOVE ---
        vm.warp(block.timestamp + 1);
        evidences[0] = Evidence(user, data);
        vm.prank(remover);
        I_VERIFY.remove(evidences);

        s = I_VERIFY.state(user);
        assertEq(s.addedSince, 0);
        assertEq(s.approvedSince, 0);
        assertEq(s.bannedSince, 0);
    }
}
