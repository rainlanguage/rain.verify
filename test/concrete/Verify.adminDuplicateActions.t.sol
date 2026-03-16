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
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @title VerifyAdminDuplicateActionsTest
/// @notice Tests that duplicate admin operations are idempotent at the storage
/// level. Re-approving an already approved account or re-banning an already
/// banned account MUST emit the event but MUST NOT change the on-chain state.
/// Also verifies that removal works correctly after a ban+approve sequence.
contract VerifyAdminDuplicateActionsTest is Test {
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

    /// Re-approving an already approved account emits an `Approve` event but
    /// does not change the `approvedSince` timestamp in the stored `State`.
    function testDuplicateApproveIsIdempotent(
        address user,
        address approver0,
        address approver1,
        bytes memory data
    ) external {
        vm.assume(user != address(0));
        vm.assume(approver0 != address(0));
        vm.assume(approver1 != address(0));
        vm.assume(user != approver0);
        vm.assume(user != approver1);

        vm.startPrank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver0);
        I_VERIFY.grantRole(APPROVER_ROLE, approver1);
        vm.stopPrank();

        // Add the account.
        vm.prank(user);
        I_VERIFY.add(data);

        // First approval.
        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(approver0);
        I_VERIFY.approve(evidences);

        // Snapshot state after first approval.
        State memory stateAfterFirstApproval = I_VERIFY.state(user);
        assertEq(stateAfterFirstApproval.approvedSince, uint32(block.timestamp));
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_APPROVED));

        // Second approval at a later time.
        vm.warp(block.timestamp + 1);
        evidences[0] = Evidence(user, data);

        vm.recordLogs();
        vm.prank(approver1);
        I_VERIFY.approve(evidences);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Verify the Approve event was emitted.
        bool approveEventFound = false;
        bytes32 approveEventSig = keccak256("Approve(address,(address,bytes))");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == approveEventSig) {
                approveEventFound = true;
                break;
            }
        }
        assertTrue(approveEventFound);

        // State MUST NOT have changed.
        State memory stateAfterSecondApproval = I_VERIFY.state(user);
        assertEq(stateAfterSecondApproval.addedSince, stateAfterFirstApproval.addedSince);
        assertEq(stateAfterSecondApproval.approvedSince, stateAfterFirstApproval.approvedSince);
        assertEq(stateAfterSecondApproval.bannedSince, stateAfterFirstApproval.bannedSince);
    }

    /// Re-banning an already banned account emits a `Ban` event but does not
    /// change the `bannedSince` timestamp in the stored `State`.
    function testDuplicateBanIsIdempotent(address user, address banner0, address banner1, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(banner0 != address(0));
        vm.assume(banner1 != address(0));
        vm.assume(user != banner0);
        vm.assume(user != banner1);

        vm.startPrank(ADMIN);
        I_VERIFY.grantRole(BANNER_ROLE, banner0);
        I_VERIFY.grantRole(BANNER_ROLE, banner1);
        vm.stopPrank();

        // Add the account.
        vm.prank(user);
        I_VERIFY.add(data);

        // First ban.
        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(banner0);
        I_VERIFY.ban(evidences);

        // Snapshot state after first ban.
        State memory stateAfterFirstBan = I_VERIFY.state(user);
        assertEq(stateAfterFirstBan.bannedSince, uint32(block.timestamp));
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_BANNED));

        // Second ban at a later time.
        vm.warp(block.timestamp + 1);
        evidences[0] = Evidence(user, data);

        vm.recordLogs();
        vm.prank(banner1);
        I_VERIFY.ban(evidences);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Verify the Ban event was emitted.
        bool banEventFound = false;
        bytes32 banEventSig = keccak256("Ban(address,(address,bytes))");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == banEventSig) {
                banEventFound = true;
                break;
            }
        }
        assertTrue(banEventFound);

        // State MUST NOT have changed.
        State memory stateAfterSecondBan = I_VERIFY.state(user);
        assertEq(stateAfterSecondBan.addedSince, stateAfterFirstBan.addedSince);
        assertEq(stateAfterSecondBan.approvedSince, stateAfterFirstBan.approvedSince);
        assertEq(stateAfterSecondBan.bannedSince, stateAfterFirstBan.bannedSince);
    }

    /// An account that has been banned can still be approved (the event emits)
    /// but remains BANNED. After removal, the account returns to NIL.
    function testRemoveAfterBanAndApprove(
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

        // Add the account.
        vm.prank(user);
        I_VERIFY.add(data);

        // Ban the account.
        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(banner);
        I_VERIFY.ban(evidences);
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_BANNED));

        // Approve the banned account (event emits but status stays BANNED).
        vm.warp(block.timestamp + 1);
        evidences[0] = Evidence(user, data);
        vm.prank(approver);
        I_VERIFY.approve(evidences);
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_BANNED));

        // Remove the account.
        vm.warp(block.timestamp + 1);
        evidences[0] = Evidence(user, data);
        vm.prank(remover);
        I_VERIFY.remove(evidences);

        // Account is now NIL.
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_NIL));
        State memory s = I_VERIFY.state(user);
        assertEq(s.addedSince, 0);
        assertEq(s.approvedSince, 0);
        assertEq(s.bannedSince, 0);
    }

    /// Only accounts with the APPROVER role can call `approve`. A non-approver
    /// MUST be rejected.
    function testApproveRequiresRole(address user, address nonApprover, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(nonApprover != address(0));
        vm.assume(user != nonApprover);
        vm.assume(nonApprover != ADMIN);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonApprover, APPROVER_ROLE));
        vm.prank(nonApprover);
        I_VERIFY.approve(evidences);
    }

    /// Only accounts with the BANNER role can call `ban`. A non-banner MUST be
    /// rejected.
    function testBanRequiresRole(address user, address nonBanner, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(nonBanner != address(0));
        vm.assume(user != nonBanner);
        vm.assume(nonBanner != ADMIN);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonBanner, BANNER_ROLE));
        vm.prank(nonBanner);
        I_VERIFY.ban(evidences);
    }

    /// Only accounts with the REMOVER role can call `remove`. A non-remover
    /// MUST be rejected.
    function testRemoveRequiresRole(address user, address nonRemover, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(nonRemover != address(0));
        vm.assume(user != nonRemover);
        vm.assume(nonRemover != ADMIN);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonRemover, REMOVER_ROLE));
        vm.prank(nonRemover);
        I_VERIFY.remove(evidences);
    }
}
