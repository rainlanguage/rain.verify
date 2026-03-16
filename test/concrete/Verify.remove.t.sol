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

/// @title VerifyRemoveTest
/// @notice Tests that `remove` is only callable by the REMOVER role, that a
/// remover cannot approve or ban (role separation), that remove emits the
/// correct `Remove` event, and that after removal the account state is fully
/// cleared (all timestamps reset to zero).
contract VerifyRemoveTest is Test {
    using LibVerifyStatus for VerifyStatus;

    Verify internal immutable I_VERIFY;

    address internal constant ADMIN = address(uint160(uint256(keccak256("admin"))));

    bytes32 internal constant APPROVER_ROLE = keccak256("APPROVER");
    bytes32 internal constant REMOVER_ROLE = keccak256("REMOVER");
    bytes32 internal constant BANNER_ROLE = keccak256("BANNER");

    constructor() {
        Verify implementation = new Verify();
        address clone = Clones.clone(address(implementation));
        I_VERIFY = Verify(clone);
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(ADMIN, address(0))));
    }

    /// A remover MUST NOT be able to call `approve`. Role separation ensures
    /// that the remover role alone does not grant approval privileges.
    function testRemoverCannotApprove(address remover, address user, bytes memory data) external {
        vm.assume(remover != address(0));
        vm.assume(user != address(0));
        vm.assume(remover != user);
        vm.assume(remover != ADMIN);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(REMOVER_ROLE, remover);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, remover, APPROVER_ROLE)
        );
        vm.prank(remover);
        I_VERIFY.approve(evidences);
    }

    /// A remover MUST NOT be able to call `ban`. Role separation ensures that
    /// the remover role alone does not grant banning privileges.
    function testRemoverCannotBan(address remover, address user, bytes memory data) external {
        vm.assume(remover != address(0));
        vm.assume(user != address(0));
        vm.assume(remover != user);
        vm.assume(remover != ADMIN);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(REMOVER_ROLE, remover);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, remover, BANNER_ROLE)
        );
        vm.prank(remover);
        I_VERIFY.ban(evidences);
    }

    /// Only an account with the REMOVER role can call `remove`. An arbitrary
    /// account without the role MUST be rejected.
    function testOnlyRemoverCanRemove(address nonRemover, address user, bytes memory data) external {
        vm.assume(nonRemover != address(0));
        vm.assume(user != address(0));
        vm.assume(nonRemover != user);
        vm.assume(nonRemover != ADMIN);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonRemover, REMOVER_ROLE)
        );
        vm.prank(nonRemover);
        I_VERIFY.remove(evidences);
    }

    /// Calling `remove` on an ADDED account MUST emit the `Remove` event with
    /// the correct sender and evidence.
    function testRemoveEmitsEvent(address remover, address user, bytes memory data) external {
        vm.assume(remover != address(0));
        vm.assume(user != address(0));
        vm.assume(remover != user);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(REMOVER_ROLE, remover);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.expectEmit(true, true, true, true);
        emit Verify.Remove(remover, Evidence(user, data));

        vm.prank(remover);
        I_VERIFY.remove(evidences);
    }

    /// After removing an ADDED account, the on-chain state MUST be fully
    /// cleared: `addedSince`, `approvedSince`, and `bannedSince` all reset
    /// to zero.
    function testRemoveFromAddedClearsState(address remover, address user, bytes memory data) external {
        vm.assume(remover != address(0));
        vm.assume(user != address(0));
        vm.assume(remover != user);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(REMOVER_ROLE, remover);

        vm.prank(user);
        I_VERIFY.add(data);
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_ADDED));

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(remover);
        I_VERIFY.remove(evidences);

        State memory s = I_VERIFY.state(user);
        assertEq(s.addedSince, 0);
        assertEq(s.approvedSince, 0);
        assertEq(s.bannedSince, 0);
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_NIL));
    }

    /// After removing an APPROVED account, the on-chain state MUST be fully
    /// cleared: `addedSince`, `approvedSince`, and `bannedSince` all reset
    /// to zero.
    function testRemoveFromApprovedClearsState(address remover, address approver, address user, bytes memory data)
        external
    {
        vm.assume(remover != address(0));
        vm.assume(approver != address(0));
        vm.assume(user != address(0));
        vm.assume(remover != user);
        vm.assume(approver != user);
        vm.assume(remover != approver);

        vm.startPrank(ADMIN);
        I_VERIFY.grantRole(REMOVER_ROLE, remover);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);
        vm.stopPrank();

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory approveEvidences = new Evidence[](1);
        approveEvidences[0] = Evidence(user, data);
        vm.prank(approver);
        I_VERIFY.approve(approveEvidences);
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_APPROVED));

        Evidence[] memory removeEvidences = new Evidence[](1);
        removeEvidences[0] = Evidence(user, data);
        vm.prank(remover);
        I_VERIFY.remove(removeEvidences);

        State memory s = I_VERIFY.state(user);
        assertEq(s.addedSince, 0);
        assertEq(s.approvedSince, 0);
        assertEq(s.bannedSince, 0);
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_NIL));
    }

    /// After removing a BANNED account, the on-chain state MUST be fully
    /// cleared: `addedSince`, `approvedSince`, and `bannedSince` all reset
    /// to zero.
    function testRemoveFromBannedClearsState(address remover, address banner, address user, bytes memory data)
        external
    {
        vm.assume(remover != address(0));
        vm.assume(banner != address(0));
        vm.assume(user != address(0));
        vm.assume(remover != user);
        vm.assume(banner != user);
        vm.assume(remover != banner);

        vm.startPrank(ADMIN);
        I_VERIFY.grantRole(REMOVER_ROLE, remover);
        I_VERIFY.grantRole(BANNER_ROLE, banner);
        vm.stopPrank();

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory banEvidences = new Evidence[](1);
        banEvidences[0] = Evidence(user, data);
        vm.prank(banner);
        I_VERIFY.ban(banEvidences);
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_BANNED));

        Evidence[] memory removeEvidences = new Evidence[](1);
        removeEvidences[0] = Evidence(user, data);
        vm.prank(remover);
        I_VERIFY.remove(removeEvidences);

        State memory s = I_VERIFY.state(user);
        assertEq(s.addedSince, 0);
        assertEq(s.approvedSince, 0);
        assertEq(s.bannedSince, 0);
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_NIL));
    }
}
