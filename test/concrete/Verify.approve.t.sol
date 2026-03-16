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
import {ZeroAdmin, NotApproved, AlreadyExists, UnknownAccount} from "../../src/err/ErrVerify.sol";
import {LibVerifyStatus} from "../../src/lib/LibVerifyStatus.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @title VerifyApproveTest
/// @notice Tests for `approve` covering role separation, implicit add+approve,
/// role enforcement, event emission, and post-approval add rejection.
contract VerifyApproveTest is Test {
    using LibVerifyStatus for VerifyStatus;

    Verify internal immutable I_VERIFY;

    address internal constant ADMIN = address(uint160(uint256(keccak256("admin"))));

    bytes32 internal constant APPROVER_ROLE = keccak256("APPROVER");
    bytes32 internal constant APPROVER_ADMIN_ROLE = keccak256("APPROVER_ADMIN");
    bytes32 internal constant REMOVER_ROLE = keccak256("REMOVER");
    bytes32 internal constant BANNER_ROLE = keccak256("BANNER");

    constructor() {
        Verify implementation = new Verify();
        address clone = Clones.clone(address(implementation));
        I_VERIFY = Verify(clone);
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(ADMIN, address(0))));
    }

    /// An account with APPROVER role MUST NOT be able to call `remove`.
    /// Role separation ensures approvers cannot remove accounts.
    function testApproverCannotRemove(address approver, address user, bytes memory data) external {
        vm.assume(approver != address(0));
        vm.assume(user != address(0));
        vm.assume(approver != user);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, approver, REMOVER_ROLE)
        );
        vm.prank(approver);
        I_VERIFY.remove(evidences);
    }

    /// An account with APPROVER role MUST NOT be able to call `ban`.
    /// Role separation ensures approvers cannot ban accounts.
    function testApproverCannotBan(address approver, address user, bytes memory data) external {
        vm.assume(approver != address(0));
        vm.assume(user != address(0));
        vm.assume(approver != user);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, approver, BANNER_ROLE)
        );
        vm.prank(approver);
        I_VERIFY.ban(evidences);
    }

    /// An approver can implicitly add and approve a NIL account in a single
    /// call. After the call the account MUST be in the APPROVED state.
    function testApproveImplicitlyAddsNilAccount(address approver, address user, bytes memory data) external {
        vm.assume(approver != address(0));
        vm.assume(user != address(0));
        vm.assume(approver != user);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);

        // Verify the account is NIL before approval.
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_NIL));

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(approver);
        I_VERIFY.approve(evidences);

        // The account MUST now be APPROVED, having been implicitly added.
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_APPROVED));
    }

    /// Only an account with the APPROVER role can call `approve`. An account
    /// without the role MUST be rejected by the AccessControl modifier.
    function testOnlyApproverRoleCanApprove(address nonApprover, address user, bytes memory data) external {
        vm.assume(nonApprover != address(0));
        vm.assume(user != address(0));
        vm.assume(nonApprover != user);
        // Ensure the non-approver does not accidentally have the role.
        vm.assume(!I_VERIFY.hasRole(APPROVER_ROLE, nonApprover));
        vm.assume(!I_VERIFY.hasRole(APPROVER_ADMIN_ROLE, nonApprover));

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonApprover, APPROVER_ROLE)
        );
        vm.prank(nonApprover);
        I_VERIFY.approve(evidences);
    }

    /// `approve` MUST emit an `Approve` event for each evidence entry.
    function testApproveEmitsEvent(address approver, address user, bytes memory data) external {
        vm.assume(approver != address(0));
        vm.assume(user != address(0));
        vm.assume(approver != user);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.expectEmit(true, true, true, true);
        emit Verify.Approve(approver, Evidence(user, data));

        vm.prank(approver);
        I_VERIFY.approve(evidences);
    }

    /// After an account has been approved, the account MUST NOT be able to
    /// call `add` again. It MUST revert with `AlreadyExists`.
    function testAddRevertsAfterApproval(address approver, address user, bytes memory data) external {
        vm.assume(approver != address(0));
        vm.assume(user != address(0));
        vm.assume(approver != user);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(approver);
        I_VERIFY.approve(evidences);

        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_APPROVED));

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(AlreadyExists.selector));
        I_VERIFY.add(data);
    }
}
