// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
import {Verify, VerifyConfig, State} from "../src/concrete/Verify.sol";
import {Evidence, VerifyStatus} from "rain.verify.interface/interface/IVerifyV1.sol";
import {ICloneableV2} from "rain.factory/interface/ICloneableV2.sol";
import {ZeroAdmin} from "../src/err/ErrVerify.sol";
import {LibVerifyStatus} from "../src/lib/LibVerifyStatus.sol";
import {Clones} from "rain.factory/../lib/openzeppelin-contracts/contracts/proxy/Clones.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @title VerifyAdminTest
/// @notice Tests for admin role delegation, renunciation, and the ability of
/// delegated admins to grant both admin and non-admin roles. Covers the full
/// admin delegation chain, post-renounce lockout, and zero-admin revert.
contract VerifyAdminTest is Test {
    using LibVerifyStatus for VerifyStatus;

    Verify internal immutable I_VERIFY;
    Verify internal immutable I_IMPLEMENTATION;

    address internal constant ADMIN = address(uint160(uint256(keccak256("admin"))));

    bytes32 internal constant APPROVER_ADMIN_ROLE = keccak256("APPROVER_ADMIN");
    bytes32 internal constant APPROVER_ROLE = keccak256("APPROVER");
    bytes32 internal constant REMOVER_ADMIN_ROLE = keccak256("REMOVER_ADMIN");
    bytes32 internal constant REMOVER_ROLE = keccak256("REMOVER");
    bytes32 internal constant BANNER_ADMIN_ROLE = keccak256("BANNER_ADMIN");
    bytes32 internal constant BANNER_ROLE = keccak256("BANNER");

    constructor() {
        I_IMPLEMENTATION = new Verify();
        address clone = Clones.clone(address(I_IMPLEMENTATION));
        I_VERIFY = Verify(clone);
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(ADMIN, address(0))));
    }

    /// ADMIN can grant APPROVER_ADMIN to another address, and that delegated
    /// admin can in turn grant APPROVER_ADMIN to a third address. This tests
    /// that the self-admin relationship on APPROVER_ADMIN allows an unbounded
    /// delegation chain.
    function testAdminDelegationChain(address aprAdmin0, address aprAdmin1) external {
        vm.assume(aprAdmin0 != address(0));
        vm.assume(aprAdmin1 != address(0));
        vm.assume(aprAdmin0 != ADMIN);
        vm.assume(aprAdmin1 != ADMIN);
        vm.assume(aprAdmin0 != aprAdmin1);

        // ADMIN grants APPROVER_ADMIN to aprAdmin0.
        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ADMIN_ROLE, aprAdmin0);
        assertTrue(I_VERIFY.hasRole(APPROVER_ADMIN_ROLE, aprAdmin0));

        // aprAdmin0 can grant APPROVER_ADMIN to aprAdmin1 because
        // APPROVER_ADMIN is its own role admin (self-admin relationship).
        vm.prank(aprAdmin0);
        I_VERIFY.grantRole(APPROVER_ADMIN_ROLE, aprAdmin1);
        assertTrue(I_VERIFY.hasRole(APPROVER_ADMIN_ROLE, aprAdmin1));
    }

    /// ADMIN delegates all three admin roles, then renounces them. After
    /// renouncing, ADMIN MUST no longer be able to grant any admin role.
    function testAdminRenounceLocksOutGranting(
        address aprAdmin,
        address remAdmin,
        address banAdmin,
        address target
    ) external {
        vm.assume(aprAdmin != address(0));
        vm.assume(remAdmin != address(0));
        vm.assume(banAdmin != address(0));
        vm.assume(target != address(0));
        vm.assume(aprAdmin != ADMIN);
        vm.assume(remAdmin != ADMIN);
        vm.assume(banAdmin != ADMIN);
        vm.assume(target != ADMIN);

        // ADMIN delegates each admin role to a separate address.
        vm.startPrank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ADMIN_ROLE, aprAdmin);
        I_VERIFY.grantRole(REMOVER_ADMIN_ROLE, remAdmin);
        I_VERIFY.grantRole(BANNER_ADMIN_ROLE, banAdmin);

        // ADMIN renounces all three admin roles from itself.
        I_VERIFY.renounceRole(APPROVER_ADMIN_ROLE, ADMIN);
        I_VERIFY.renounceRole(REMOVER_ADMIN_ROLE, ADMIN);
        I_VERIFY.renounceRole(BANNER_ADMIN_ROLE, ADMIN);
        vm.stopPrank();

        assertFalse(I_VERIFY.hasRole(APPROVER_ADMIN_ROLE, ADMIN));
        assertFalse(I_VERIFY.hasRole(REMOVER_ADMIN_ROLE, ADMIN));
        assertFalse(I_VERIFY.hasRole(BANNER_ADMIN_ROLE, ADMIN));

        // ADMIN can no longer grant APPROVER_ADMIN.
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, ADMIN, APPROVER_ADMIN_ROLE));
        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ADMIN_ROLE, target);

        // ADMIN can no longer grant REMOVER_ADMIN.
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, ADMIN, REMOVER_ADMIN_ROLE));
        vm.prank(ADMIN);
        I_VERIFY.grantRole(REMOVER_ADMIN_ROLE, target);

        // ADMIN can no longer grant BANNER_ADMIN.
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, ADMIN, BANNER_ADMIN_ROLE));
        vm.prank(ADMIN);
        I_VERIFY.grantRole(BANNER_ADMIN_ROLE, target);
    }

    /// A delegated APPROVER_ADMIN can grant the APPROVER (non-admin) role to
    /// any address, because APPROVER_ADMIN is the role admin for APPROVER.
    function testDelegatedApproverAdminCanGrantApprover(address aprAdmin, address approver) external {
        vm.assume(aprAdmin != address(0));
        vm.assume(approver != address(0));
        vm.assume(aprAdmin != ADMIN);
        vm.assume(approver != ADMIN);
        vm.assume(aprAdmin != approver);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ADMIN_ROLE, aprAdmin);

        vm.prank(aprAdmin);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);
        assertTrue(I_VERIFY.hasRole(APPROVER_ROLE, approver));
    }

    /// A delegated REMOVER_ADMIN can grant the REMOVER (non-admin) role to
    /// any address, because REMOVER_ADMIN is the role admin for REMOVER.
    function testDelegatedRemoverAdminCanGrantRemover(address remAdmin, address remover) external {
        vm.assume(remAdmin != address(0));
        vm.assume(remover != address(0));
        vm.assume(remAdmin != ADMIN);
        vm.assume(remover != ADMIN);
        vm.assume(remAdmin != remover);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(REMOVER_ADMIN_ROLE, remAdmin);

        vm.prank(remAdmin);
        I_VERIFY.grantRole(REMOVER_ROLE, remover);
        assertTrue(I_VERIFY.hasRole(REMOVER_ROLE, remover));
    }

    /// A delegated BANNER_ADMIN can grant the BANNER (non-admin) role to
    /// any address, because BANNER_ADMIN is the role admin for BANNER.
    function testDelegatedBannerAdminCanGrantBanner(address banAdmin, address banner) external {
        vm.assume(banAdmin != address(0));
        vm.assume(banner != address(0));
        vm.assume(banAdmin != ADMIN);
        vm.assume(banner != ADMIN);
        vm.assume(banAdmin != banner);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(BANNER_ADMIN_ROLE, banAdmin);

        vm.prank(banAdmin);
        I_VERIFY.grantRole(BANNER_ROLE, banner);
        assertTrue(I_VERIFY.hasRole(BANNER_ROLE, banner));
    }

    /// Initializing a Verify clone with a zero admin address MUST revert with
    /// `ZeroAdmin`. Included for completeness alongside the construction tests.
    function testZeroAdminReverts(address callback) external {
        address clone = Clones.clone(address(I_IMPLEMENTATION));
        vm.expectRevert(abi.encodeWithSelector(ZeroAdmin.selector));
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(address(0), callback)));
    }
}
