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
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @title VerifyBanTest
/// @notice Tests for the `ban` function on `Verify`. Covers preemptive banning
/// of NIL accounts (implicit add+ban), role separation (banner cannot approve
/// or remove), role enforcement (only BANNER can ban), event emissions, and
/// post-ban account status.
contract VerifyBanTest is Test {
    using LibVerifyStatus for VerifyStatus;

    Verify internal immutable I_VERIFY;

    address internal constant ADMIN = address(uint160(uint256(keccak256("admin"))));

    bytes32 internal constant APPROVER_ROLE = keccak256("APPROVER");
    bytes32 internal constant BANNER_ROLE = keccak256("BANNER");
    bytes32 internal constant REMOVER_ROLE = keccak256("REMOVER");

    constructor() {
        Verify implementation = new Verify();
        address clone = Clones.clone(address(implementation));
        I_VERIFY = Verify(clone);
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(ADMIN, address(0))));
    }

    /// A banner can preemptively ban a NIL account. The contract implicitly
    /// adds the account before banning it, so the final status is BANNED.
    function testBanNILAccount(address banner, address account, bytes memory data) external {
        vm.assume(banner != address(0));
        vm.assume(account != address(0));
        vm.assume(banner != account);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(BANNER_ROLE, banner);

        // Account starts as NIL.
        assertTrue(I_VERIFY.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_NIL));

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(account, data);
        vm.prank(banner);
        I_VERIFY.ban(evidences);

        // After preemptive ban, account status is BANNED.
        assertTrue(I_VERIFY.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_BANNED));
    }

    /// A banner MUST NOT be able to call `approve`. The BANNER role does not
    /// grant APPROVER privileges.
    function testBannerCannotApprove(address banner, address account, bytes memory data) external {
        vm.assume(banner != address(0));
        vm.assume(account != address(0));
        vm.assume(banner != account);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(BANNER_ROLE, banner);

        vm.prank(account);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(account, data);

        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, banner, APPROVER_ROLE));
        vm.prank(banner);
        I_VERIFY.approve(evidences);
    }

    /// A banner MUST NOT be able to call `remove`. The BANNER role does not
    /// grant REMOVER privileges.
    function testBannerCannotRemove(address banner, address account, bytes memory data) external {
        vm.assume(banner != address(0));
        vm.assume(account != address(0));
        vm.assume(banner != account);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(BANNER_ROLE, banner);

        vm.prank(account);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(account, data);

        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, banner, REMOVER_ROLE));
        vm.prank(banner);
        I_VERIFY.remove(evidences);
    }

    /// Only an account with the BANNER role can call `ban`. An arbitrary
    /// non-banner address MUST be rejected.
    function testOnlyBannerCanBan(address nonBanner, address account, bytes memory data) external {
        vm.assume(nonBanner != address(0));
        vm.assume(account != address(0));
        vm.assume(nonBanner != account);
        // Ensure the address does not accidentally hold the BANNER role.
        vm.assume(!I_VERIFY.hasRole(BANNER_ROLE, nonBanner));

        vm.prank(account);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(account, data);

        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonBanner, BANNER_ROLE));
        vm.prank(nonBanner);
        I_VERIFY.ban(evidences);
    }

    /// Banning an added account emits the `Ban` event with the correct sender
    /// and evidence.
    function testBanEmitsEvent(address banner, address account, bytes memory data) external {
        vm.assume(banner != address(0));
        vm.assume(account != address(0));
        vm.assume(banner != account);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(BANNER_ROLE, banner);

        vm.prank(account);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(account, data);

        vm.expectEmit(true, true, true, true);
        emit Verify.Ban(banner, Evidence(account, data));

        vm.prank(banner);
        I_VERIFY.ban(evidences);
    }

    /// After banning a previously added account, the account status at the
    /// current timestamp MUST be BANNED.
    function testBanStatusIsBanned(address banner, address account, bytes memory data) external {
        vm.assume(banner != address(0));
        vm.assume(account != address(0));
        vm.assume(banner != account);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(BANNER_ROLE, banner);

        vm.prank(account);
        I_VERIFY.add(data);
        assertTrue(I_VERIFY.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_ADDED));

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(account, data);
        vm.prank(banner);
        I_VERIFY.ban(evidences);

        assertTrue(I_VERIFY.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_BANNED));
    }
}
