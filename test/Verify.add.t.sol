// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
import {Verify, VerifyConfig, State} from "../src/concrete/Verify.sol";
import {
    Evidence,
    VerifyStatus,
    VERIFY_STATUS_NIL,
    VERIFY_STATUS_ADDED,
    VERIFY_STATUS_APPROVED,
    VERIFY_STATUS_BANNED
} from "rain.verify.interface/interface/IVerifyV1.sol";
import {ICloneableV2} from "rain.factory/interface/ICloneableV2.sol";
import {AlreadyExists} from "../src/err/ErrVerify.sol";
import {LibVerifyStatus} from "../src/lib/LibVerifyStatus.sol";
import {Clones} from "rain.factory/../lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

/// @title VerifyAddTest
/// @notice Tests that `add` is only accessible from NIL and ADDED states.
/// Approved and banned accounts MUST revert with `AlreadyExists`.
contract VerifyAddTest is Test {
    using LibVerifyStatus for VerifyStatus;

    Verify internal immutable I_VERIFY;

    address internal constant ADMIN = address(uint160(uint256(keccak256("admin"))));

    bytes32 internal constant APPROVER_ROLE = keccak256("APPROVER");
    bytes32 internal constant BANNER_ROLE = keccak256("BANNER");

    constructor() {
        Verify implementation = new Verify();
        address clone = Clones.clone(address(implementation));
        I_VERIFY = Verify(clone);
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(ADMIN, address(0))));
    }

    /// A NIL account can add itself with arbitrary evidence.
    function testAddFromNIL(address user, bytes memory data) external {
        vm.assume(user != address(0));
        vm.prank(user);
        I_VERIFY.add(data);
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_ADDED));
    }

    /// An ADDED account can resubmit evidence without changing state.
    function testAddFromADDED(address user, bytes memory data0, bytes memory data1) external {
        vm.assume(user != address(0));

        vm.prank(user);
        I_VERIFY.add(data0);
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_ADDED));

        vm.prank(user);
        I_VERIFY.add(data1);
        assertTrue(I_VERIFY.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_ADDED));
    }

    /// An APPROVED account MUST NOT be able to add. Reverts `AlreadyExists`.
    function testAddFromAPPROVED(address user, address approver, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(approver != address(0));
        vm.assume(approver != user);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(approver);
        I_VERIFY.approve(evidences);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(AlreadyExists.selector));
        I_VERIFY.add(data);
    }

    /// A BANNED account MUST NOT be able to add. Reverts `AlreadyExists`.
    function testAddFromBANNED(address user, address banner, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(banner != address(0));
        vm.assume(banner != user);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(BANNER_ROLE, banner);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(banner);
        I_VERIFY.ban(evidences);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(AlreadyExists.selector));
        I_VERIFY.add(data);
    }
}
