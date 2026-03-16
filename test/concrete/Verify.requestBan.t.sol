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
import {ICloneableV2} from "rain.factory/interface/ICloneableV2.sol";
import {NotApproved} from "../../src/err/ErrVerify.sol";
import {LibVerifyStatus} from "../../src/lib/LibVerifyStatus.sol";
import {Clones} from "rain.factory/../lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

/// @title VerifyRequestBanTest
/// @notice Tests for `requestBan` covering access control (only approved
/// accounts may request a ban) and correct `RequestBan` event emission.
contract VerifyRequestBanTest is Test {
    using LibVerifyStatus for VerifyStatus;

    Verify internal immutable I_VERIFY;

    address internal constant ADMIN = address(uint160(uint256(keccak256("admin"))));

    bytes32 internal constant APPROVER_ROLE = keccak256("APPROVER");

    constructor() {
        Verify implementation = new Verify();
        address clone = Clones.clone(address(implementation));
        I_VERIFY = Verify(clone);
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(ADMIN, address(0))));
    }

    /// An unapproved account MUST NOT be able to request a ban. The
    /// `onlyApproved` modifier MUST revert with `NotApproved`.
    function testRequestBanUnapprovedReverts(address user, address target, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(target != address(0));
        vm.assume(user != target);

        // user is NIL (never added), so not approved.
        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(target, data);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(NotApproved.selector));
        I_VERIFY.requestBan(evidences);
    }

    /// An approved account can request a ban. The call MUST emit a
    /// `RequestBan` event with the caller as `sender` and the correct
    /// `Evidence`.
    function testRequestBanApprovedEmitsEvent(address approver, address requester, address target, bytes memory data)
        external
    {
        vm.assume(approver != address(0));
        vm.assume(requester != address(0));
        vm.assume(target != address(0));
        vm.assume(approver != requester);
        vm.assume(requester != target);

        // Grant approver role so we can approve the requester.
        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);

        // Requester adds themselves.
        vm.prank(requester);
        I_VERIFY.add(data);

        // Approver approves the requester.
        Evidence[] memory approveEvidences = new Evidence[](1);
        approveEvidences[0] = Evidence(requester, data);
        vm.prank(approver);
        I_VERIFY.approve(approveEvidences);

        assertTrue(I_VERIFY.accountStatusAtTime(requester, block.timestamp).eq(VERIFY_STATUS_APPROVED));

        // Approved requester requests a ban on target.
        Evidence[] memory banEvidences = new Evidence[](1);
        banEvidences[0] = Evidence(target, data);

        vm.expectEmit(true, true, true, true);
        emit Verify.RequestBan(requester, Evidence(target, data));

        vm.prank(requester);
        I_VERIFY.requestBan(banEvidences);
    }
}
