// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test, Vm} from "forge-std/Test.sol";
import {Verify, VerifyConfig, State} from "../../src/concrete/Verify.sol";
import {Evidence, VerifyStatus} from "rain.verify.interface/interface/IVerifyV1.sol";
import {ICloneableV2} from "rain.factory/interface/ICloneableV2.sol";
import {NotApproved} from "../../src/err/ErrVerify.sol";
import {LibVerifyStatus} from "../../src/lib/LibVerifyStatus.sol";
import {Clones} from "rain.factory/../lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

/// @title VerifyRequestApproveTest
/// @notice Tests for `requestApprove` covering event emission, state
/// preservation across repeated calls, and independence between different
/// signers.
contract VerifyRequestApproveTest is Test {
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

    /// Helper to add and approve an account so it satisfies the `onlyApproved`
    /// modifier required by `requestApprove`.
    /// @param approver The address with the APPROVER role.
    /// @param account The address to add and approve.
    /// @param data The evidence data used for add and approve.
    function _addAndApprove(address approver, address account, bytes memory data) internal {
        vm.prank(account);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(account, data);
        vm.prank(approver);
        I_VERIFY.approve(evidences);
    }

    /// Any approved account can call `requestApprove` and it MUST emit a
    /// `RequestApprove` event with the caller as `sender` and the correct
    /// `Evidence` struct.
    function testRequestApproveEmitsEvent(
        address approver,
        address signer,
        address subject,
        bytes memory addData,
        bytes memory requestData
    ) external {
        vm.assume(approver != address(0));
        vm.assume(signer != address(0));
        vm.assume(subject != address(0));
        vm.assume(approver != signer);
        vm.assume(approver != subject);
        vm.assume(signer != subject);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);

        _addAndApprove(approver, signer, addData);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(subject, requestData);

        vm.expectEmit(true, true, true, true);
        emit Verify.RequestApprove(signer, Evidence(subject, requestData));

        vm.prank(signer);
        I_VERIFY.requestApprove(evidences);
    }

    /// Re-adding evidence via `requestApprove` MUST NOT override the caller's
    /// own `State`. The `addedSince`, `approvedSince`, and `bannedSince`
    /// fields MUST be identical before and after the second call.
    function testRequestApproveDoesNotOverrideState(
        address approver,
        address signer,
        address subject,
        bytes memory addData,
        bytes memory requestData0,
        bytes memory requestData1
    ) external {
        vm.assume(approver != address(0));
        vm.assume(signer != address(0));
        vm.assume(subject != address(0));
        vm.assume(approver != signer);
        vm.assume(approver != subject);
        vm.assume(signer != subject);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);

        _addAndApprove(approver, signer, addData);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(subject, requestData0);

        vm.prank(signer);
        I_VERIFY.requestApprove(evidences);

        State memory stateAfterFirst = I_VERIFY.state(signer);

        evidences[0] = Evidence(subject, requestData1);

        vm.prank(signer);
        I_VERIFY.requestApprove(evidences);

        State memory stateAfterSecond = I_VERIFY.state(signer);

        assertEq(stateAfterFirst.addedSince, stateAfterSecond.addedSince, "addedSince changed");
        assertEq(stateAfterFirst.approvedSince, stateAfterSecond.approvedSince, "approvedSince changed");
        assertEq(stateAfterFirst.bannedSince, stateAfterSecond.bannedSince, "bannedSince changed");
    }

    /// Different approved signers can independently call `requestApprove`
    /// without affecting each other's `State`. After signer2 submits evidence,
    /// signer1's `addedSince`, `approvedSince`, and `bannedSince` MUST remain
    /// unchanged.
    function testRequestApproveIndependentSigners(
        address approver,
        address signer1,
        address signer2,
        address subject,
        bytes memory addData1,
        bytes memory addData2,
        bytes memory requestData1,
        bytes memory requestData2
    ) external {
        vm.assume(approver != address(0));
        vm.assume(signer1 != address(0));
        vm.assume(signer2 != address(0));
        vm.assume(subject != address(0));
        vm.assume(approver != signer1);
        vm.assume(approver != signer2);
        vm.assume(approver != subject);
        vm.assume(signer1 != signer2);
        vm.assume(signer1 != subject);
        vm.assume(signer2 != subject);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(APPROVER_ROLE, approver);

        _addAndApprove(approver, signer1, addData1);
        _addAndApprove(approver, signer2, addData2);

        // signer1 submits evidence.
        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(subject, requestData1);

        vm.prank(signer1);
        I_VERIFY.requestApprove(evidences);

        State memory signer1StateAfterOwnRequest = I_VERIFY.state(signer1);

        // signer2 submits evidence independently.
        evidences[0] = Evidence(subject, requestData2);

        vm.prank(signer2);
        I_VERIFY.requestApprove(evidences);

        // signer1's state MUST be unchanged after signer2's call.
        State memory signer1StateAfterSigner2Request = I_VERIFY.state(signer1);

        assertEq(
            signer1StateAfterOwnRequest.addedSince,
            signer1StateAfterSigner2Request.addedSince,
            "signer1 addedSince changed after signer2 request"
        );
        assertEq(
            signer1StateAfterOwnRequest.approvedSince,
            signer1StateAfterSigner2Request.approvedSince,
            "signer1 approvedSince changed after signer2 request"
        );
        assertEq(
            signer1StateAfterOwnRequest.bannedSince,
            signer1StateAfterSigner2Request.bannedSince,
            "signer1 bannedSince changed after signer2 request"
        );
    }

    /// A NIL account MUST NOT be able to call `requestApprove`.
    function testRequestApproveNilReverts(address user, address subject, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(subject != address(0));

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(subject, data);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(NotApproved.selector));
        I_VERIFY.requestApprove(evidences);
    }

    /// An ADDED (but not approved) account MUST NOT be able to call
    /// `requestApprove`.
    function testRequestApproveAddedReverts(address user, address subject, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(subject != address(0));
        vm.assume(user != subject);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(subject, data);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(NotApproved.selector));
        I_VERIFY.requestApprove(evidences);
    }

    /// A BANNED account MUST NOT be able to call `requestApprove`.
    function testRequestApproveBannedReverts(address user, address banner, bytes memory data) external {
        vm.assume(user != address(0));
        vm.assume(banner != address(0));
        vm.assume(user != banner);

        vm.prank(ADMIN);
        I_VERIFY.grantRole(BANNER_ROLE, banner);

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory banEvidence = new Evidence[](1);
        banEvidence[0] = Evidence(user, data);
        vm.prank(banner);
        I_VERIFY.ban(banEvidence);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(NotApproved.selector));
        I_VERIFY.requestApprove(evidences);
    }
}
