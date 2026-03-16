// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
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
import {UnknownAccount} from "../../src/err/ErrVerify.sol";
import {LibVerifyStatus} from "../../src/lib/LibVerifyStatus.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

/// @title VerifyRequestRemoveTest
/// @notice Tests that `requestRemove` is accessible from any non-NIL state
/// (ADDED, APPROVED, BANNED) and reverts for NIL accounts. This ensures
/// banned accounts have an on-chain appeal mechanism to request removal.
contract VerifyRequestRemoveTest is Test {
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

    /// A NIL account MUST NOT be able to request removal. Reverts
    /// `UnknownAccount`.
    function testRequestRemoveFromNIL(address user, bytes memory data) external {
        vm.assume(user != address(0));
        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(UnknownAccount.selector));
        I_VERIFY.requestRemove(evidences);
    }

    /// An ADDED account can request removal.
    function testRequestRemoveFromADDED(address user, bytes memory data) external {
        vm.assume(user != address(0));

        vm.prank(user);
        I_VERIFY.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);
        vm.prank(user);
        I_VERIFY.requestRemove(evidences);
    }

    /// An APPROVED account can request removal.
    function testRequestRemoveFromAPPROVED(address user, address approver, bytes memory data) external {
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

        Evidence[] memory removeEvidences = new Evidence[](1);
        removeEvidences[0] = Evidence(user, data);
        vm.prank(user);
        I_VERIFY.requestRemove(removeEvidences);
    }

    /// A BANNED account can request removal as an appeal mechanism.
    function testRequestRemoveFromBANNED(address user, address banner, bytes memory data) external {
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

        Evidence[] memory removeEvidences = new Evidence[](1);
        removeEvidences[0] = Evidence(user, data);
        vm.prank(user);
        I_VERIFY.requestRemove(removeEvidences);
    }
}
