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
import {IVerifyCallbackV1} from "rain.verify.interface/interface/IVerifyCallbackV1.sol";
import {ICloneableV2} from "rain.factory/interface/ICloneableV2.sol";
import {LibVerifyStatus} from "../src/lib/LibVerifyStatus.sol";
import {Clones} from "rain.factory/../lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

/// @dev Tracks which callback hooks were called and with what arguments.
/// Implements `IVerifyCallbackV1` directly (no access control) so the Verify
/// contract can call it without ownership setup. Suitable only for testing.
contract MockCallback is IVerifyCallbackV1 {
    /// @dev Incremented each time `afterAdd` is called.
    uint256 public afterAddCalls;
    /// @dev Incremented each time `afterApprove` is called.
    uint256 public afterApproveCalls;
    /// @dev Incremented each time `afterBan` is called.
    uint256 public afterBanCalls;
    /// @dev Incremented each time `afterRemove` is called.
    uint256 public afterRemoveCalls;

    /// @dev The `adder` from the most recent `afterAdd` call.
    address public lastAddAdder;
    /// @dev The evidences from the most recent `afterAdd` call.
    Evidence[] public lastAddEvidences;

    /// @dev The `approver` from the most recent `afterApprove` call.
    address public lastApproveApprover;
    /// @dev The evidences from the most recent `afterApprove` call.
    Evidence[] public lastApproveEvidences;

    /// @dev The `banner` from the most recent `afterBan` call.
    address public lastBanBanner;
    /// @dev The evidences from the most recent `afterBan` call.
    Evidence[] public lastBanEvidences;

    /// @dev The `remover` from the most recent `afterRemove` call.
    address public lastRemoveRemover;
    /// @dev The evidences from the most recent `afterRemove` call.
    Evidence[] public lastRemoveEvidences;

    /// @inheritdoc IVerifyCallbackV1
    function afterAdd(address adder, Evidence[] calldata evidences) external override {
        afterAddCalls++;
        lastAddAdder = adder;
        delete lastAddEvidences;
        for (uint256 i = 0; i < evidences.length; i++) {
            lastAddEvidences.push(evidences[i]);
        }
    }

    /// @inheritdoc IVerifyCallbackV1
    function afterApprove(address approver, Evidence[] calldata evidences) external override {
        afterApproveCalls++;
        lastApproveApprover = approver;
        delete lastApproveEvidences;
        for (uint256 i = 0; i < evidences.length; i++) {
            lastApproveEvidences.push(evidences[i]);
        }
    }

    /// @inheritdoc IVerifyCallbackV1
    function afterBan(address banner, Evidence[] calldata evidences) external override {
        afterBanCalls++;
        lastBanBanner = banner;
        delete lastBanEvidences;
        for (uint256 i = 0; i < evidences.length; i++) {
            lastBanEvidences.push(evidences[i]);
        }
    }

    /// @inheritdoc IVerifyCallbackV1
    function afterRemove(address remover, Evidence[] calldata evidences) external override {
        afterRemoveCalls++;
        lastRemoveRemover = remover;
        delete lastRemoveEvidences;
        for (uint256 i = 0; i < evidences.length; i++) {
            lastRemoveEvidences.push(evidences[i]);
        }
    }

    /// @dev Returns the number of evidences stored from the last `afterAdd`.
    function lastAddEvidencesLength() external view returns (uint256) {
        return lastAddEvidences.length;
    }

    /// @dev Returns the number of evidences stored from the last `afterApprove`.
    function lastApproveEvidencesLength() external view returns (uint256) {
        return lastApproveEvidences.length;
    }

    /// @dev Returns the number of evidences stored from the last `afterBan`.
    function lastBanEvidencesLength() external view returns (uint256) {
        return lastBanEvidences.length;
    }

    /// @dev Returns the number of evidences stored from the last `afterRemove`.
    function lastRemoveEvidencesLength() external view returns (uint256) {
        return lastRemoveEvidences.length;
    }
}

/// @title VerifyCallbackTest
/// @notice Tests that callback hooks on `IVerifyCallbackV1` are invoked
/// correctly after `add`, `approve`, `ban`, and `remove` actions in the
/// `Verify` contract, and that no callback is invoked when the callback
/// address is zero.
contract VerifyCallbackTest is Test {
    using LibVerifyStatus for VerifyStatus;

    address internal constant ADMIN = address(uint160(uint256(keccak256("admin"))));

    bytes32 internal constant APPROVER_ROLE = keccak256("APPROVER");
    bytes32 internal constant BANNER_ROLE = keccak256("BANNER");
    bytes32 internal constant REMOVER_ROLE = keccak256("REMOVER");

    Verify internal immutable I_IMPLEMENTATION;

    constructor() {
        I_IMPLEMENTATION = new Verify();
    }

    /// @dev Helper to deploy a fresh Verify clone with a given callback address.
    function _deployVerify(address callback) internal returns (Verify) {
        address clone = Clones.clone(address(I_IMPLEMENTATION));
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(ADMIN, callback)));
        return Verify(clone);
    }

    /// The `afterAdd` callback MUST be called when a user calls `add`.
    /// The callback receives the user as `adder` and the evidence array.
    function testCallbackOnAdd(address user, bytes memory data) external {
        vm.assume(user != address(0));

        MockCallback callback = new MockCallback();
        Verify verify = _deployVerify(address(callback));

        assertEq(callback.afterAddCalls(), 0);

        vm.prank(user);
        verify.add(data);

        assertEq(callback.afterAddCalls(), 1);
        assertEq(callback.lastAddAdder(), user);
        assertEq(callback.lastAddEvidencesLength(), 1);
        (address account, bytes memory evidenceData) = callback.lastAddEvidences(0);
        assertEq(account, user);
        assertEq(evidenceData, data);
    }

    /// The `afterAdd` and `afterApprove` callbacks MUST both be called when
    /// an approver implicitly adds and approves a NIL account. `afterAdd` is
    /// invoked for the implicit add, and `afterApprove` for the approval.
    function testCallbackOnApproveImplicitAdd(address approver, address user, bytes memory data) external {
        vm.assume(approver != address(0));
        vm.assume(user != address(0));
        vm.assume(approver != user);

        MockCallback callback = new MockCallback();
        Verify verify = _deployVerify(address(callback));

        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, approver);

        // The user is NIL, so approving triggers an implicit add.
        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(approver);
        verify.approve(evidences);

        // afterAdd called once for the implicit add.
        assertEq(callback.afterAddCalls(), 1);
        assertEq(callback.lastAddAdder(), approver);
        assertEq(callback.lastAddEvidencesLength(), 1);
        (address addAccount, bytes memory addData) = callback.lastAddEvidences(0);
        assertEq(addAccount, user);
        assertEq(addData, data);

        // afterApprove called once.
        assertEq(callback.afterApproveCalls(), 1);
        assertEq(callback.lastApproveApprover(), approver);
        assertEq(callback.lastApproveEvidencesLength(), 1);
        (address approveAccount, bytes memory approveData) = callback.lastApproveEvidences(0);
        assertEq(approveAccount, user);
        assertEq(approveData, data);
    }

    /// When an approver approves an already-added account, only `afterApprove`
    /// fires (no `afterAdd`).
    function testCallbackOnApproveAlreadyAdded(address approver, address user, bytes memory data) external {
        vm.assume(approver != address(0));
        vm.assume(user != address(0));
        vm.assume(approver != user);

        MockCallback callback = new MockCallback();
        Verify verify = _deployVerify(address(callback));

        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, approver);

        // User adds themselves first.
        vm.prank(user);
        verify.add(data);

        // Reset the add-call counter by noting it already fired once.
        assertEq(callback.afterAddCalls(), 1);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(approver);
        verify.approve(evidences);

        // No additional afterAdd call because the account was already added.
        assertEq(callback.afterAddCalls(), 1);

        // afterApprove called once.
        assertEq(callback.afterApproveCalls(), 1);
        assertEq(callback.lastApproveApprover(), approver);
        assertEq(callback.lastApproveEvidencesLength(), 1);
        (address approveAccount, bytes memory approveData) = callback.lastApproveEvidences(0);
        assertEq(approveAccount, user);
        assertEq(approveData, data);
    }

    /// The `afterAdd` and `afterBan` callbacks MUST both be called when a
    /// banner bans a NIL account (implicit add+ban).
    function testCallbackOnBanImplicitAdd(address banner, address user, bytes memory data) external {
        vm.assume(banner != address(0));
        vm.assume(user != address(0));
        vm.assume(banner != user);

        MockCallback callback = new MockCallback();
        Verify verify = _deployVerify(address(callback));

        vm.prank(ADMIN);
        verify.grantRole(BANNER_ROLE, banner);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(banner);
        verify.ban(evidences);

        // afterAdd called once for the implicit add.
        assertEq(callback.afterAddCalls(), 1);
        assertEq(callback.lastAddAdder(), banner);
        assertEq(callback.lastAddEvidencesLength(), 1);
        (address addAccount, bytes memory addData) = callback.lastAddEvidences(0);
        assertEq(addAccount, user);
        assertEq(addData, data);

        // afterBan called once.
        assertEq(callback.afterBanCalls(), 1);
        assertEq(callback.lastBanBanner(), banner);
        assertEq(callback.lastBanEvidencesLength(), 1);
        (address banAccount, bytes memory banData) = callback.lastBanEvidences(0);
        assertEq(banAccount, user);
        assertEq(banData, data);
    }

    /// When a banner bans an already-added account, only `afterBan` fires
    /// (no additional `afterAdd`).
    function testCallbackOnBanAlreadyAdded(address banner, address user, bytes memory data) external {
        vm.assume(banner != address(0));
        vm.assume(user != address(0));
        vm.assume(banner != user);

        MockCallback callback = new MockCallback();
        Verify verify = _deployVerify(address(callback));

        vm.prank(ADMIN);
        verify.grantRole(BANNER_ROLE, banner);

        // User adds themselves first.
        vm.prank(user);
        verify.add(data);
        assertEq(callback.afterAddCalls(), 1);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(banner);
        verify.ban(evidences);

        // No additional afterAdd since account was already added.
        assertEq(callback.afterAddCalls(), 1);

        // afterBan called once.
        assertEq(callback.afterBanCalls(), 1);
        assertEq(callback.lastBanBanner(), banner);
    }

    /// The `afterRemove` callback MUST be called when a remover removes an
    /// added account.
    function testCallbackOnRemove(address remover, address user, bytes memory data) external {
        vm.assume(remover != address(0));
        vm.assume(user != address(0));
        vm.assume(remover != user);

        MockCallback callback = new MockCallback();
        Verify verify = _deployVerify(address(callback));

        vm.prank(ADMIN);
        verify.grantRole(REMOVER_ROLE, remover);

        vm.prank(user);
        verify.add(data);

        assertEq(callback.afterRemoveCalls(), 0);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(remover);
        verify.remove(evidences);

        assertEq(callback.afterRemoveCalls(), 1);
        assertEq(callback.lastRemoveRemover(), remover);
        assertEq(callback.lastRemoveEvidencesLength(), 1);
        (address removeAccount, bytes memory removeData) = callback.lastRemoveEvidences(0);
        assertEq(removeAccount, user);
        assertEq(removeData, data);
    }

    /// When the callback address is zero, no callback hooks are invoked.
    /// `add` MUST succeed without reverting and no external call is made.
    function testNoCallbackWhenZeroAdd(address user, bytes memory data) external {
        vm.assume(user != address(0));

        Verify verify = _deployVerify(address(0));

        vm.prank(user);
        verify.add(data);

        assertTrue(verify.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_ADDED));
    }

    /// When the callback address is zero, `approve` MUST succeed without
    /// reverting and no external call is made.
    function testNoCallbackWhenZeroApprove(address approver, address user, bytes memory data) external {
        vm.assume(approver != address(0));
        vm.assume(user != address(0));
        vm.assume(approver != user);

        Verify verify = _deployVerify(address(0));

        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, approver);

        vm.prank(user);
        verify.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(approver);
        verify.approve(evidences);

        assertTrue(verify.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_APPROVED));
    }

    /// When the callback address is zero, `ban` MUST succeed without
    /// reverting and no external call is made.
    function testNoCallbackWhenZeroBan(address banner, address user, bytes memory data) external {
        vm.assume(banner != address(0));
        vm.assume(user != address(0));
        vm.assume(banner != user);

        Verify verify = _deployVerify(address(0));

        vm.prank(ADMIN);
        verify.grantRole(BANNER_ROLE, banner);

        vm.prank(user);
        verify.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(banner);
        verify.ban(evidences);

        assertTrue(verify.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_BANNED));
    }

    /// When the callback address is zero, `remove` MUST succeed without
    /// reverting and no external call is made.
    function testNoCallbackWhenZeroRemove(address remover, address user, bytes memory data) external {
        vm.assume(remover != address(0));
        vm.assume(user != address(0));
        vm.assume(remover != user);

        Verify verify = _deployVerify(address(0));

        vm.prank(ADMIN);
        verify.grantRole(REMOVER_ROLE, remover);

        vm.prank(user);
        verify.add(data);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(remover);
        verify.remove(evidences);

        assertTrue(verify.accountStatusAtTime(user, block.timestamp).eq(VERIFY_STATUS_NIL));
    }

    /// The `afterRemove` callback MUST NOT fire when removing an account that
    /// was never added (NIL). The remove call succeeds but the callback is
    /// skipped because there is no state to clear.
    function testCallbackNotFiredOnRemoveNilAccount(address remover, address user, bytes memory data) external {
        vm.assume(remover != address(0));
        vm.assume(user != address(0));
        vm.assume(remover != user);

        MockCallback callback = new MockCallback();
        Verify verify = _deployVerify(address(callback));

        vm.prank(ADMIN);
        verify.grantRole(REMOVER_ROLE, remover);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(user, data);

        vm.prank(remover);
        verify.remove(evidences);

        // No state was cleared, so afterRemove should not fire.
        assertEq(callback.afterRemoveCalls(), 0);
    }

    /// Duplicate approvals in a batch MUST deduplicate callbacks. If the same
    /// account appears twice, `afterApprove` receives only one evidence entry
    /// (the first non-duplicate) while the `Approve` event is still emitted
    /// for both.
    function testCallbackDeduplicatesApprove(address approver, address user, bytes memory data) external {
        vm.assume(approver != address(0));
        vm.assume(user != address(0));
        vm.assume(approver != user);

        MockCallback callback = new MockCallback();
        Verify verify = _deployVerify(address(callback));

        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, approver);

        // Send two evidences for the same account.
        Evidence[] memory evidences = new Evidence[](2);
        evidences[0] = Evidence(user, data);
        evidences[1] = Evidence(user, data);

        vm.prank(approver);
        verify.approve(evidences);

        // afterAdd called once (implicit add deduped to one entry).
        assertEq(callback.afterAddCalls(), 1);
        assertEq(callback.lastAddEvidencesLength(), 1);

        // afterApprove called once with only one entry (deduped).
        assertEq(callback.afterApproveCalls(), 1);
        assertEq(callback.lastApproveEvidencesLength(), 1);
    }

    /// Duplicate bans in a batch MUST deduplicate callbacks. If the same
    /// account appears twice, `afterBan` receives only one evidence entry
    /// while the `Ban` event is still emitted for both.
    function testCallbackDeduplicatesBan(address banner, address user, bytes memory data) external {
        vm.assume(banner != address(0));
        vm.assume(user != address(0));
        vm.assume(banner != user);

        MockCallback callback = new MockCallback();
        Verify verify = _deployVerify(address(callback));

        vm.prank(ADMIN);
        verify.grantRole(BANNER_ROLE, banner);

        // Send two evidences for the same account.
        Evidence[] memory evidences = new Evidence[](2);
        evidences[0] = Evidence(user, data);
        evidences[1] = Evidence(user, data);

        vm.prank(banner);
        verify.ban(evidences);

        // afterAdd called once (implicit add deduped to one entry).
        assertEq(callback.afterAddCalls(), 1);
        assertEq(callback.lastAddEvidencesLength(), 1);

        // afterBan called once with only one entry (deduped).
        assertEq(callback.afterBanCalls(), 1);
        assertEq(callback.lastBanEvidencesLength(), 1);
    }
}
