// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test, Vm} from "forge-std-1.16.1/src/Test.sol";
import {AutoApprove, AutoApproveConfig, BadEvidenceLength} from "../../src/concrete/AutoApprove.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.1/access/Ownable.sol";
import {Initializable} from "@openzeppelin-contracts-5.6.1/proxy/utils/Initializable.sol";
import {Verify, VerifyConfig} from "../../src/concrete/Verify.sol";
import {
    Evidence,
    VerifyStatus,
    VERIFY_STATUS_NIL,
    VERIFY_STATUS_ADDED,
    VERIFY_STATUS_APPROVED,
    VERIFY_STATUS_BANNED
} from "rain-verify-interface-0.1.0/src/interface/IVerifyV1.sol";
import {ICloneableV2, ICLONEABLE_V2_SUCCESS} from "rain-factory-0.1.1/src/interface/ICloneableV2.sol";
import {
    IInterpreterV4,
    StackItem,
    SourceIndexV2,
    DEFAULT_STATE_NAMESPACE
} from "rain-interpreter-interface-0.1.0/src/interface/IInterpreterV4.sol";
import {IInterpreterStoreV3} from "rain-interpreter-interface-0.1.0/src/interface/IInterpreterStoreV3.sol";
import {EvaluableV4} from "rain-interpreter-interface-0.1.0/src/interface/IInterpreterCallerV4.sol";
import {MockInterpreterV4} from "../mock/MockInterpreterV4.sol";
import {MockInterpreterStoreV3} from "../mock/MockInterpreterStoreV3.sol";
import {LibVerifyStatus} from "../../src/lib/LibVerifyStatus.sol";
import {Clones} from "@openzeppelin-contracts-5.6.1/proxy/Clones.sol";

/// @title AutoApproveTest
/// @notice Tests for the `AutoApprove` callback contract, covering
/// construction, auto-approval logic, denial, evidence-length filtering,
/// and full integration with the `Verify` contract.
contract AutoApproveTest is Test {
    using LibVerifyStatus for VerifyStatus;

    address internal constant ADMIN = address(uint160(uint256(keccak256("admin"))));

    bytes32 internal constant APPROVER_ROLE = keccak256("APPROVER");

    Verify internal immutable I_VERIFY_IMPLEMENTATION;
    AutoApprove internal immutable I_AUTO_APPROVE_IMPLEMENTATION;

    constructor() {
        I_VERIFY_IMPLEMENTATION = new Verify();
        I_AUTO_APPROVE_IMPLEMENTATION = new AutoApprove();
    }

    /// @dev Helper to deploy a fresh AutoApprove clone with the given owner and
    /// evaluable configuration.
    function _deployAutoApprove(address owner, EvaluableV4 memory evaluable) internal returns (AutoApprove) {
        address clone = Clones.clone(address(I_AUTO_APPROVE_IMPLEMENTATION));
        AutoApproveConfig memory config = AutoApproveConfig({owner: owner, evaluable: evaluable});
        ICloneableV2(clone).initialize(abi.encode(config));
        return AutoApprove(clone);
    }

    /// @dev Helper to deploy a fresh Verify clone with the given admin and
    /// callback address.
    function _deployVerify(address admin, address callback) internal returns (Verify) {
        address clone = Clones.clone(address(I_VERIFY_IMPLEMENTATION));
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(admin, callback)));
        return Verify(clone);
    }

    /// @dev Helper to deploy AutoApprove + Verify wired together with a
    /// default mock evaluable.
    function _deployIntegration() internal returns (AutoApprove autoApprove, Verify verify) {
        (MockInterpreterV4 interpreter, EvaluableV4 memory evaluable) = _createMockEvaluable();
        interpreter.setReturnValue(StackItem.wrap(bytes32(uint256(1))));

        address autoApproveClone = Clones.clone(address(I_AUTO_APPROVE_IMPLEMENTATION));
        AutoApproveConfig memory config = AutoApproveConfig({owner: address(this), evaluable: evaluable});
        ICloneableV2(autoApproveClone).initialize(abi.encode(config));
        autoApprove = AutoApprove(autoApproveClone);

        verify = _deployVerify(ADMIN, address(autoApprove));
        autoApprove.transferOwnership(address(verify));

        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, address(autoApprove));
    }

    /// @dev Helper to create a standard mock evaluable (interpreter + store).
    function _createMockEvaluable() internal returns (MockInterpreterV4 interpreter, EvaluableV4 memory evaluable) {
        interpreter = new MockInterpreterV4();
        MockInterpreterStoreV3 store = new MockInterpreterStoreV3();
        evaluable = EvaluableV4({
            interpreter: IInterpreterV4(address(interpreter)),
            store: IInterpreterStoreV3(address(store)),
            bytecode: hex"01"
        });
    }

    /// AutoApprove initializes successfully and returns ICLONEABLE_V2_SUCCESS.
    /// The owner is set to the provided address and the evaluable is stored.
    function testConstruction(address owner) external {
        vm.assume(owner != address(0));

        (MockInterpreterV4 interpreter, EvaluableV4 memory evaluable) = _createMockEvaluable();

        address clone = Clones.clone(address(I_AUTO_APPROVE_IMPLEMENTATION));
        AutoApproveConfig memory config = AutoApproveConfig({owner: owner, evaluable: evaluable});

        vm.expectEmit(true, true, true, true);
        emit AutoApprove.Initialize(address(this), config);
        bytes32 result = ICloneableV2(clone).initialize(abi.encode(config));
        assertEq(result, ICLONEABLE_V2_SUCCESS);

        // Verify owner is set correctly.
        AutoApprove autoApprove = AutoApprove(clone);
        assertEq(autoApprove.owner(), owner);

        // Verify the interpreter address was stored by confirming that calling
        // afterAdd with the correct owner does not revert due to a zero
        // interpreter.
        interpreter.setReturnValue(StackItem.wrap(bytes32(0)));
        Evidence[] memory evidences = new Evidence[](0);
        vm.prank(owner);
        autoApprove.afterAdd(address(this), evidences);
    }

    /// Double initialization MUST revert. The clone can only be initialized
    /// once.
    function testConstructionDoubleInitializeReverts(address owner) external {
        vm.assume(owner != address(0));

        (, EvaluableV4 memory evaluable) = _createMockEvaluable();

        address clone = Clones.clone(address(I_AUTO_APPROVE_IMPLEMENTATION));
        AutoApproveConfig memory config = AutoApproveConfig({owner: owner, evaluable: evaluable});
        ICloneableV2(clone).initialize(abi.encode(config));

        vm.expectRevert(abi.encodeWithSelector(Initializable.InvalidInitialization.selector));
        ICloneableV2(clone).initialize(abi.encode(config));
    }

    /// When the interpreter returns a non-zero stack value for 32-byte
    /// evidence, `afterAdd` MUST call `Verify.approve` to auto-approve the
    /// account. The `Approve` event is emitted on the Verify contract.
    function testAfterAddAutoApproves(address account, bytes32 evidenceData) external {
        vm.assume(account != address(0));

        (MockInterpreterV4 interpreter, EvaluableV4 memory evaluable) = _createMockEvaluable();
        interpreter.setReturnValue(StackItem.wrap(bytes32(uint256(1))));

        // Deploy AutoApprove first with a temporary owner, then deploy Verify
        // pointing to it, then transfer ownership.
        address autoApproveClone = Clones.clone(address(I_AUTO_APPROVE_IMPLEMENTATION));

        // We need Verify to be deployed with AutoApprove as callback, and
        // AutoApprove needs Verify as owner. Deploy AutoApprove with
        // address(this) as temp owner, deploy Verify, then transfer ownership.
        AutoApproveConfig memory config = AutoApproveConfig({owner: address(this), evaluable: evaluable});
        ICloneableV2(autoApproveClone).initialize(abi.encode(config));
        AutoApprove autoApprove = AutoApprove(autoApproveClone);

        Verify verify = _deployVerify(ADMIN, address(autoApprove));

        // Transfer AutoApprove ownership to Verify.
        autoApprove.transferOwnership(address(verify));

        // Grant APPROVER role to AutoApprove so it can call verify.approve().
        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, address(autoApprove));

        // User adds themselves with 32-byte evidence.
        vm.prank(account);
        verify.add(abi.encodePacked(evidenceData));

        // The account should now be approved because the callback auto-approved.
        assertTrue(verify.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_APPROVED));
    }

    /// When the interpreter returns zero for 32-byte evidence, `afterAdd`
    /// MUST NOT auto-approve. The account stays in the ADDED state.
    function testAfterAddDenies(address account, bytes32 evidenceData) external {
        vm.assume(account != address(0));

        (MockInterpreterV4 interpreter, EvaluableV4 memory evaluable) = _createMockEvaluable();
        interpreter.setReturnValue(StackItem.wrap(bytes32(uint256(0))));

        address autoApproveClone = Clones.clone(address(I_AUTO_APPROVE_IMPLEMENTATION));
        AutoApproveConfig memory config = AutoApproveConfig({owner: address(this), evaluable: evaluable});
        ICloneableV2(autoApproveClone).initialize(abi.encode(config));
        AutoApprove autoApprove = AutoApprove(autoApproveClone);

        Verify verify = _deployVerify(ADMIN, address(autoApprove));
        autoApprove.transferOwnership(address(verify));

        // Grant APPROVER role to AutoApprove just in case (should not be
        // needed since no approval should happen).
        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, address(autoApprove));

        vm.prank(account);
        verify.add(abi.encodePacked(evidenceData));

        // The account should remain in ADDED state, not approved.
        assertTrue(verify.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_ADDED));
    }

    /// Evidence with data length of 0 bytes MUST revert.
    function testAfterAddRevertsEmptyEvidence(address account) external {
        vm.assume(account != address(0));

        (, Verify verify) = _deployIntegration();

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(BadEvidenceLength.selector, 0));
        verify.add(hex"");
    }

    /// Evidence with data length of 31 bytes MUST revert.
    function testAfterAddReverts31ByteEvidence(address account) external {
        vm.assume(account != address(0));

        (, Verify verify) = _deployIntegration();

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(BadEvidenceLength.selector, 31));
        verify.add(hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddee");
    }

    /// Evidence with data length of 33 bytes MUST revert.
    function testAfterAddReverts33ByteEvidence(address account) external {
        vm.assume(account != address(0));

        (, Verify verify) = _deployIntegration();

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(BadEvidenceLength.selector, 33));
        verify.add(hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00");
    }

    /// `afterAdd` MUST revert when called by a non-owner (i.e. not the Verify
    /// contract). The `onlyOwner` modifier inherited from VerifyCallback
    /// enforces this.
    function testAfterAddRevertsNonOwner(address caller, address account) external {
        vm.assume(caller != address(0));
        vm.assume(account != address(0));

        (, EvaluableV4 memory evaluable) = _createMockEvaluable();

        // Deploy AutoApprove with a known owner that is NOT the caller.
        address owner = address(uint160(uint256(keccak256("owner"))));
        vm.assume(caller != owner);

        AutoApprove autoApprove = _deployAutoApprove(owner, evaluable);

        Evidence[] memory evidences = new Evidence[](1);
        evidences[0] = Evidence(account, abi.encodePacked(bytes32(uint256(42))));

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, caller));
        autoApprove.afterAdd(address(this), evidences);
    }

    /// Full integration test: a user adds themselves to Verify with 32-byte
    /// evidence, the AutoApprove callback fires, the interpreter returns
    /// non-zero, and the account ends up in APPROVED state. This tests the
    /// complete add-callback-approve flow.
    function testAfterAddFullIntegration(address account, bytes32 evidenceData, uint256 returnVal) external {
        vm.assume(account != address(0));
        vm.assume(returnVal > 0);

        (MockInterpreterV4 interpreter, EvaluableV4 memory evaluable) = _createMockEvaluable();
        interpreter.setReturnValue(StackItem.wrap(bytes32(returnVal)));

        // Deploy AutoApprove with temporary owner.
        address autoApproveClone = Clones.clone(address(I_AUTO_APPROVE_IMPLEMENTATION));
        AutoApproveConfig memory config = AutoApproveConfig({owner: address(this), evaluable: evaluable});
        ICloneableV2(autoApproveClone).initialize(abi.encode(config));
        AutoApprove autoApprove = AutoApprove(autoApproveClone);

        // Deploy Verify with AutoApprove as callback.
        Verify verify = _deployVerify(ADMIN, address(autoApprove));

        // Transfer ownership to Verify so the onlyOwner check passes.
        autoApprove.transferOwnership(address(verify));

        // AutoApprove must have APPROVER role to call verify.approve().
        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, address(autoApprove));

        // Expect the Approve event from Verify when auto-approval fires.
        vm.expectEmit(true, true, true, true);
        emit Verify.Approve(address(autoApprove), Evidence(account, abi.encodePacked(evidenceData)));

        // User adds themselves.
        vm.prank(account);
        verify.add(abi.encodePacked(evidenceData));

        // Verify the final state is APPROVED.
        assertTrue(verify.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_APPROVED));
    }

    /// When multiple evidences are submitted and only some have 32-byte data,
    /// only the 32-byte ones are evaluated. Those returning non-zero are
    /// approved; the rest are left as ADDED.
    function testAfterAddMixedEvidenceLengths(address account1, address account2, bytes32 evidenceData) external {
        vm.assume(account1 != address(0));
        vm.assume(account2 != address(0));
        vm.assume(account1 != account2);

        (MockInterpreterV4 interpreter, EvaluableV4 memory evaluable) = _createMockEvaluable();
        interpreter.setReturnValue(StackItem.wrap(bytes32(uint256(1))));

        address autoApproveClone = Clones.clone(address(I_AUTO_APPROVE_IMPLEMENTATION));
        AutoApproveConfig memory config = AutoApproveConfig({owner: address(this), evaluable: evaluable});
        ICloneableV2(autoApproveClone).initialize(abi.encode(config));
        AutoApprove autoApprove = AutoApprove(autoApproveClone);

        Verify verify = _deployVerify(ADMIN, address(autoApprove));
        autoApprove.transferOwnership(address(verify));

        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, address(autoApprove));

        // account1 adds with 32-byte evidence => should be auto-approved.
        vm.prank(account1);
        verify.add(abi.encodePacked(evidenceData));
        assertTrue(verify.accountStatusAtTime(account1, block.timestamp).eq(VERIFY_STATUS_APPROVED));

        // account2 adds with non-32-byte evidence => should revert.
        vm.prank(account2);
        vm.expectRevert(abi.encodeWithSelector(BadEvidenceLength.selector, 4));
        verify.add(hex"aabbccdd");
    }

    /// Documents that the afterAdd → Verify.approve → afterApprove callback
    /// reentrancy path is safe. When AutoApprove.afterAdd calls
    /// Verify.approve(), Verify triggers callback.afterApprove() back into
    /// AutoApprove. This is harmless because afterApprove is inherited as a
    /// no-op from VerifyCallback. The deduplication in Verify.approve() also
    /// ensures a second approval attempt for the same account is a no-op at
    /// the state level.
    ///
    /// This test verifies:
    /// 1. The full add→afterAdd→approve→afterApprove chain completes without
    ///    reverting
    /// 2. The account reaches APPROVED exactly once (correct final state)
    /// 3. Exactly one Approve event is emitted (no duplicate from reentrancy)
    function testAfterAddReentrancySafe(address account, bytes32 evidenceData) external {
        vm.assume(account != address(0));

        (MockInterpreterV4 interpreter, EvaluableV4 memory evaluable) = _createMockEvaluable();
        interpreter.setReturnValue(StackItem.wrap(bytes32(uint256(1))));

        address autoApproveClone = Clones.clone(address(I_AUTO_APPROVE_IMPLEMENTATION));
        AutoApproveConfig memory config = AutoApproveConfig({owner: address(this), evaluable: evaluable});
        ICloneableV2(autoApproveClone).initialize(abi.encode(config));
        AutoApprove autoApprove = AutoApprove(autoApproveClone);

        Verify verify = _deployVerify(ADMIN, address(autoApprove));
        autoApprove.transferOwnership(address(verify));

        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, address(autoApprove));

        // Record logs to count Approve events.
        vm.recordLogs();

        vm.prank(account);
        verify.add(abi.encodePacked(evidenceData));

        // Account is approved exactly once.
        assertTrue(verify.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_APPROVED));

        // Count Approve events to verify no duplicate from reentrancy.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 approveSelector = keccak256("Approve(address,(address,bytes))");
        uint256 approveCount = 0;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == approveSelector) {
                approveCount++;
            }
        }
        assertEq(approveCount, 1, "expected exactly one Approve event");
    }

    /// When the interpreter returns an empty stack, `afterAdd` MUST NOT panic
    /// and MUST NOT approve. The account stays ADDED.
    function testAfterAddEmptyStackNoApproval(address account, bytes32 evidenceData) external {
        vm.assume(account != address(0));

        (MockInterpreterV4 interpreter, EvaluableV4 memory evaluable) = _createMockEvaluable();
        // Override eval4 via vm.mockCall to return an empty stack.
        vm.mockCall(
            address(interpreter),
            abi.encodeWithSelector(MockInterpreterV4.eval4.selector),
            abi.encode(new StackItem[](0), new bytes32[](0))
        );

        address autoApproveClone = Clones.clone(address(I_AUTO_APPROVE_IMPLEMENTATION));
        AutoApproveConfig memory config = AutoApproveConfig({owner: address(this), evaluable: evaluable});
        ICloneableV2(autoApproveClone).initialize(abi.encode(config));
        AutoApprove autoApprove = AutoApprove(autoApproveClone);

        Verify verify = _deployVerify(ADMIN, address(autoApprove));
        autoApprove.transferOwnership(address(verify));

        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, address(autoApprove));

        vm.prank(account);
        verify.add(abi.encodePacked(evidenceData));

        assertTrue(verify.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_ADDED));
    }
}
