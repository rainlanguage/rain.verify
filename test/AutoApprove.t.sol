// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
import {AutoApprove, AutoApproveConfig} from "../src/concrete/AutoApprove.sol";
import {Verify, VerifyConfig} from "../src/concrete/Verify.sol";
import {
    Evidence,
    VerifyStatus,
    VERIFY_STATUS_NIL,
    VERIFY_STATUS_ADDED,
    VERIFY_STATUS_APPROVED,
    VERIFY_STATUS_BANNED
} from "rain.verify.interface/interface/IVerifyV1.sol";
import {ICloneableV2, ICLONEABLE_V2_SUCCESS} from "rain.factory/interface/ICloneableV2.sol";
import {
    IInterpreterV4,
    StackItem,
    EvalV4,
    SourceIndexV2,
    DEFAULT_STATE_NAMESPACE
} from "rain.interpreter.interface/interface/unstable/IInterpreterV4.sol";
import {IInterpreterStoreV3} from "rain.interpreter.interface/interface/unstable/IInterpreterStoreV3.sol";
import {EvaluableV4} from "rain.interpreter.interface/interface/unstable/IInterpreterCallerV4.sol";
import {StateNamespace, FullyQualifiedNamespace} from "rain.interpreter.interface/interface/IInterpreterV3.sol";
import {LibVerifyStatus} from "../src/lib/LibVerifyStatus.sol";
import {Clones} from "rain.factory/../lib/openzeppelin-contracts/contracts/proxy/Clones.sol";

/// @dev Mock interpreter that returns a configurable stack value from `eval4`.
/// Does NOT inherit `IInterpreterV4` because the interface declares `calldata`
/// return types which cannot be produced from Solidity storage/memory. The ABI
/// encoding is identical so the caller (AutoApprove) can decode the response
/// through the interface pointer without issue.
contract MockInterpreterV4 {
    /// @dev The value that will be returned as the sole stack item.
    StackItem public sReturnValue;

    /// @dev Set the return value for subsequent `eval4` calls.
    /// @param value The stack item to return.
    function setReturnValue(StackItem value) external {
        sReturnValue = value;
    }

    /// @dev Matches the `eval4` selector from `IInterpreterV4`. Returns a
    /// single-element stack containing `sReturnValue` and an empty kvs array.
    function eval4(EvalV4 calldata) external view returns (StackItem[] memory stack, bytes32[] memory kvs) {
        stack = new StackItem[](1);
        stack[0] = sReturnValue;
        kvs = new bytes32[](0);
    }
}

/// @dev Mock store that implements all required functions of
/// `IInterpreterStoreV3` as no-ops.
contract MockInterpreterStoreV3 is IInterpreterStoreV3 {
    /// @inheritdoc IInterpreterStoreV3
    function set(StateNamespace, bytes32[] calldata) external override {}

    /// @inheritdoc IInterpreterStoreV3
    function get(FullyQualifiedNamespace, bytes32) external pure override returns (bytes32) {
        return bytes32(0);
    }
}

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

        vm.expectRevert("Initializable: contract is already initialized");
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

    /// Evidence with data length != 32 bytes MUST be silently skipped by
    /// `afterAdd`. The interpreter is never called for such evidence and no
    /// approval occurs.
    function testAfterAddSkipsNon32ByteEvidence(address account) external {
        vm.assume(account != address(0));

        (MockInterpreterV4 interpreter, EvaluableV4 memory evaluable) = _createMockEvaluable();
        // Set interpreter to approve everything, so if it WERE called it would approve.
        interpreter.setReturnValue(StackItem.wrap(bytes32(uint256(1))));

        address autoApproveClone = Clones.clone(address(I_AUTO_APPROVE_IMPLEMENTATION));
        AutoApproveConfig memory config = AutoApproveConfig({owner: address(this), evaluable: evaluable});
        ICloneableV2(autoApproveClone).initialize(abi.encode(config));
        AutoApprove autoApprove = AutoApprove(autoApproveClone);

        Verify verify = _deployVerify(ADMIN, address(autoApprove));
        autoApprove.transferOwnership(address(verify));

        vm.prank(ADMIN);
        verify.grantRole(APPROVER_ROLE, address(autoApprove));

        // Add with 0 bytes of evidence data (not 32).
        vm.prank(account);
        verify.add(hex"");

        // Account should be ADDED, not APPROVED, since evidence was skipped.
        assertTrue(verify.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_ADDED));
    }

    /// Evidence with data length of 31 bytes MUST be silently skipped.
    function testAfterAddSkips31ByteEvidence(address account) external {
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

        // 31 bytes: not exactly 32, so should be skipped.
        vm.prank(account);
        verify.add(hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddee");

        assertTrue(verify.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_ADDED));
    }

    /// Evidence with data length of 33 bytes MUST be silently skipped.
    function testAfterAddSkips33ByteEvidence(address account) external {
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

        // 33 bytes: not exactly 32, so should be skipped.
        vm.prank(account);
        verify.add(hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00");

        assertTrue(verify.accountStatusAtTime(account, block.timestamp).eq(VERIFY_STATUS_ADDED));
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
        vm.expectRevert("Ownable: caller is not the owner");
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

        // account2 adds with non-32-byte evidence => should remain ADDED.
        vm.prank(account2);
        verify.add(hex"aabbccdd");
        assertTrue(verify.accountStatusAtTime(account2, block.timestamp).eq(VERIFY_STATUS_ADDED));
    }
}
