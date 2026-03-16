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
import {ICloneableV2, ICLONEABLE_V2_SUCCESS} from "rain.factory/interface/ICloneableV2.sol";
import {ZeroAdmin} from "../../src/err/ErrVerify.sol";
import {LibVerifyStatus} from "../../src/lib/LibVerifyStatus.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/// @title VerifyConstructionTest
/// @notice Tests that `Verify` constructs and initializes correctly, including
/// role constant values, callback address, emitted events, and revert
/// conditions for zero admin and double initialization.
contract VerifyConstructionTest is Test {
    using LibVerifyStatus for VerifyStatus;

    Verify internal immutable I_VERIFY;
    Verify internal immutable I_IMPLEMENTATION;

    address internal constant ADMIN = address(uint160(uint256(keccak256("admin"))));

    constructor() {
        I_IMPLEMENTATION = new Verify();
        address clone = Clones.clone(address(I_IMPLEMENTATION));
        I_VERIFY = Verify(clone);
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(ADMIN, address(0))));
    }

    /// Role constant APPROVER_ADMIN matches keccak256("APPROVER_ADMIN").
    function testConstructionApproverAdminRole() external view {
        assertEq(I_VERIFY.APPROVER_ADMIN(), keccak256("APPROVER_ADMIN"));
    }

    /// Role constant APPROVER matches keccak256("APPROVER").
    function testConstructionApproverRole() external view {
        assertEq(I_VERIFY.APPROVER(), keccak256("APPROVER"));
    }

    /// Role constant REMOVER_ADMIN matches keccak256("REMOVER_ADMIN").
    function testConstructionRemoverAdminRole() external view {
        assertEq(I_VERIFY.REMOVER_ADMIN(), keccak256("REMOVER_ADMIN"));
    }

    /// Role constant REMOVER matches keccak256("REMOVER").
    function testConstructionRemoverRole() external view {
        assertEq(I_VERIFY.REMOVER(), keccak256("REMOVER"));
    }

    /// Role constant BANNER_ADMIN matches keccak256("BANNER_ADMIN").
    function testConstructionBannerAdminRole() external view {
        assertEq(I_VERIFY.BANNER_ADMIN(), keccak256("BANNER_ADMIN"));
    }

    /// Role constant BANNER matches keccak256("BANNER").
    function testConstructionBannerRole() external view {
        assertEq(I_VERIFY.BANNER(), keccak256("BANNER"));
    }

    /// The callback address is set to the value provided during initialization.
    function testConstructionCallbackAddress(address callback) external {
        address clone = Clones.clone(address(I_IMPLEMENTATION));
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(ADMIN, callback)));
        assertEq(address(Verify(clone).sCallback()), callback);
    }

    /// Admin receives APPROVER_ADMIN, REMOVER_ADMIN, and BANNER_ADMIN roles
    /// after initialization.
    function testConstructionAdminRoles(address admin) external {
        vm.assume(admin != address(0));
        address clone = Clones.clone(address(I_IMPLEMENTATION));
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(admin, address(0))));
        Verify verify = Verify(clone);
        assertTrue(verify.hasRole(keccak256("APPROVER_ADMIN"), admin));
        assertTrue(verify.hasRole(keccak256("REMOVER_ADMIN"), admin));
        assertTrue(verify.hasRole(keccak256("BANNER_ADMIN"), admin));
    }

    /// The Initialize event is emitted with the correct sender and config
    /// during initialization.
    function testConstructionEmitsInitialize(address admin, address callback) external {
        vm.assume(admin != address(0));
        address clone = Clones.clone(address(I_IMPLEMENTATION));
        vm.expectEmit(true, true, true, true);
        emit Verify.Initialize(address(this), VerifyConfig(admin, callback));
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(admin, callback)));
    }

    /// Initializing with a zero admin address MUST revert with `ZeroAdmin`.
    function testConstructionZeroAdminReverts(address callback) external {
        address clone = Clones.clone(address(I_IMPLEMENTATION));
        vm.expectRevert(abi.encodeWithSelector(ZeroAdmin.selector));
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(address(0), callback)));
    }

    /// Double initialization MUST revert. The clone can only be initialized
    /// once.
    function testConstructionDoubleInitializeReverts(address admin, address callback) external {
        vm.assume(admin != address(0));
        address clone = Clones.clone(address(I_IMPLEMENTATION));
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(admin, callback)));
        vm.expectRevert(abi.encodeWithSelector(Initializable.InvalidInitialization.selector));
        ICloneableV2(clone).initialize(abi.encode(VerifyConfig(admin, callback)));
    }

    /// The initialize function returns ICLONEABLE_V2_SUCCESS on success.
    function testConstructionInitializeReturnsSuccess(address admin, address callback) external {
        vm.assume(admin != address(0));
        address clone = Clones.clone(address(I_IMPLEMENTATION));
        bytes32 result = ICloneableV2(clone).initialize(abi.encode(VerifyConfig(admin, callback)));
        assertEq(result, ICLONEABLE_V2_SUCCESS);
    }

    /// Role admin relationships are set correctly: APPROVER_ADMIN admins
    /// APPROVER, REMOVER_ADMIN admins REMOVER, BANNER_ADMIN admins BANNER.
    function testConstructionRoleAdminRelationships() external view {
        assertEq(I_VERIFY.getRoleAdmin(keccak256("APPROVER")), keccak256("APPROVER_ADMIN"));
        assertEq(I_VERIFY.getRoleAdmin(keccak256("REMOVER")), keccak256("REMOVER_ADMIN"));
        assertEq(I_VERIFY.getRoleAdmin(keccak256("BANNER")), keccak256("BANNER_ADMIN"));
    }

    /// Self-admin relationships are set correctly: each admin role admins
    /// itself.
    function testConstructionSelfAdminRelationships() external view {
        assertEq(I_VERIFY.getRoleAdmin(keccak256("APPROVER_ADMIN")), keccak256("APPROVER_ADMIN"));
        assertEq(I_VERIFY.getRoleAdmin(keccak256("REMOVER_ADMIN")), keccak256("REMOVER_ADMIN"));
        assertEq(I_VERIFY.getRoleAdmin(keccak256("BANNER_ADMIN")), keccak256("BANNER_ADMIN"));
    }
}
