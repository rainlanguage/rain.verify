// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.25;

import {IVerifyCallbackV1, Evidence} from "../interface/IVerifyCallbackV1.sol";
import {OwnableUpgradeable as Ownable} from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";

/// @title VerifyCallback
/// Implements empty virtual functions for every function in `IVerifyCallbackV1`
/// so that inheriting contracts only have to override the callbacks they need
/// to define logic for.
abstract contract VerifyCallback is IVerifyCallbackV1, Ownable {
    function verifyCallbackInit() internal onlyInitializing {
        __Ownable_init();
    }

    function afterAdd(address adder, Evidence[] calldata evidences) public virtual override onlyOwner {}

    function afterApprove(address approver, Evidence[] calldata evidences) public virtual override onlyOwner {}

    function afterBan(address banner, Evidence[] calldata evidences) public virtual override onlyOwner {}

    function afterRemove(address remover, Evidence[] calldata evidences) public virtual override onlyOwner {}
}
