// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Evidence} from "../interface/IVerifyV1.sol";
import {LibEvidence} from "../lib/LibEvidence.sol";
import {Verify} from "./Verify.sol";
import {VerifyCallback} from "../abstract/VerifyCallback.sol";
import {LibUint256Array} from "rain.solmem/lib/LibUint256Array.sol";
import {
    IInterpreterV4,
    SourceIndexV2,
    DEFAULT_STATE_NAMESPACE,
    StackItem,
    EvalV4
} from "rain.interpreter.interface/interface/unstable/IInterpreterV4.sol";
import {
    IInterpreterCallerV4, EvaluableV4
} from "rain.interpreter.interface/interface/unstable/IInterpreterCallerV4.sol";
import {IInterpreterStoreV3} from "rain.interpreter.interface/interface/unstable/IInterpreterStoreV3.sol";
import {LibContext} from "rain.interpreter.interface/lib/caller/LibContext.sol";
import {LibEvaluable} from "rain.interpreter.interface/lib/caller/LibEvaluable.sol";
import {ICloneableV2, ICLONEABLE_V2_SUCCESS} from "rain.factory/interface/ICloneableV2.sol";
import {LibPointer, Pointer} from "rain.solmem/lib/LibPointer.sol";
import {LibNamespace} from "rain.interpreter.interface/lib/ns/LibNamespace.sol";

bytes32 constant CALLER_META_HASH = bytes32(0x92932311849707fd57884c540914fe3ff7f45ac30152a2aa7fcc9426a6ac22d7);

uint256 constant CAN_APPROVE_MIN_OUTPUTS = 1;
uint16 constant CAN_APPROVE_MAX_OUTPUTS = 1;
SourceIndexV2 constant CAN_APPROVE_ENTRYPOINT = SourceIndexV2.wrap(0);

struct AutoApproveConfig {
    address owner;
    EvaluableV4 evaluable;
}

contract AutoApprove is ICloneableV2, VerifyCallback, IInterpreterCallerV4 {
    using LibPointer for Pointer;
    using LibUint256Array for uint256;
    using LibUint256Array for uint256[];
    using LibEvidence for uint256[];
    using LibPointer for uint256[];

    /// Contract has initialized.
    /// @param sender `msg.sender` initializing the contract (factory).
    /// @param config All initialized config.
    event Initialize(address sender, AutoApproveConfig config);

    EvaluableV4 internal sEvaluable;

    constructor() {
        _disableInitializers();
    }

    /// @inheritdoc ICloneableV2
    function initialize(bytes calldata data) external initializer returns (bytes32 success) {
        verifyCallbackInit();

        AutoApproveConfig memory config = abi.decode(data, (AutoApproveConfig));

        _transferOwnership(config.owner);
        emit Initialize(msg.sender, config);
        sEvaluable = config.evaluable;

        return ICLONEABLE_V2_SUCCESS;
    }

    function afterAdd(address adder, Evidence[] calldata evidences) public virtual override {
        unchecked {
            // Inherit owner check etc.
            super.afterAdd(adder, evidences);

            uint256[] memory approvedRefs = new uint256[](evidences.length);
            uint256 approvals = 0;
            bytes32[][] memory context = new bytes32[][](1);
            context[0] = new bytes32[](2);
            EvaluableV4 memory evaluable = sEvaluable;

            for (uint256 i = 0; i < evidences.length; i++) {
                // Currently we only support 32 byte evidence for auto approve.
                if (evidences[i].data.length == 0x20) {
                    context[0][0] = bytes32(uint256(uint160(evidences[i].account)));
                    context[0][1] = bytes32(evidences[i].data);
                    // Slither complains about this event coming after the set
                    // as it could be reentrant and confuse the ordering of
                    // events. In general this may be the case but specifically
                    // here we trust the store contract and the standard
                    // implementation doesn't reenter the caller upon set.
                    // slither-disable-next-line reentrancy-events
                    emit ContextV2(msg.sender, context);
                    // Slither doesn't like this because it involves external calls in a
                    // loop, where any revert will prevent the entire transaction. In
                    // this case the caller has control over the list of evidences
                    // and can ensure that the evidence is valid, so we can safely ignore
                    // this warning. At the least the caller can remove bad evidence and
                    // try again.
                    // slither-disable-next-line calls-loop
                    (StackItem[] memory stack, bytes32[] memory kvs) = evaluable.interpreter.eval4(
                        EvalV4({
                            store: evaluable.store,
                            namespace: LibNamespace.qualifyNamespace(DEFAULT_STATE_NAMESPACE, address(this)),
                            bytecode: evaluable.bytecode,
                            sourceIndex: CAN_APPROVE_ENTRYPOINT,
                            context: context,
                            inputs: new StackItem[](0),
                            stateOverlay: new bytes32[](0)
                        })
                    );
                    if (StackItem.unwrap(stack[stack.length - 1]) > 0) {
                        LibEvidence._updateEvidenceRef(approvedRefs, evidences[i], approvals);
                        approvals++;
                    }
                    if (kvs.length > 0) {
                        // Same as the eval.
                        // slither-disable-next-line calls-loop
                        evaluable.store.set(DEFAULT_STATE_NAMESPACE, kvs);
                    }
                }
            }

            if (approvals > 0) {
                approvedRefs.truncate(approvals);
                Verify(msg.sender).approve(approvedRefs.asEvidences());
            }
        }
    }
}
