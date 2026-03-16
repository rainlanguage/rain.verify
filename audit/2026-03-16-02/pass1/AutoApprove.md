# Pass 1 (Security) - AutoApprove.sol

**Agent:** A02
**File:** `src/concrete/AutoApprove.sol`

## Evidence of Thorough Reading

### Contract
- `AutoApprove` (line 36), inherits `ICloneableV2`, `VerifyCallback`, `IInterpreterCallerV4`

### Functions
| Function | Line | Visibility |
|---|---|---|
| `constructor` | 48 | public |
| `initialize` | 53 | external |
| `afterAdd` | 65 | public virtual override |

### Types / Errors / Constants
| Kind | Name | Line |
|---|---|---|
| error | `BadEvidenceLength(uint256)` | 27 |
| constant | `CAN_APPROVE_ENTRYPOINT` (`SourceIndexV2`) | 29 |
| struct | `AutoApproveConfig` | 31 |
| event | `Initialize` | 44 |
| state variable | `sEvaluable` (`EvaluableV4 internal`) | 46 |

### Callback Interface (`IVerifyCallbackV1`)
- `afterAdd(address, Evidence[])` (line 35)
- `afterApprove(address, Evidence[])` (line 41)
- `afterBan(address, Evidence[])` (line 47)
- `afterRemove(address, Evidence[])` (line 53)

## Security Review

### 1. Memory Safety in Assembly

AutoApprove itself contains no inline assembly. It delegates to `LibEvidence._updateEvidenceRef` and `LibEvidence.asEvidences`, both of which use `assembly ("memory-safe")`. The `_updateEvidenceRef` call on line 109 is always guarded by the fact that `approvals < evidences.length` (since `approvals` only increments when the stack condition is true and the loop index `i` is bounded by `evidences.length`), so the write at `refsIndex` is always within the allocated array bounds. No memory safety issue.

### 2. Access Control

`afterAdd` inherits `onlyOwner` from `VerifyCallback` (line 17 of VerifyCallback.sol) via `super.afterAdd(adder, evidences)` on line 68. The owner should be the `Verify` contract that calls this callback. The `initialize` function is guarded by the `initializer` modifier, preventing re-initialization. The constructor calls `_disableInitializers()` to prevent initialization of the implementation contract. Access control is correct.

### 3. Reentrancy

The `afterAdd` function makes multiple external calls in a loop:
- `evaluable.interpreter.eval4(...)` (line 97)
- `evaluable.store.set(...)` (line 115)
- `Verify(msg.sender).approve(...)` (line 122)

The interpreter and store are set at initialization from trusted config, and the `Verify(msg.sender)` call goes back to the calling Verify contract. The reentrancy path is: User -> `Verify.add` -> `AutoApprove.afterAdd` -> `Verify.approve` -> `AutoApprove.afterApprove` (empty, passes `onlyOwner` since `msg.sender` is Verify which is owner). This is a well-understood call chain that terminates correctly.

A malicious interpreter could reenter, but the interpreter is set by the deployer at initialization and is therefore trusted. The code comments acknowledge this trust assumption (lines 86-88, 91-96).

### 4. Input Validation

Evidence data length is validated to be exactly 32 bytes (line 77), reverting with a custom error `BadEvidenceLength`. The `bytes32` cast on line 82 is safe given this validation. The `address` truncation on line 81 (`uint256(uint160(evidences[i].account))`) correctly zero-extends the address to 32 bytes.

### 5. Namespace Isolation in Store Access

The `eval4` call uses `LibNamespace.qualifyNamespace(DEFAULT_STATE_NAMESPACE, address(this))` (line 100), properly qualifying the namespace with the AutoApprove contract address. The `store.set` call on line 115 uses the raw `DEFAULT_STATE_NAMESPACE`. Per the `IInterpreterStoreV3` spec, the store itself qualifies the namespace using `msg.sender` (which is AutoApprove). Since `eval4` internally delegates store writes through the same store, the qualification is consistent. No namespace isolation issue.

### 6. Error Handling

All reverts use the custom error `BadEvidenceLength`. The `super.afterAdd` call propagates `onlyOwner` reverts from OpenZeppelin, which also uses custom errors. No bare `revert()` or `require()` with string messages.

### 7. Unchecked Arithmetic

The entire `afterAdd` body is wrapped in `unchecked` (line 66). The loop variable `i` and the `approvals` counter are both bounded by `evidences.length`, which cannot practically overflow `uint256` due to gas limits. No overflow risk.

### 8. Trust of `msg.sender` as Verify Contract

On line 122, `Verify(msg.sender).approve(...)` casts `msg.sender` to `Verify` and calls `approve`. Since `afterAdd` is `onlyOwner`, and the owner is expected to be the Verify contract, this is consistent. However, if an owner were set to a non-Verify contract, this call would fail or behave unexpectedly. This is a deployment configuration concern, not a code bug.

## Findings

No findings.

All reviewed areas (memory safety, access control, reentrancy, input validation, namespace isolation, error handling, unchecked arithmetic) are correctly implemented. The trust model is well-documented and the external call chain terminates correctly.
