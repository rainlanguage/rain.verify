# Pass 5 - Correctness / Intent Verification: AutoApprove.sol (A02)

**File:** `/Users/thedavidmeister/Code/rain.verify/src/concrete/AutoApprove.sol`
**Date:** 2026-03-16

---

## Evidence of Thorough Reading

### Contract Name
`AutoApprove` (line 36) -- inherits `ICloneableV2`, `VerifyCallback`, `IInterpreterCallerV4`

### Functions

| Name | Line | Visibility | Modifiers |
|------|------|------------|-----------|
| `constructor` | 48 | public (implicit) | -- |
| `initialize` | 53 | external | `initializer` |
| `afterAdd` | 65 | public virtual | `override` |

### Types

| Name | Kind | Line |
|------|------|------|
| `AutoApproveConfig` | struct (file-level) | 31 |

### Constants

| Name | Type | Value | Line |
|------|------|-------|------|
| `CAN_APPROVE_ENTRYPOINT` | `SourceIndexV2` | `SourceIndexV2.wrap(0)` | 29 |

### Errors

| Name | Line |
|------|------|
| `BadEvidenceLength(uint256)` | 27 |

### Events

| Name | Line |
|------|------|
| `Initialize(address, AutoApproveConfig)` | 44 |

### State Variables

| Name | Type | Line |
|------|------|------|
| `sEvaluable` | `EvaluableV4` | 46 |

---

## Verification

### 1. Every named function does what its name and NatSpec claim

- **`constructor`** (line 48): Calls `_disableInitializers()` to prevent initialization of the implementation contract. Correct.
- **`initialize`** (line 53): Decodes `AutoApproveConfig` from bytes, calls `verifyCallbackInit()` (initializing Ownable), transfers ownership to `config.owner`, stores the evaluable config, emits `Initialize`, and returns `ICLONEABLE_V2_SUCCESS`. Correct.
- **`afterAdd`** (line 65): Processes the post-add callback by iterating over evidences, reverting if any evidence data is not exactly 32 bytes, evaluating each through the interpreter, and auto-approving accounts where the expression returns a nonzero top-of-stack value. Correct.

### 2. Constants match documented meaning

- `CAN_APPROVE_ENTRYPOINT = SourceIndexV2.wrap(0)`: Source index 0, the first (and only) expression entrypoint. Used at line 102 when calling `eval4`. Correct.

### 3. Error conditions match their names

- `BadEvidenceLength(uint256 length)` (line 27): NatSpec says "Thrown when evidence data is not exactly 32 bytes." Triggered at line 77-78 when `evidences[i].data.length != 0x20`. The error carries the actual length. Correct.

### 4. Interface conformance

**ICloneableV2**: Requires `initialize(bytes calldata data) external returns (bytes32 success)`. AutoApprove implements this at line 53 with the `initializer` modifier, returns `ICLONEABLE_V2_SUCCESS`. Conforms.

**IVerifyCallbackV1** (via `VerifyCallback`): The abstract base `VerifyCallback` provides default empty `onlyOwner` implementations for `afterAdd`, `afterApprove`, `afterBan`, `afterRemove`. AutoApprove overrides only `afterAdd`. All four interface methods are satisfied through the inheritance chain. Conforms.

**IInterpreterCallerV4**: AutoApprove declares it implements this. The interface requires emitting `ContextV2` events when providing context to an interpreter. AutoApprove emits `ContextV2` at line 89 inside the loop. Conforms.

### 5. `afterAdd` correctly evaluates interpreter and conditionally approves

Step by step through lines 66-125:

1. **Line 68:** Calls `super.afterAdd(adder, evidences)` which invokes `VerifyCallback.afterAdd()`. This checks `onlyOwner`, ensuring only the owning Verify contract can call this function. Correct access control.

2. **Lines 70-74:** Allocates `approvedRefs` array sized to `evidences.length`, initializes `approvals` counter, creates 1x2 context matrix, loads `sEvaluable` into memory. Correct setup.

3. **Lines 76-78:** For each evidence, if data length is not 0x20 (32 bytes), reverts with `BadEvidenceLength`. This is a hard revert that rolls back the entire transaction including the `add()` state change in Verify. This means a user calling `Verify.add()` with non-32-byte evidence data will have their entire transaction reverted when AutoApprove is configured as the callback. This is correct behavior -- it prevents invalid evidence from being recorded.

4. **Lines 81-82:** Context construction: `context[0][0]` is the account address zero-padded to 32 bytes, `context[0][1]` is the raw 32-byte evidence data. Correct.

5. **Lines 97-107:** Calls `eval4` on the interpreter with the evaluable's bytecode, the qualified namespace, source index 0, and the context. The namespace is pre-qualified using `LibNamespace.qualifyNamespace(DEFAULT_STATE_NAMESPACE, address(this))`, which is correct because `EvalV4.namespace` is typed as `FullyQualifiedNamespace`.

6. **Line 108:** Checks `stack.length > 0 && StackItem.unwrap(stack[stack.length - 1]) > 0`. If the expression returns at least one stack item and the top-of-stack is nonzero, the account is approved. Reading `stack[stack.length - 1]` (the last element) follows Rain convention where the top of the returned stack array is the last element. Correct.

7. **Lines 109-110:** Records the evidence reference and increments the approvals counter. Uses `LibEvidence._updateEvidenceRef` which stores a memory pointer to the evidence struct. Correct.

8. **Lines 112-116:** If the interpreter returned key-value pairs to persist, writes them to the store using `DEFAULT_STATE_NAMESPACE` (unqualified). The store will internally qualify this using `msg.sender` (the AutoApprove contract address), producing the same namespace as the eval used. Correct and consistent.

9. **Lines 120-123:** If any approvals occurred, truncates the array and calls `Verify(msg.sender).approve(approvedRefs.asEvidences())`. Since `msg.sender` is the Verify contract (which called this callback), this calls back into Verify to approve the accounts.

**Re-entrancy analysis:** When `Verify.approve()` is called from the callback, the accounts being approved were already added by the user's `Verify.add()` call. In `Verify.approve()` at line 433, `lState.addedSince < 1` will be FALSE (the account already has an added state), so no implicit add occurs and `callback.afterAdd()` is NOT called again. Only `callback.afterApprove()` fires, which is the empty default from `VerifyCallback`. No re-entrancy issue exists.

### 6. `BadEvidenceLength` reverts on non-32-byte evidence

Confirmed at line 77-78: `if (evidences[i].data.length != 0x20) { revert BadEvidenceLength(evidences[i].data.length); }`. The revert is triggered for any evidence data that is not exactly 32 bytes. This is a hard revert that prevents the entire `add()` transaction from completing. The error name and NatSpec accurately describe this behavior. Correct.

---

## Findings

No findings. All named functions, constants, errors, and behaviors match their documented intent. Interface conformance is complete. The re-entrancy path through `Verify.approve()` terminates safely because accounts are already added when the callback fires.
