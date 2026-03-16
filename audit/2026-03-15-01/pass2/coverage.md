# Pass 2: Test Coverage

## Overview

The repository has **no `test/` directory and no test files**. Zero test coverage exists for any source file. All findings below are HIGH because the contracts handle access control, state transitions, and external calls with no automated verification.

## Source Files In Scope

1. `src/abstract/VerifyCallback.sol` — A01
2. `src/concrete/AutoApprove.sol` — A02
3. `src/concrete/Verify.sol` — A03
4. `src/err/ErrVerify.sol` — A04
5. `src/lib/LibEvidence.sol` — A05
6. `src/lib/LibVerifyStatus.sol` — A06
7. `script/Deploy.sol` — A07

## Findings

### A03-9 [HIGH] — No tests for Verify.sol

`Verify.sol` is the core contract (~200 lines of logic) with role-based access control, state machine transitions, batch operations, external callback invocations, and assembly-adjacent library usage. No tests exist for any of the following:

- `initialize` — admin setup, zero-admin revert, callback assignment
- `add` — status guard logic (the `&&`/`||` bug from A03-1 is untested), state creation for NIL accounts, event emission, callback invocation
- `approve` — APPROVER role check, batch processing, status transitions, callback, evidence handling
- `ban` — BANNER role check, batch processing, status transitions, callback
- `remove` — REMOVER role check, batch processing, state reset, callback
- `accountStatusAtTime` — time-based status resolution across all states
- `statusAtTime` (internal) — timestamp comparison logic for all four status fields

**File:** `src/concrete/Verify.sol`

### A02-5 [HIGH] — No tests for AutoApprove.sol

No tests for:
- `initialize` — owner/callback/interpreter setup via `receiveHandlePayload`
- `afterAdd` — interpreter evaluation, auto-approval logic, evidence forwarding, store interactions
- `afterApprove` / `afterBan` / `afterRemove` — no-op verification

**File:** `src/concrete/AutoApprove.sol`

### A01-3 [HIGH] — No tests for VerifyCallback.sol

No tests for:
- `verifyCallbackInit` — `__Ownable_init` delegation
- `afterAdd` / `afterApprove` / `afterBan` / `afterRemove` — `onlyOwner` guard enforcement

**File:** `src/abstract/VerifyCallback.sol`

### A05-4 [HIGH] — No tests for LibEvidence.sol

No tests for:
- `_updateEvidenceRef` — assembly-level array element writing
- `asEvidences` — type-punning `uint256[]` to `Evidence[]`
- Edge cases: zero-length arrays, boundary indices

**File:** `src/lib/LibEvidence.sol`

### A06-1 [HIGH] — No tests for LibVerifyStatus.sol

No tests for:
- `eq` — equality comparison of VerifyStatus values, including same-value and different-value cases

**File:** `src/lib/LibVerifyStatus.sol`

### A04-1 [LOW] — No tests for ErrVerify.sol

Error-only file. Testing would validate that errors are triggered by the correct conditions, but those tests belong to the consuming contracts (Verify.sol). Covered by A03-9.

**File:** `src/err/ErrVerify.sol`

### A07-1 [LOW] — No tests for Deploy.sol

Deployment scripts are typically not unit-tested but could benefit from fork tests verifying successful deployment and initialization.

**File:** `script/Deploy.sol`
