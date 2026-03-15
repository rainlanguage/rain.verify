# Audit Pass 3 (Documentation) -- Verify.sol

**Agent:** A03
**File:** `/Users/thedavidmeister/Code/rain.verify/src/concrete/Verify.sol`
**Date:** 2026-03-15

---

## Evidence of Thorough Reading

### Contract/Module Name
`Verify` (line 186) -- inherits `IVerifyV1`, `ICloneableV2`, `AccessControl`

### Structs Defined

| Name | Line |
|------|------|
| `State` | 29 |
| `VerifyConfig` | 41 |

### Constants

| Name | Visibility | Line |
|------|-----------|------|
| `UNINITIALIZED` | private | 196 |
| `APPROVER_ADMIN` | public | 238 |
| `APPROVER` | public | 240 |
| `REMOVER_ADMIN` | public | 242 |
| `REMOVER` | public | 244 |
| `BANNER_ADMIN` | public | 248 |
| `BANNER` | public | 250 |

### Events

| Name | Line | Has NatSpec |
|------|------|-------------|
| `Initialize` | 199 | Partial (missing @param) |
| `RequestApprove` | 206 | Yes |
| `Approve` | 210 | Yes |
| `RequestBan` | 218 | Yes |
| `Ban` | 223 | Yes |
| `RequestRemove` | 230 | Yes |
| `Remove` | 235 | Yes |

### State Variables

| Name | Line |
|------|------|
| `sStates` | 253 |
| `sCallback` | 257 |

### Errors (imported from ErrVerify.sol)

| Name | Line (ErrVerify.sol) |
|------|---------------------|
| `ZeroAdmin` | 6 |
| `NotApproved` | 9 |
| `AlreadyExists` | 12 |

### Functions/Methods

| Name | Visibility | Line | Has NatSpec |
|------|-----------|------|-------------|
| `constructor` | -- | 259 | No (trivial) |
| `initialize` | external | 264 | Yes (@inheritdoc) |
| `state` | external view | 306 | Yes (missing @return) |
| `statusAtTime` | public pure | 314 | Yes |
| `accountStatusAtTime` | external view virtual | 347 | Yes (@inheritdoc) |
| `newState` | private view | 360 | Yes (@dev) |
| `add` | external | 367 | Yes |
| `approve` | external | 412 | Yes |
| `requestApprove` | external | 474 | Yes |
| `ban` | external | 484 | Yes |
| `requestBan` | external | 538 | Yes |
| `remove` | external | 550 | Yes (typo in @param) |
| `requestRemove` | external | 582 | Yes |

### Modifiers

| Name | Line | Has NatSpec |
|------|------|-------------|
| `onlyApproved` | 352 | Yes |

---

## Findings

### A03-10: Contract-level NatSpec contradicts `add` guard implementation for banned accounts [MEDIUM]

**Location:** `Verify.sol` lines 136-138 (contract doc) vs line 370 (implementation)

**Description:**
The contract-level NatSpec on lines 136-138 states:

> Once an account is banned, any attempt by the account holder to change their status, or an approver to approve will be rejected.

However, the `add` function guard on line 370 does not reject banned accounts:

```solidity
if (currentStatus.eq(VERIFY_STATUS_APPROVED) && !currentStatus.eq(VERIFY_STATUS_BANNED)) {
    revert AlreadyExists();
}
```

This condition only reverts for `APPROVED` accounts (and the `!BANNED` sub-expression is redundant, as already identified in A03-1 and A03-2 from pass 1). A `BANNED` account can still call `add`, which emits `RequestApprove` events and triggers callbacks -- contradicting the documented behavior.

The documentation claims banned accounts are rejected; the code does not reject them. Either the documentation is wrong and banned accounts should be allowed to call `add` (unlikely given the security context), or the code is wrong and the documentation accurately describes intent. Given the security findings in pass 1 (A03-1), the code is the defective artifact. From a documentation perspective, the NatSpec accurately describes the *intended* behavior but the implementation diverges.

The `add` function's own NatSpec (lines 364-366) does not mention what statuses are rejected, which makes the discoverability of the guard behavior worse.

**Impact:** Developers relying on the contract-level documentation would incorrectly assume banned accounts cannot call `add`. This is a documentation-vs-implementation mismatch with security implications (already captured as A03-1 MEDIUM in pass 1; this finding covers the documentation angle).

---

### A03-11: `add` function NatSpec does not document guard conditions [LOW]

**Location:** `Verify.sol` lines 364-366

**Description:**
The `add` function's NatSpec says:

```
/// An account adds their own verification evidence.
/// Internally `msg.sender` is used; delegated `add` is not supported.
/// @param data The evidence to support approving the `msg.sender`.
```

This does not document:
1. Which account statuses are allowed to call `add` (only `NIL` and `ADDED`).
2. Which statuses cause a revert (should be `APPROVED` and `BANNED` per contract-level docs).
3. The behavior when an already-added account calls `add` again (re-emits `RequestApprove` without changing state).

Compare this to the `approve` function (lines 398-411) which thoroughly documents its guard behavior, idempotency semantics, and interaction with banned status. The `add` function should have similar documentation clarity.

---

### A03-12: Typo in `remove` parameter NatSpec: "suppor" [LOW]

**Location:** `Verify.sol` line 549

**Description:**
The `@param` documentation for the `remove` function reads:

```
/// @param evidences All evidence to suppor the removal.
```

The word "suppor" should be "support".

---

### A03-13: `state` function missing `@return` NatSpec tag [LOW]

**Location:** `Verify.sol` lines 304-307

**Description:**
The `state` function has a `@param` tag but no `@return` tag:

```solidity
/// Typed accessor into states.
/// @param account The account to return the current `State` for.
function state(address account) external view returns (State memory) {
```

Per NatSpec conventions, the return value should be documented with `@return`.

---

### A03-14: `Initialize` event missing `@param` NatSpec tags [LOW]

**Location:** `Verify.sol` lines 198-199

**Description:**
The `Initialize` event has a general description but no `@param` tags:

```solidity
/// Emitted when the `Verify` contract is initialized.
event Initialize(address sender, VerifyConfig config);
```

All other events in the contract have `@param` tags for their parameters. The `Initialize` event should document `sender` and `config` for consistency.

---

### A03-15: Contract-level NatSpec typo: "implicity" should be "implicitly" [INFO]

**Location:** `Verify.sol` line 139

**Description:**
Line 139 reads:

> Banners MAY ban and implicity add any account atomically...

The word "implicity" should be "implicitly".

---

### A03-16: Contract-level NatSpec uses "pseudonomous" instead of "pseudonymous" [INFO]

**Location:** `Verify.sol` lines 81, 84

**Description:**
Lines 81-82:
> ...opt-in, permissionless system based on pseudonomous actors

Line 84:
> ...a permissionless pseudonomous system

The standard spelling is "pseudonymous" (derived from "pseudonym"), not "pseudonomous".

---

## Summary

| ID | Severity | Title |
|----|----------|-------|
| A03-10 | MEDIUM | Contract-level NatSpec contradicts `add` guard implementation for banned accounts |
| A03-11 | LOW | `add` function NatSpec does not document guard conditions |
| A03-12 | LOW | Typo in `remove` parameter NatSpec: "suppor" |
| A03-13 | LOW | `state` function missing `@return` NatSpec tag |
| A03-14 | LOW | `Initialize` event missing `@param` NatSpec tags |
| A03-15 | INFO | Contract-level NatSpec typo: "implicity" |
| A03-16 | INFO | Contract-level NatSpec typo: "pseudonomous" |
