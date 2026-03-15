# Audit Pass 5 (Correctness / Intent Verification) -- Verify.sol

**Agent:** A03
**File:** `/Users/thedavidmeister/Code/rain.verify/src/concrete/Verify.sol`
**Date:** 2026-03-15

---

## Evidence of Thorough Reading

### Contract Name
`Verify` (line 186) -- inherits `IVerifyV1`, `ICloneableV2`, `AccessControl`

### Every Function/Method and Its Line Number

| Name | Visibility | Modifiers | Line |
|------|-----------|-----------|------|
| `constructor()` | public | -- | 259 |
| `initialize(bytes)` | external | `initializer` | 264 |
| `state(address)` | external view | -- | 306 |
| `statusAtTime(State, uint256)` | public pure | -- | 314 |
| `accountStatusAtTime(address, uint256)` | external view virtual | -- | 347 |
| `newState()` | private view | -- | 360 |
| `add(bytes)` | external | -- | 367 |
| `approve(Evidence[])` | external | `onlyRole(APPROVER)` | 412 |
| `requestApprove(Evidence[])` | external | `onlyApproved` | 474 |
| `ban(Evidence[])` | external | `onlyRole(BANNER)` | 484 |
| `requestBan(Evidence[])` | external | `onlyApproved` | 538 |
| `remove(Evidence[])` | external | `onlyRole(REMOVER)` | 550 |
| `requestRemove(Evidence[])` | external | `onlyApproved` | 582 |

### Modifier

| Name | Line |
|------|------|
| `onlyApproved` | 352 |

### Types Defined (file-level)

| Name | Kind | Line |
|------|------|------|
| `State` | struct | 29 |
| `VerifyConfig` | struct | 41 |

### Constants

| Name | Type | Visibility | Value | Line |
|------|------|-----------|-------|------|
| `UNINITIALIZED` | uint32 | private | `type(uint32).max` (0xFFFFFFFF) | 196 |
| `APPROVER_ADMIN` | bytes32 | public | `keccak256("APPROVER_ADMIN")` | 238 |
| `APPROVER` | bytes32 | public | `keccak256("APPROVER")` | 240 |
| `REMOVER_ADMIN` | bytes32 | public | `keccak256("REMOVER_ADMIN")` | 242 |
| `REMOVER` | bytes32 | public | `keccak256("REMOVER")` | 244 |
| `BANNER_ADMIN` | bytes32 | public | `keccak256("BANNER_ADMIN")` | 248 |
| `BANNER` | bytes32 | public | `keccak256("BANNER")` | 250 |

### Errors (imported from `src/err/ErrVerify.sol`)

| Name | Purpose | ErrVerify.sol Line |
|------|---------|-------------------|
| `ZeroAdmin` | Thrown when admin is address(0) in initialize | 6 |
| `NotApproved` | Thrown when msg.sender is not approved | 9 |
| `AlreadyExists` | Thrown when account already exists in add() | 12 |

### Events

| Name | Line |
|------|------|
| `Initialize` | 199 |
| `RequestApprove` | 206 |
| `Approve` | 210 |
| `RequestBan` | 218 |
| `Ban` | 223 |
| `RequestRemove` | 230 |
| `Remove` | 235 |

### State Variables

| Name | Type | Visibility | Line |
|------|------|-----------|------|
| `sStates` | `mapping(address => State)` | private | 253 |
| `sCallback` | `IVerifyCallbackV1` | public | 257 |

---

## Verification: Interface Conformance

### IVerifyV1 Conformance
`IVerifyV1` requires a single function:
```
function accountStatusAtTime(address account, uint256 timestamp) external view returns (VerifyStatus);
```
`Verify` implements this at line 347 with matching signature (marked `virtual`). The `virtual` keyword is a superset of the interface requirement and is valid. **Conforms.**

### ICloneableV2 Conformance
`ICloneableV2` requires:
```
function initialize(bytes calldata data) external returns (bytes32 success);
```
`Verify` implements this at line 264 with matching signature plus the `initializer` modifier. Returns `ICLONEABLE_V2_SUCCESS` on success. **Conforms.**

---

## Verification: State Machine Transitions

The intended state machine is:

```
NIL --> ADDED (via add, or implicit add in approve/ban)
ADDED --> APPROVED (via approve)
ADDED --> BANNED (via ban)
APPROVED --> BANNED (via ban)
ANY --> NIL (via remove, which deletes all state)
```

### Transition: NIL -> ADDED
- `add()` line 380-381: if `currentStatus == NIL`, writes `newState()`. Correct.
- `approve()` line 425-426: if `addedSince < 1`, creates `newState()` (implicit add). Correct.
- `ban()` line 500-501: if `addedSince < 1`, creates `newState()` (implicit add). Correct.

### Transition: ADDED -> APPROVED
- `approve()` line 442-446: if `approvedSince == UNINITIALIZED`, sets `approvedSince = block.timestamp` and writes. Correct.

### Transition: ADDED/APPROVED -> BANNED
- `ban()` line 508-510: if `bannedSince == UNINITIALIZED`, sets `bannedSince = block.timestamp` and writes. Correct.
- `statusAtTime` line 326: banned takes priority over approved regardless of temporal ordering. Correct.

### Transition: ANY -> NIL (remove)
- `remove()` line 558-563: if `addedSince > 0`, deletes the state mapping entry. This resets all fields to zero, which `statusAtTime` treats as NIL. Correct.

### Re-add after remove
- After `remove`, state is zeroed. `add()` line 380: `currentStatus == NIL` is true, so `newState()` is written. Correct.
- The banned-account-can-call-add issue (A03-1) applies here: a removed-then-re-adding path works, but the guard does not prevent banned accounts from calling add (which is the known issue).

**State machine transitions are correct**, modulo the known A03-1 guard bug on line 370.

---

## Verification: `accountStatusAtTime` Resolution

`accountStatusAtTime` (line 347) delegates to `statusAtTime` (line 314). The resolution logic:

1. `addedSince == 0` -> NIL (line 321)
2. `bannedSince <= timestamp` -> BANNED (line 326) -- ban takes priority
3. `approvedSince <= timestamp` -> APPROVED (line 331)
4. `addedSince <= timestamp` -> ADDED (line 336)
5. else -> NIL (line 341) -- querying a time before the account was added

This correctly resolves status at arbitrary timestamps with proper priority ordering: ban > approval > add. The fallback to NIL for future timestamps is correct.

**See finding A03-P5-01 for an edge case when timestamp exceeds uint32 range.**

---

## Verification: `add` Guard Logic

Line 370:
```solidity
if (currentStatus.eq(VERIFY_STATUS_APPROVED) && !currentStatus.eq(VERIFY_STATUS_BANNED)) {
    revert AlreadyExists();
}
```

This is the known A03-1 bug. The `&&` should be `||`. The `!currentStatus.eq(VERIFY_STATUS_BANNED)` branch is always true when the first branch is true (a status cannot be both APPROVED and BANNED simultaneously since `VerifyStatus` is a single `uint256`). As a result:
- APPROVED accounts correctly revert (the first condition is sufficient).
- BANNED accounts do NOT revert and can call `add`, emitting events and triggering callbacks.
- ADDED accounts do NOT revert, allowing evidence resubmission (intentional per comments on lines 373-378).

**Known issue, not re-filed.**

---

## Verification: Constants and Magic Numbers

- `UNINITIALIZED = type(uint32).max` (0xFFFFFFFF): Matches the NatSpec on line 23 ("0xFFFFFFFF") and the struct documentation ("else 0xFFFFFFFF"). Correct.
- `ICLONEABLE_V2_SUCCESS = keccak256("ICloneableV2.initialize")`: Imported from `rain.factory` and returned by `initialize()`. Matches the interface requirement. Correct.
- Role constants use `keccak256` of their string names, following OpenZeppelin conventions. Correct.
- `VERIFY_STATUS_NIL = 0`, `VERIFY_STATUS_ADDED = 1`, `VERIFY_STATUS_APPROVED = 2`, `VERIFY_STATUS_BANNED = 3`: Defined in the interface. Used consistently throughout. Correct.

---

## Verification: Error Conditions

- `ZeroAdmin`: Triggered at line 266-268 when `config.admin == address(0)`. Matches NatSpec "Thrown when Verify is initialised with a zero address for admin." Correct.
- `NotApproved`: Triggered in `onlyApproved` modifier (line 353) when `msg.sender` status is not APPROVED at current timestamp. Matches NatSpec "Thrown when msg.sender is not approved at the current timestamp." Correct.
- `AlreadyExists`: Triggered at line 370-372 in `add()`. Intended to prevent already-existing accounts from re-adding. Partially correct due to A03-1 bug (does not catch BANNED accounts).

---

## Verification: NatSpec Accuracy

- `statusAtTime` NatSpec (lines 310-313): Claims to derive "a single Status from a State and a reference timestamp." Implementation does exactly this. Accurate.
- `accountStatusAtTime` NatSpec: Uses `@inheritdoc IVerifyV1`. Interface docs describe returning "the status of the account at the specified timestamp." Implementation fetches state and delegates to `statusAtTime`. Accurate.
- `add` NatSpec (lines 364-366): Says "An account adds their own verification evidence" and "Internally msg.sender is used." Accurate but incomplete (does not document guard conditions -- covered in A03-11 from pass 3).
- `approve` NatSpec (lines 398-410): Thoroughly documents batch semantics, idempotency, interaction with banned accounts. Accurate.
- `ban` NatSpec (lines 482-483): Brief but accurate.
- `remove` NatSpec (lines 546-548): States "A REMOVER can scrub state mapping" and "A malicious account MUST be banned rather than removed." Accurate.
- `newState` NatSpec (line 359): "@dev Builds a new State for use by add and approve." Missing mention of `ban` which also uses it. See A03-P5-02.
- Contract-level NatSpec: Extensive and mostly accurate. Known discrepancy with banned-account add behavior documented in A03-10 from pass 3.

---

## Findings

### A03-P5-01 [LOW] -- `statusAtTime` returns incorrect status when `timestamp > type(uint32).max`

**Location:** `Verify.sol` lines 314-344

**Description:**

The `statusAtTime` function accepts `uint256 timestamp` but the `State` struct fields are `uint32`. The sentinel value `UNINITIALIZED` is `type(uint32).max` (4294967295). When `timestamp` exceeds `type(uint32).max`, the comparison `lState.bannedSince <= timestamp` evaluates to true even when `bannedSince == UNINITIALIZED`, because `UNINITIALIZED` (4294967295) is less than any `uint256` value above that.

Concretely: for an account that has been added but never banned, calling `accountStatusAtTime(account, 4294967296)` will return `VERIFY_STATUS_BANNED` instead of `VERIFY_STATUS_ADDED` or `VERIFY_STATUS_APPROVED`.

Similarly, an account that has been added but never approved would incorrectly show as APPROVED for timestamps above the UNINITIALIZED threshold.

**Impact:** Low in practice because `block.timestamp` will not exceed `type(uint32).max` until the year 2106. However, the function signature accepts `uint256` without input validation, so off-chain callers or integrating contracts passing arbitrary timestamps will receive incorrect results. The interface `IVerifyV1` defines the parameter as `uint256`, so this is a conformance issue with no easy fix without changing the interface.

**Recommendation:** Add a check at the top of `statusAtTime`:
```solidity
if (timestamp > type(uint32).max) {
    timestamp = type(uint32).max - 1;
}
```
Or revert for out-of-range timestamps:
```solidity
require(timestamp <= type(uint32).max, "timestamp overflow");
```

---

### A03-P5-02 [INFO] -- `newState` NatSpec omits `ban` as a caller

**Location:** `Verify.sol` line 359

**Description:**

The `@dev` comment reads: "Builds a new State for use by add and approve." However, `newState()` is also called by `ban()` at line 501 for implicit adds. The NatSpec should mention all three callers: `add`, `approve`, and `ban`.

---

### A03-P5-03 [INFO] -- `remove` guard uses `addedSince > 0` instead of `addedSince >= 1`

**Location:** `Verify.sol` line 558

**Description:**

The `remove` function checks `lState.addedSince > 0` to determine if an account exists. Throughout the rest of the codebase, the equivalent nil-check is `lState.addedSince < 1` (lines 321, 425, 500). The `> 0` vs `< 1` inconsistency is cosmetic for `uint32` (they are logically equivalent) but the pattern difference reduces readability. The `statusAtTime` function and `approve`/`ban` functions all use `< 1`; `remove` is the only function using `> 0`.

---

## Summary

| ID | Severity | Title |
|----|----------|-------|
| A03-P5-01 | LOW | `statusAtTime` returns incorrect status when `timestamp > type(uint32).max` |
| A03-P5-02 | INFO | `newState` NatSpec omits `ban` as a caller |
| A03-P5-03 | INFO | `remove` guard uses `addedSince > 0` instead of `addedSince >= 1` |

### Previously Known Issues Confirmed
- **A03-1 (MEDIUM):** `&&` vs `||` bug on line 370 in `add()`. Confirmed still present. Not re-filed.
- **A03-10 (MEDIUM):** NatSpec contradicts implementation regarding banned accounts calling `add`. Confirmed. Not re-filed.
