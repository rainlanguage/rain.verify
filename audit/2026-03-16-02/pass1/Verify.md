# Pass 1 (Security) -- Verify.sol

**Agent:** A03
**File:** `src/concrete/Verify.sol`
**Date:** 2026-03-16

## Evidence of Thorough Reading

### Contract

`Verify` (line 186), inherits `IVerifyV1`, `ICloneableV2`, `AccessControl`

### Structs

| Name | Line | Fields |
|------|------|--------|
| `State` | 29 | `uint32 addedSince`, `uint32 approvedSince`, `uint32 bannedSince` |
| `VerifyConfig` | 41 | `address admin`, `address callback` |

### Constants

| Name | Line | Value |
|------|------|-------|
| `UNINITIALIZED` | 196 | `type(uint32).max` (0xFFFFFFFF) |
| `APPROVER_ADMIN` | 240 | `keccak256("APPROVER_ADMIN")` |
| `APPROVER` | 242 | `keccak256("APPROVER")` |
| `REMOVER_ADMIN` | 244 | `keccak256("REMOVER_ADMIN")` |
| `REMOVER` | 246 | `keccak256("REMOVER")` |
| `BANNER_ADMIN` | 249 | `keccak256("BANNER_ADMIN")` |
| `BANNER` | 252 | `keccak256("BANNER")` |

### Events

| Name | Line |
|------|------|
| `Initialize` | 201 |
| `RequestApprove` | 208 |
| `Approve` | 212 |
| `RequestBan` | 220 |
| `Ban` | 225 |
| `RequestRemove` | 232 |
| `Remove` | 237 |

### State Variables

| Name | Line | Type |
|------|------|------|
| `sStates` | 255 | `mapping(address => State) private` |
| `sCallback` | 259 | `IVerifyCallbackV1 public` |

### Functions

| Name | Line | Visibility | Modifiers |
|------|------|------------|-----------|
| `constructor()` | 261 | (internal) | none |
| `initialize(bytes)` | 266 | external | `initializer` |
| `state(address)` | 309 | external view | none |
| `statusAtTime(State, uint256)` | 317 | public pure | none |
| `accountStatusAtTime(address, uint256)` | 350 | external view virtual | none |
| `newState()` | 363 | private view | none |
| `add(bytes)` | 375 | external | none |
| `approve(Evidence[])` | 420 | external | `onlyRole(APPROVER)` |
| `requestApprove(Evidence[])` | 482 | external | `onlyApproved` |
| `ban(Evidence[])` | 492 | external | `onlyRole(BANNER)` |
| `requestBan(Evidence[])` | 546 | external | `onlyApproved` |
| `remove(Evidence[])` | 558 | external | `onlyRole(REMOVER)` |
| `requestRemove(Evidence[])` | 593 | external | none (checks non-NIL inline) |

### Modifiers

| Name | Line |
|------|------|
| `onlyApproved` | 355 |

### Errors (from `src/err/ErrVerify.sol`)

| Name | Line (in ErrVerify.sol) |
|------|------------------------|
| `ZeroAdmin` | 6 |
| `NotApproved` | 9 |
| `AlreadyExists` | 12 |
| `UnknownAccount` | 16 |

## Security Review

### 1. Access Control and Privilege Escalation

- `approve`: gated by `onlyRole(APPROVER)`. Correct.
- `ban`: gated by `onlyRole(BANNER)`. Correct.
- `remove`: gated by `onlyRole(REMOVER)`. Correct.
- `requestApprove` / `requestBan`: gated by `onlyApproved` modifier (checks `msg.sender` is APPROVED at `block.timestamp`). Correct.
- `requestRemove`: inline check rejects NIL accounts; allows ADDED, APPROVED, and BANNED. Correct per spec (banned accounts need a mechanism to appeal).
- `add`: open to any `msg.sender` -- by design, only adds the caller's own address.
- Admin role hierarchy: `APPROVER_ADMIN` self-admins and admins `APPROVER`; same for `REMOVER_ADMIN`/`REMOVER` and `BANNER_ADMIN`/`BANNER`. `DEFAULT_ADMIN_ROLE` (0x00) is NOT granted to anyone, so the OpenZeppelin default admin cannot interfere. Correct separation.
- `initialize` is protected by `initializer` modifier preventing re-initialization. Correct.
- Constructor calls `_disableInitializers()` preventing initialization of the implementation contract. Correct.

### 2. add() Guard Logic

Line 378: Reverts with `AlreadyExists` for both APPROVED and BANNED accounts. NIL accounts get a new state; ADDED accounts can re-call `add` to submit additional evidence without state change. This matches the documented spec.

### 3. requestRemove() Access

Line 594: Reverts with `UnknownAccount` only for NIL accounts. ADDED, APPROVED, and BANNED accounts can all call it. This is correct -- banned accounts need this as their only on-chain appeal mechanism.

### 4. Reentrancy Around Callbacks

All callback calls occur AFTER state changes:
- `add()`: storage write at line 389, callback at line 402.
- `approve()`: storage writes inside loop (line 454), callbacks at lines 469/473 after loop completes.
- `ban()`: storage writes inside loop (line 518), callbacks at lines 533/537 after loop completes.
- `remove()`: storage delete inside loop (line 571), callback at line 580 after loop completes.

The callback interface documentation explicitly notes that all callbacks happen after state changes and all actions are bound to `msg.sender` authority, so reentrancy does not grant additional capabilities. Sound.

### 5. State Consistency and Batch Operation Safety

- Batch `approve`/`ban`/`remove` are infallible per-account: duplicate accounts in a batch are handled gracefully (events always emit, state changes only on first occurrence, storage re-read from `sStates` each iteration).
- Implicit add in `approve` and `ban`: when an account has never been added (`addedSince < 1`), `newState()` creates a fresh state. Since `newState()` sets `approvedSince = UNINITIALIZED` and `bannedSince = UNINITIALIZED`, the subsequent approval/ban check always passes, ensuring storage is written. No dangling in-memory state.
- Callbacks only receive evidences for accounts whose state actually changed (deduplication via separate `additions`/`approvals`/`bans`/`removals` counters and `truncate`). Correct.

### 6. Arithmetic in Unchecked Blocks

All `unchecked` blocks contain only loop counter increments (`i++`) and evidence counters (`additions++`, `approvals++`, `bans++`, `removals++`). These are bounded by `evidences.length` which is limited by calldata/memory size. No overflow risk.

### 7. Custom Errors

All reverts use custom errors:
- `ZeroAdmin` (line 269)
- `AlreadyExists` (line 379)
- `NotApproved` (line 357 via modifier)
- `UnknownAccount` (line 595)
- `onlyRole` from OpenZeppelin 5.x uses `AccessControlUnauthorizedAccount`. Correct.
- `initializer` modifier uses `InvalidInitialization`. Correct.

No `require` statements with string messages exist.

### 8. statusAtTime() Priority Logic

The priority order is: NIL (uninitialized) > BANNED > APPROVED > ADDED > NIL (future timestamp). BANNED takes absolute priority over APPROVED, which is critical for security -- a banned account cannot be "un-banned" by a subsequent approval. The only way to reset a ban is via `remove` (which requires the REMOVER role). Correct.

## Findings

No findings.
