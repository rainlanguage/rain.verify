# Pass 5 - Correctness / Intent Verification: Verify.sol (A03)

**File:** `/Users/thedavidmeister/Code/rain.verify/src/concrete/Verify.sol`
**Date:** 2026-03-16

---

## Evidence of Thorough Reading

### Contract Name
`Verify` (line 186) -- inherits `IVerifyV1`, `ICloneableV2`, `AccessControl`

### Functions

| Name | Line | Visibility | Modifiers |
|------|------|------------|-----------|
| `constructor` | 261 | public (implicit) | -- |
| `initialize` | 266 | external | `initializer` |
| `state` | 309 | external view | -- |
| `statusAtTime` | 317 | public pure | -- |
| `accountStatusAtTime` | 350 | external view virtual | -- |
| `newState` | 363 | private view | -- |
| `add` | 375 | external | -- |
| `approve` | 420 | external | `onlyRole(APPROVER)` |
| `requestApprove` | 482 | external | `onlyApproved` |
| `ban` | 492 | external | `onlyRole(BANNER)` |
| `requestBan` | 546 | external | `onlyApproved` |
| `remove` | 558 | external | `onlyRole(REMOVER)` |
| `requestRemove` | 593 | external | -- |

### Modifier

| Name | Line |
|------|------|
| `onlyApproved` | 355 |

### Types (file-level)

| Name | Kind | Line |
|------|------|------|
| `State` | struct | 29 |
| `VerifyConfig` | struct | 41 |

### Constants

| Name | Type | Value | Line |
|------|------|-------|------|
| `UNINITIALIZED` | `uint32` (private) | `type(uint32).max` | 196 |
| `APPROVER_ADMIN` | `bytes32` (public) | `keccak256("APPROVER_ADMIN")` | 240 |
| `APPROVER` | `bytes32` (public) | `keccak256("APPROVER")` | 242 |
| `REMOVER_ADMIN` | `bytes32` (public) | `keccak256("REMOVER_ADMIN")` | 244 |
| `REMOVER` | `bytes32` (public) | `keccak256("REMOVER")` | 246 |
| `BANNER_ADMIN` | `bytes32` (public) | `keccak256("BANNER_ADMIN")` | 250 |
| `BANNER` | `bytes32` (public) | `keccak256("BANNER")` | 252 |

### Errors (imported from `src/err/ErrVerify.sol`)

| Name | Purpose |
|------|---------|
| `ZeroAdmin` | Thrown when admin is address(0) in initialize |
| `NotApproved` | Thrown when msg.sender is not approved |
| `AlreadyExists` | Thrown when APPROVED or BANNED account calls add |
| `UnknownAccount` | Thrown when NIL account calls requestRemove |

### Events

| Name | Line |
|------|------|
| `Initialize(address, VerifyConfig)` | 201 |
| `RequestApprove(address, Evidence)` | 208 |
| `Approve(address, Evidence)` | 212 |
| `RequestBan(address, Evidence)` | 220 |
| `Ban(address, Evidence)` | 225 |
| `RequestRemove(address, Evidence)` | 232 |
| `Remove(address, Evidence)` | 237 |

### State Variables

| Name | Type | Visibility | Line |
|------|------|------------|------|
| `sStates` | `mapping(address => State)` | private | 255 |
| `sCallback` | `IVerifyCallbackV1` | public | 259 |

---

## Verification

### 1. Every named function does what its name and NatSpec claim

- **`constructor`** (line 261): Calls `_disableInitializers()`. Prevents initialization of the implementation contract. Correct.
- **`initialize`** (line 266): Decodes `VerifyConfig`, validates admin is not zero, initializes AccessControl, sets up role admin hierarchy, grants all admin roles to `config.admin`, sets callback, emits `Initialize`, returns `ICLONEABLE_V2_SUCCESS`. Correct.
- **`state`** (line 309): Returns the raw `State` struct for an account. NatSpec says "Typed accessor into states." Correct.
- **`statusAtTime`** (line 317): Derives a single `VerifyStatus` from a `State` and timestamp. Priority: NIL (not added) > BANNED > APPROVED > ADDED > NIL (future). Correct. (See pre-existing finding re: timestamp overflow.)
- **`accountStatusAtTime`** (line 350): Fetches state from storage and delegates to `statusAtTime`. Matches `IVerifyV1` interface. Correct.
- **`newState`** (line 363): Returns `State(uint32(block.timestamp), UNINITIALIZED, UNINITIALIZED)`. Creates a state with `addedSince` set to now and both `approvedSince`/`bannedSince` uninitialized. Correct.
- **`add`** (line 375): Allows `msg.sender` to add themselves. Reverts for APPROVED or BANNED accounts with `AlreadyExists`. ADDED accounts can call again to resubmit evidence without state change. NIL accounts get a new state. Emits `RequestApprove`. Fires callback if set. NatSpec matches implementation. Correct.
- **`approve`** (line 420): APPROVER role required. Batch processes approvals. Implicitly adds accounts not yet added. Sets `approvedSince` only if uninitialized. Always emits `Approve` event. Fires `afterAdd`/`afterApprove` callbacks for state changes. NatSpec thoroughly documents batch semantics and interaction with banned accounts. Correct.
- **`requestApprove`** (line 482): Only approved accounts can call. Emits `RequestApprove` for each evidence. Correct.
- **`ban`** (line 492): BANNER role required. Batch processes bans. Implicitly adds accounts not yet added. Sets `bannedSince` only if uninitialized. Always emits `Ban`. Fires `afterAdd`/`afterBan` callbacks. Correct.
- **`requestBan`** (line 546): Only approved accounts can call. Emits `RequestBan`. Correct.
- **`remove`** (line 558): REMOVER role required. Deletes state for accounts with `addedSince > 0`. Always emits `Remove`. Fires `afterRemove` callback. Correct.
- **`requestRemove`** (line 593): Any non-NIL account can call. Reverts with `UnknownAccount` if caller is NIL. Emits `RequestRemove`. Correct.

### 2. Constants match documented meaning

- `UNINITIALIZED = type(uint32).max` (0xFFFFFFFF): Matches NatSpec on line 23 ("0xFFFFFFFF") and struct field documentation ("else 0xFFFFFFFF"). Correct.
- `ICLONEABLE_V2_SUCCESS`: Imported from `rain.factory` and returned by `initialize()`. Matches interface requirement. Correct.
- Role constants (`APPROVER`, `APPROVER_ADMIN`, `REMOVER`, `REMOVER_ADMIN`, `BANNER`, `BANNER_ADMIN`): All use `keccak256` of their string names, following OpenZeppelin convention. Used consistently in `onlyRole` guards and role admin setup. Correct.
- Status constants (`VERIFY_STATUS_NIL = 0`, `VERIFY_STATUS_ADDED = 1`, `VERIFY_STATUS_APPROVED = 2`, `VERIFY_STATUS_BANNED = 3`): Imported from the interface. Used consistently in `statusAtTime` and guards. Correct.

### 3. Error conditions match their names

- **`ZeroAdmin`**: Triggered at line 268-269 when `config.admin == address(0)`. NatSpec: "Thrown when Verify is initialised with a zero address for admin." Correct.
- **`NotApproved`**: Triggered in `onlyApproved` modifier (line 356) when `msg.sender` status is not APPROVED at current timestamp. NatSpec: "Thrown when msg.sender is not approved at the current timestamp." Correct.
- **`AlreadyExists`**: Triggered at line 378-379 in `add()` when status is APPROVED or BANNED. NatSpec: "Thrown when an account already exists in the system and is being added." The `||` correctly catches both APPROVED and BANNED statuses. Correct.
- **`UnknownAccount`**: Triggered at line 594-595 in `requestRemove()` when caller status is NIL. NatSpec: "Thrown when a NIL account attempts an action that requires the account to have been previously added to the system." Correct.

### 4. Interface conformance

**IVerifyV1**: Requires `accountStatusAtTime(address, uint256) external view returns (VerifyStatus)`. Implemented at line 350 with matching signature (marked `virtual`). Conforms.

**ICloneableV2**: Requires `initialize(bytes calldata data) external returns (bytes32 success)`. Implemented at line 266 with `initializer` modifier. Returns `ICLONEABLE_V2_SUCCESS`. Conforms.

### 5. State machine transitions

The intended state machine:

```
NIL --> ADDED (via add, or implicit add in approve/ban)
ADDED --> APPROVED (via approve)
ADDED --> BANNED (via ban)
APPROVED --> BANNED (via ban)
ANY --> NIL (via remove)
```

**NIL -> ADDED:**
- `add()` line 388-389: if status is NIL, writes `newState()`. Correct.
- `approve()` line 433-434: if `addedSince < 1`, creates `newState()` (implicit add). Correct.
- `ban()` line 508-509: if `addedSince < 1`, creates `newState()` (implicit add). Correct.

**ADDED -> APPROVED:**
- `approve()` line 450-454: if `approvedSince == UNINITIALIZED`, sets `approvedSince = block.timestamp` and writes to storage. Correct.

**ADDED/APPROVED -> BANNED:**
- `ban()` line 516-518: if `bannedSince == UNINITIALIZED`, sets `bannedSince = block.timestamp` and writes to storage. Correct.
- `statusAtTime` line 329: banned takes priority over approved regardless of temporal ordering. Correct.

**ANY -> NIL (remove):**
- `remove()` line 566-571: if `addedSince > 0`, deletes the state mapping entry. This zeroes all fields. `statusAtTime` treats `addedSince == 0` as NIL. Correct.

**Re-add after remove:**
- After `remove`, state is zeroed. `add()` evaluates status as NIL, writes `newState()`. Correct.

**All transitions are correct.**

### 6. `accountStatusAtTime` correctly resolves at arbitrary timestamps

`accountStatusAtTime` (line 350) fetches `sStates[account]` and calls `statusAtTime`. The resolution logic:

1. `addedSince == 0` -> NIL (never added or was removed)
2. `bannedSince <= timestamp` -> BANNED (ban takes highest priority)
3. `approvedSince <= timestamp` -> APPROVED
4. `addedSince <= timestamp` -> ADDED
5. else -> NIL (querying a time before the account was added)

This correctly resolves status at arbitrary timestamps with proper priority ordering. The fallback to NIL for timestamps before the add is correct.

Pre-existing issue: when `timestamp >= type(uint32).max`, the sentinel `UNINITIALIZED` (which equals `type(uint32).max`) is treated as "in the past", causing incorrect results. See prior finding A03-P5-01 (not re-filed).

### 7. `add()` correctly blocks APPROVED and BANNED

Line 378: `if (currentStatus.eq(VERIFY_STATUS_APPROVED) || currentStatus.eq(VERIFY_STATUS_BANNED))`. The `||` operator correctly catches both APPROVED and BANNED statuses, reverting with `AlreadyExists`. ADDED accounts are allowed through to resubmit evidence. NIL accounts are allowed through to create their initial state. Correct.

### 8. `requestRemove()` allows any non-NIL correctly

Line 594: `if (statusAtTime(sStates[msg.sender], block.timestamp).eq(VERIFY_STATUS_NIL)) { revert UnknownAccount(); }`. This reverts only for NIL accounts, allowing ADDED, APPROVED, and BANNED accounts to request removal. NatSpec explicitly documents that banned accounts need this as their only on-chain appeal mechanism. Correct.

---

## Findings

No new findings. All named functions, constants, errors, state transitions, and interface conformance match their documented intent.

### Pre-existing Issues Confirmed (Not Re-filed)

- **A03-P5-01 (LOW):** `statusAtTime` returns incorrect status when `timestamp >= type(uint32).max`. Fix proposed in `.fixes/A03-P5-01.md` but not yet applied.
- **A03-P5-02 (INFO):** `newState` NatSpec says "for use by `add` and `approve`" but `ban()` also calls it.
