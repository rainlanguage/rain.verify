# Pass 3 - Documentation Audit: Verify.sol

**Agent:** A03
**File:** `src/concrete/Verify.sol`

## Evidence of Reading

**Contract:** `Verify` (lines 186-603)
**Inherits:** `IVerifyV1`, `ICloneableV2`, `AccessControl`

### Functions
| Function | Line | Visibility |
|---|---|---|
| `constructor` | 261 | public |
| `initialize` | 266 | external |
| `state` | 309 | external view |
| `statusAtTime` | 317 | public pure |
| `accountStatusAtTime` | 350 | external view virtual |
| `newState` | 363 | private view |
| `add` | 375 | external |
| `approve` | 420 | external |
| `requestApprove` | 482 | external |
| `ban` | 492 | external |
| `requestBan` | 546 | external |
| `remove` | 558 | external |
| `requestRemove` | 593 | external |

### Modifiers
| Name | Line |
|---|---|
| `onlyApproved` | 355 |

### Types/Errors/Constants
| Name | Kind | Line |
|---|---|---|
| `State` | struct | 29-33 |
| `VerifyConfig` | struct | 41-44 |
| `UNINITIALIZED` | constant | 196 |
| `APPROVER_ADMIN` | constant | 240 |
| `APPROVER` | constant | 242 |
| `REMOVER_ADMIN` | constant | 244 |
| `REMOVER` | constant | 246 |
| `BANNER_ADMIN` | constant | 249 |
| `BANNER` | constant | 252 |

### Events
| Name | Line |
|---|---|
| `Initialize` | 201 |
| `RequestApprove` | 208 |
| `Approve` | 212 |
| `RequestBan` | 220 |
| `Ban` | 225 |
| `RequestRemove` | 232 |
| `Remove` | 237 |

### State variables
| Name | Line |
|---|---|
| `sStates` | 255 |
| `sCallback` | 259 |

## Documentation Check

### Contract-level NatSpec
- `@title Verify` present (line 47). Extensive documentation (lines 47-185) covering trust model, process flow, roles, deduplication. Accurate and thorough.

### Structs
- `State` (lines 22-33): Has NatSpec with `@param` for all three fields. The comment says UNINITIALIZED is `0xFFFFFFFF` (line 23). Accurate: `type(uint32).max` = `0xFFFFFFFF`.
- `VerifyConfig` (lines 35-44): Has NatSpec with `@param` for `admin` and `callback`. Accurate.

### Events (lines 198-237)
- All 7 events have NatSpec with `@param` tags. Accurate descriptions.

### Constants (lines 240-252)
- All 6 role constants have brief NatSpec. Adequate.

### `constructor` (line 261)
- No NatSpec. Trivial `_disableInitializers()` pattern. No finding.

### `initialize` (line 266)
- Has `@inheritdoc ICloneableV2`. Adequate.

### `state` (line 309)
- Has NatSpec: `@param account`, `@return`. Accurate.

### `statusAtTime` (line 317)
- Has NatSpec: `@param lState`, `@param timestamp`, `@return status`. Accurate.

### `accountStatusAtTime` (line 350)
- Has `@inheritdoc IVerifyV1`. Adequate.

### `onlyApproved` modifier (line 355)
- No NatSpec tag but has a plain comment (line 354): "Requires that `msg.sender` is approved as at the current timestamp." Adequate.

### `newState` (line 363)
- Has `@dev` tag. Private function. Adequate.

### `add` (line 375)
- Has NatSpec (lines 367-374): documents behavior for NIL, ADDED, APPROVED, BANNED accounts. `@param data` documented. Accurate.

### `approve` (line 420)
- Has NatSpec (lines 406-419): documents batch behavior, dedup semantics, interaction with bans. `@param evidences` documented. Accurate.

### `requestApprove` (line 482)
- Has NatSpec (lines 479-481): documents behavior and `@param evidences`. Accurate.

### `ban` (line 492)
- Has NatSpec (lines 490-491): `@param evidences` documented. Accurate.

### `requestBan` (line 546)
- Has NatSpec (lines 543-545): documents behavior and `@param evidences`. Accurate.

### `remove` (line 558)
- Has NatSpec (lines 554-557): documents behavior and `@param evidences`. Accurate.

### `requestRemove` (line 593)
- Has NatSpec (lines 587-592): documents that any non-NIL account can request removal, banned accounts use this to appeal. `@param evidences` documented. Accurate.

## Findings

### A03-1 [LOW] State struct NatSpec says uninitialized is 0xFFFFFFFF but add function comment says account "hasn't already been added" checks addedSince < 1

**Location:** `src/concrete/Verify.sol`, lines 22-23 vs lines 324, 381, 388, 433, 508

The `State` struct NatSpec (line 23) says: "If a status is not reached it is left as UNINITIALIZED, i.e. 0xFFFFFFFF." However, the code uses `lState.addedSince < 1` (i.e., checking for zero) to determine if an account has never been added (lines 324, 433, 508). This is because `addedSince` defaults to `0` from EVM storage (not `UNINITIALIZED`/0xFFFFFFFF). Only `approvedSince` and `bannedSince` are set to `UNINITIALIZED` in `newState()`. The struct NatSpec is misleading because it implies all three fields start at `0xFFFFFFFF`, when in reality `addedSince` starts at `0` (EVM default) for accounts that have never been added.

The NatSpec at line 23 says "If a status is not reached it is left as UNINITIALIZED, i.e. 0xFFFFFFFF" but this is only true for `approvedSince` and `bannedSince` after `add` is called. Before `add`, all three fields are `0` (EVM default).
