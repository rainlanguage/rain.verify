# Pass 4 - Code Quality: Verify.sol (A03)

**File:** `/Users/thedavidmeister/Code/rain.verify/src/concrete/Verify.sol`

## Evidence of Thorough Reading

- **Contract name:** `Verify` (line 186)
- **Inherits:** `IVerifyV1`, `ICloneableV2`, `AccessControl`
- **Structs (file-level):**
  - `State` (line 29) - fields: `addedSince` (uint32), `approvedSince` (uint32), `bannedSince` (uint32)
  - `VerifyConfig` (line 41) - fields: `admin` (address), `callback` (address)
- **Constants:**
  - `UNINITIALIZED` - line 196 (uint32, private, type(uint32).max)
  - `APPROVER_ADMIN` - line 238 (bytes32, public)
  - `APPROVER` - line 240 (bytes32, public)
  - `REMOVER_ADMIN` - line 243 (bytes32, public)
  - `REMOVER` - line 245 (bytes32, public)
  - `BANNER_ADMIN` - line 248 (bytes32, public)
  - `BANNER` - line 250 (bytes32, public)
- **State variables:**
  - `sStates` - line 253 (mapping, private)
  - `sCallback` - line 257 (IVerifyCallbackV1, public)
- **Events:**
  - `Initialize` - line 199
  - `RequestApprove` - line 206
  - `Approve` - line 210
  - `RequestBan` - line 218
  - `Ban` - line 223
  - `RequestRemove` - line 230
  - `Remove` - line 235
- **Modifiers:**
  - `onlyApproved` - line 352
- **Functions:**
  - `constructor()` - line 259
  - `initialize(bytes)` - line 264, external initializer
  - `state(address)` - line 306, external view
  - `statusAtTime(State, uint256)` - line 314, public pure
  - `accountStatusAtTime(address, uint256)` - line 347, external view virtual
  - `newState()` - line 360, private view
  - `add(bytes)` - line 367, external
  - `approve(Evidence[])` - line 412, external onlyRole(APPROVER)
  - `requestApprove(Evidence[])` - line 474, external onlyApproved
  - `ban(Evidence[])` - line 484, external onlyRole(BANNER)
  - `requestBan(Evidence[])` - line 538, external onlyApproved
  - `remove(Evidence[])` - line 550, external onlyRole(REMOVER)
  - `requestRemove(Evidence[])` - line 582, external onlyApproved
- **Using directives:**
  - `LibUint256Array for uint256[]`
  - `LibEvidence for uint256[]`
  - `LibVerifyStatus for VerifyStatus`
- **Pragma:** `=0.8.25`

## Findings

### A03-P4-01 [MEDIUM] - Incorrect logic in `add()` function guard (line 370)

The condition at line 370 reads:
```solidity
if (currentStatus.eq(VERIFY_STATUS_APPROVED) && !currentStatus.eq(VERIFY_STATUS_BANNED)) {
    revert AlreadyExists();
}
```

The second branch `!currentStatus.eq(VERIFY_STATUS_BANNED)` is always true when `currentStatus.eq(VERIFY_STATUS_APPROVED)` is true, because `currentStatus` cannot simultaneously be both `APPROVED` and `BANNED`. This means the `&&` with the negated ban check is redundant and the condition simplifies to just `if (currentStatus.eq(VERIFY_STATUS_APPROVED))`. More importantly, this does NOT block re-adding for accounts with status `ADDED` (only `APPROVED`), so an already-added account can re-enter `add()` and get a new state written. Looking at the comment on line 373-378, this appears intentional for the `ADDED` case (allows re-submitting evidence). However, the condition name `AlreadyExists` and the inclusion of the superfluous ban check suggest the logic was meant to cover more cases. In particular, a banned account can call `add()` since `BANNED` is not equal to `APPROVED` -- the banned account's state won't be overwritten (line 380 only writes on `NIL`), but the `RequestApprove` event will emit and the callback fires, which may be undesirable.

### A03-P4-02 [INFO] - Minor typo in NatSpec comment (line 549)

`suppor` should be `support`:
```
/// @param evidences All evidence to suppor the removal.
```

### A03-P4-03 [INFO] - NatSpec comment says "its" but means "it's" (line 287)

`From themselves.` at line 287 is also grammatically awkward after `revokes the X_ADMIN roles.`
