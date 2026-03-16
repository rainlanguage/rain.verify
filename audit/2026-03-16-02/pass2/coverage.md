# Pass 2 -- Test Coverage Audit (Agents A01-A07)

Audit date: 2026-03-16
Audit namespace: `2026-03-16-02`

---

## A01 -- `src/abstract/VerifyCallback.sol`

### Evidence of reading

- **Contract**: `VerifyCallback` (abstract), line 12
- **Functions**:
  - `verifyCallbackInit()` internal, line 13
  - `afterAdd(address, Evidence[])` public virtual, line 17
  - `afterApprove(address, Evidence[])` public virtual, line 19
  - `afterBan(address, Evidence[])` public virtual, line 21
  - `afterRemove(address, Evidence[])` public virtual, line 23
- **Inherits**: `IVerifyCallbackV1`, `Ownable`
- **Modifier used**: `onlyOwner` on all four `after*` functions, `onlyInitializing` on `verifyCallbackInit`

### Test mapping

`VerifyCallback` is abstract and has no dedicated test file. It is exercised indirectly through:

| Source function | Tests |
|---|---|
| `verifyCallbackInit()` | `AutoApprove.t.sol::testConstruction` (calls `initialize` which calls `verifyCallbackInit`) |
| `afterAdd` | `AutoApprove.t.sol::testAfterAddRevertsNonOwner`, `testAfterAddAutoApproves`, etc. (AutoApprove overrides `afterAdd`) |
| `afterApprove` | No test exercises the base no-op `afterApprove` in isolation |
| `afterBan` | No test exercises the base no-op `afterBan` in isolation |
| `afterRemove` | No test exercises the base no-op `afterRemove` in isolation |

### Coverage gaps

The base no-op implementations of `afterApprove`, `afterBan`, `afterRemove` are tested indirectly through `AutoApprove` (which inherits the no-op for all three), and the `Verify.callback.t.sol` `MockCallback` directly implements the interface without going through `VerifyCallback`. The `onlyOwner` guard is tested via `AutoApprove.t.sol::testAfterAddRevertsNonOwner` for `afterAdd`.

No coverage-specific finding needed -- the base no-ops have no logic to test, and the `onlyOwner` modifier is an OZ primitive tested by its own suite. The `afterAdd` override path is well-tested via AutoApprove.

---

## A02 -- `src/concrete/AutoApprove.sol`

### Evidence of reading

- **Contract**: `AutoApprove`, line 36
- **Error**: `BadEvidenceLength(uint256)`, line 27
- **Constant**: `CAN_APPROVE_ENTRYPOINT = SourceIndexV2.wrap(0)`, line 29
- **Struct**: `AutoApproveConfig { address owner; EvaluableV4 evaluable; }`, line 31
- **State variable**: `sEvaluable`, line 46
- **Event**: `Initialize(address, AutoApproveConfig)`, line 44
- **Functions**:
  - `constructor()`, line 48
  - `initialize(bytes)`, line 53
  - `afterAdd(address, Evidence[])`, line 65
- **Inherits**: `ICloneableV2`, `VerifyCallback`, `IInterpreterCallerV4`

### Test mapping

Test file: `test/AutoApprove.t.sol`

| Source function / path | Tests |
|---|---|
| `constructor()` | `testConstruction` (implicit via clone pattern) |
| `initialize` | `testConstruction`, `testConstructionDoubleInitializeReverts` |
| `afterAdd` -- happy path (auto-approve) | `testAfterAddAutoApproves`, `testAfterAddFullIntegration` |
| `afterAdd` -- denial (return 0) | `testAfterAddDenies` |
| `afterAdd` -- `BadEvidenceLength` (0 bytes) | `testAfterAddRevertsEmptyEvidence` |
| `afterAdd` -- `BadEvidenceLength` (31 bytes) | `testAfterAddReverts31ByteEvidence` |
| `afterAdd` -- `BadEvidenceLength` (33 bytes) | `testAfterAddReverts33ByteEvidence` |
| `afterAdd` -- `onlyOwner` revert | `testAfterAddRevertsNonOwner` |
| `afterAdd` -- empty stack | `testAfterAddEmptyStackNoApproval` |
| `afterAdd` -- reentrancy safety | `testAfterAddReentrancySafe` |
| `afterAdd` -- mixed evidence | `testAfterAddMixedEvidenceLengths` |

### Coverage gaps

No findings -- AutoApprove is well-tested including edge cases for evidence length, empty stack, reentrancy, and denial path.

---

## A03 -- `src/concrete/Verify.sol`

### Evidence of reading

- **Contract**: `Verify`, line 186
- **Structs**: `State { uint32 addedSince; uint32 approvedSince; uint32 bannedSince; }` (line 29), `VerifyConfig { address admin; address callback; }` (line 41)
- **Constants**: `UNINITIALIZED = type(uint32).max` (line 196), `APPROVER_ADMIN` (line 240), `APPROVER` (line 242), `REMOVER_ADMIN` (line 245), `REMOVER` (line 247), `BANNER_ADMIN` (line 250), `BANNER` (line 252)
- **State variables**: `sStates` mapping (line 255), `sCallback` (line 259)
- **Events**: `Initialize` (line 201), `RequestApprove` (line 208), `Approve` (line 212), `RequestBan` (line 219), `Ban` (line 225), `RequestRemove` (line 232), `Remove` (line 237)
- **Functions**:
  - `constructor()`, line 261
  - `initialize(bytes)`, line 266
  - `state(address)`, line 309
  - `statusAtTime(State, uint256)`, line 317
  - `accountStatusAtTime(address, uint256)`, line 350
  - `newState()` private, line 363
  - `add(bytes)`, line 375
  - `approve(Evidence[])`, line 420
  - `requestApprove(Evidence[])`, line 482
  - `ban(Evidence[])`, line 492
  - `requestBan(Evidence[])`, line 546
  - `remove(Evidence[])`, line 558
  - `requestRemove(Evidence[])`, line 593
- **Modifier**: `onlyApproved`, line 355

### Test mapping

Test files: `Verify.construction.t.sol`, `Verify.add.t.sol`, `Verify.approve.t.sol`, `Verify.ban.t.sol`, `Verify.remove.t.sol`, `Verify.state.t.sol`, `Verify.status.t.sol`, `Verify.admin.t.sol`, `Verify.adminDuplicateActions.t.sol`, `Verify.requestApprove.t.sol`, `Verify.requestBan.t.sol`, `Verify.requestRemove.t.sol`, `Verify.callback.t.sol`

| Source function | Tests |
|---|---|
| `constructor` | `testConstructionDoubleInitializeReverts` (implicit via clone) |
| `initialize` | `testConstructionZeroAdminReverts`, `testConstructionDoubleInitializeReverts`, `testConstructionInitializeReturnsSuccess`, `testConstructionAdminRoles`, `testConstructionEmitsInitialize`, `testConstructionCallbackAddress`, `testConstructionRoleAdminRelationships`, `testConstructionSelfAdminRelationships` |
| `state()` | `testStateNil`, `testStateAfterAdd`, `testStateAfterApprove`, `testStateAfterBan`, `testStateAfterRemove`, `testStateFullLifecycle` |
| `statusAtTime()` | `testStatusNilState`, `testStatusNilBeforeAdded`, `testStatusAdded`, `testStatusApproved`, `testStatusAddedBeforeApproval`, `testStatusBanned`, `testStatusBannedOverridesApproved`, `testStatusFullLifecycle` |
| `accountStatusAtTime()` | Used transitively in nearly every test |
| `add()` | `testAddFromNIL`, `testAddFromADDED`, `testAddFromAPPROVED`, `testAddFromBANNED` |
| `approve()` | `testApproveImplicitlyAddsNilAccount`, `testApproveEmitsEvent`, `testOnlyApproverRoleCanApprove`, `testApproverCannotRemove`, `testApproverCannotBan`, `testAddRevertsAfterApproval`, `testDuplicateApproveIsIdempotent` |
| `requestApprove()` | `testRequestApproveEmitsEvent`, `testRequestApproveDoesNotOverrideState`, `testRequestApproveIndependentSigners` |
| `ban()` | `testBanNILAccount`, `testBannerCannotApprove`, `testBannerCannotRemove`, `testOnlyBannerCanBan`, `testBanEmitsEvent`, `testBanStatusIsBanned`, `testDuplicateBanIsIdempotent` |
| `requestBan()` | `testRequestBanUnapprovedReverts`, `testRequestBanApprovedEmitsEvent` |
| `remove()` | `testRemoverCannotApprove`, `testRemoverCannotBan`, `testOnlyRemoverCanRemove`, `testRemoveEmitsEvent`, `testRemoveFromAddedClearsState`, `testRemoveFromApprovedClearsState`, `testRemoveFromBannedClearsState` |
| `requestRemove()` | `testRequestRemoveFromNIL`, `testRequestRemoveFromADDED`, `testRequestRemoveFromAPPROVED`, `testRequestRemoveFromBANNED` |
| `onlyApproved` modifier | `testRequestBanUnapprovedReverts` (NotApproved), `testRequestApproveEmitsEvent` (implicitly via approved path) |
| Callbacks | `Verify.callback.t.sol` -- extensive coverage of all callback hooks |

### Coverage gaps

**Finding A03-1**: See below (bare `vm.expectRevert()` across multiple test files).

**Finding A03-2**: See below (missing `requestApprove` revert test for non-approved caller).

---

## A04 -- `src/err/ErrVerify.sol`

### Evidence of reading

- **Errors**:
  - `ZeroAdmin()`, line 6
  - `NotApproved()`, line 9
  - `AlreadyExists()`, line 12
  - `UnknownAccount()`, line 16

### Test mapping

| Error | Tests that trigger it with specific selector |
|---|---|
| `ZeroAdmin` | `Verify.construction.t.sol::testConstructionZeroAdminReverts`, `Verify.admin.t.sol::testZeroAdminReverts` |
| `NotApproved` | `Verify.requestBan.t.sol::testRequestBanUnapprovedReverts` |
| `AlreadyExists` | `Verify.add.t.sol::testAddFromAPPROVED`, `testAddFromBANNED`, `Verify.approve.t.sol::testAddRevertsAfterApproval` |
| `UnknownAccount` | `Verify.requestRemove.t.sol::testRequestRemoveFromNIL` |

### Coverage gaps

All four errors are tested with specific selectors. No gap.

---

## A05 -- `src/lib/LibEvidence.sol`

### Evidence of reading

- **Library**: `LibEvidence`, line 7
- **Functions**:
  - `_updateEvidenceRef(uint256[], Evidence, uint256)`, line 13
  - `asEvidences(uint256[])`, line 24

### Test mapping

Test file: `test/LibEvidence.t.sol`

| Source function | Tests |
|---|---|
| `_updateEvidenceRef` | `testSingleEvidenceRefUpdateAndRetrieve`, `testMultipleEvidenceRefsSequential`, `testRoundTripFuzz` |
| `asEvidences` | `testSingleEvidenceRefUpdateAndRetrieve`, `testMultipleEvidenceRefsSequential`, `testRoundTripFuzz` |

### Coverage gaps

No finding -- functions are well-tested with fuzz including bounded indices.

---

## A06 -- `src/lib/LibVerifyStatus.sol`

### Evidence of reading

- **Library**: `LibVerifyStatus`, line 7
- **Functions**:
  - `eq(VerifyStatus, VerifyStatus)`, line 11

### Test mapping

`LibVerifyStatus.eq` has no dedicated test file. It is used pervasively via `using LibVerifyStatus for VerifyStatus` in nearly every test file as the assertion mechanism (e.g., `status.eq(VERIFY_STATUS_APPROVED)`).

### Coverage gaps

No finding -- `eq` is a trivial wrapper over `==` on the underlying `uint256`, and it is exercised hundreds of times across the test suite in both true and false branches.

---

## A07 -- `script/Deploy.sol`

### Evidence of reading

- **Contract**: `Deploy`, line 14, inherits `Script`
- **Constant**: `DEPLOYMENT_SUITE_IMPLEMENTATIONS`, line 9
- **Functions**:
  - `deployImplementations(uint256)` internal, line 15
  - `run()` external, line 23

### Test mapping

No test file exists for `Deploy.sol`. Deploy scripts are typically not unit-tested in Foundry projects -- they are validated by CI dry-runs.

### Coverage gaps

No finding -- deployment scripts are out of scope for unit test coverage (validated by CI integration).

---

## Cross-cutting findings

### A03-1: Bare `vm.expectRevert()` used in 15 test assertions across 5 files (LOW)

**Files affected (15 instances)**:
- `test/Verify.remove.t.sol`: lines 61, 85, 106
- `test/Verify.admin.t.sol`: lines 98, 104, 110
- `test/Verify.adminDuplicateActions.t.sol`: lines 231, 251, 271
- `test/Verify.approve.t.sol`: lines 60, 83, 129
- `test/Verify.ban.t.sol`: lines 82, 105, 127

All 15 bare `vm.expectRevert()` calls guard OpenZeppelin AccessControl role checks. A bare `vm.expectRevert()` matches **any** revert, so the test could pass for the wrong reason (e.g., an unrelated revert earlier in the call). Per GENERAL_RULES.md, tests must use specific revert expectations.

However, OZ AccessControl v4 reverts with `AccessControl: account <hex> is missing role <hex>` where both hex strings depend on the fuzzed address, making exact matching impractical. Each test file documents this with a comment like `"OZ AccessControl revert with unpredictable string content due to fuzzed addresses"`.

**Mitigation**: While the bare `expectRevert()` is technically non-compliant with the coding standard, the OZ string revert makes exact matching impractical with fuzzed addresses. A partial match on the prefix `"AccessControl: account "` or using `vm.expectRevert(bytes(""))` is not correct either since the revert does carry data. The pragmatic fix is to use `vm.expectPartialRevert` (available in newer Foundry) or to hardcode a specific non-fuzzed address for the role check tests so the revert string is deterministic.

### A03-2: Missing `requestApprove` revert test for non-approved callers (LOW)

`requestApprove` (line 482 of `Verify.sol`) uses the `onlyApproved` modifier which reverts with `NotApproved()`. There is no test that verifies a non-approved caller is rejected from `requestApprove` with the specific `NotApproved` selector.

`requestBan` has this test (`testRequestBanUnapprovedReverts`), but `requestApprove` does not -- the test file `Verify.requestApprove.t.sol` only tests happy paths (approved callers emitting events and preserving state).

**Gap**: An unapproved (NIL, ADDED, or BANNED) account calling `requestApprove` should revert with `NotApproved`. No test verifies this.
