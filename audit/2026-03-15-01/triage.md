# Audit Triage — 2026-03-15-01

## MEDIUM

| ID | Title | Status |
|---|---|---|
| A03-1 | `&&` vs `||` bug in `add()` guard allows banned accounts to re-add (dupes: A03-2, A03-10, A03-P4-01, A04-HIGH-01) | FIXED |
| A02-4-P5 | `afterAdd` callback reentrancy loop via `Verify.approve` → `afterApprove` | DOCUMENTED — testAfterAddReentrancySafe verifies safe reentrancy with exactly 1 Approve event |

## HIGH (Test Coverage)

| ID | Title | Status |
|---|---|---|
| A03-9 | No tests for Verify.sol | FIXED — 75 tests across 12 Verify.*.t.sol files |
| A02-5 | No tests for AutoApprove.sol | FIXED — 10 tests in AutoApprove.t.sol |
| A01-3 | No tests for VerifyCallback.sol | FIXED — tested indirectly via Verify.callback.t.sol (13 tests) and AutoApprove.t.sol |
| A05-4 | No tests for LibEvidence.sol | FIXED — 3 tests in LibEvidence.t.sol |
| A06-1 | No tests for LibVerifyStatus.sol | FIXED — eq() exercised by all test suites via `using LibVerifyStatus` |

## Legacy Test Ports (from rain-protocol/test/Verify)

| ID | Legacy File | Status |
|---|---|---|
| LP-01 | `construction.ts` | FIXED — `Verify.construction.t.sol` |
| LP-02 | `admin.ts` | FIXED — `Verify.admin.t.sol` |
| LP-03 | `adminDuplicateActions.ts` | FIXED — `Verify.adminDuplicateActions.t.sol` |
| LP-04 | `approve.ts` | FIXED — `Verify.approve.t.sol` |
| LP-05 | `ban.ts` | FIXED — `Verify.ban.t.sol` |
| LP-06 | `callback.ts` | FIXED — `Verify.callback.t.sol` |
| LP-07 | `remove.ts` | FIXED — `Verify.remove.t.sol` |
| LP-08 | `requestApprove.ts` | FIXED — `Verify.requestApprove.t.sol` |
| LP-09 | `requestBan.ts` | FIXED — `Verify.requestBan.t.sol` |
| LP-10 | `requestRemove.ts` | FIXED — `Verify.requestRemove.t.sol` (updated for new non-NIL access) |
| LP-11 | `state.ts` | FIXED — `Verify.state.t.sol` |
| LP-12 | `status.ts` | FIXED — `Verify.status.t.sol` |
| LP-13 | `iVerifyV1Op.ts` | UPSTREAM — tests interpreter opcode in rain-protocol, not rain.verify |
| LP-14 | `Auto/AutoApprove/construction.ts` | FIXED — `AutoApprove.t.sol` |
| LP-15 | `Auto/AutoApprove/afterAdd.ts` | FIXED — `AutoApprove.t.sol` |
| LP-16 | `Auto/AutoApprove/erc721AutoApprove.ts` | DISMISSED — ERC721 ownership check is interpreter logic, not AutoApprove logic |
| LP-17 | `Auto/AutoApprove/stateSandboxEvidenceDataApproved.ts` | DISMISSED — state sandbox is interpreter logic, not AutoApprove logic |
| LP-18 | `LibEvidence/libEvidence.ts` | FIXED — `LibEvidence.t.sol` |

## LOW

| ID | Title | Status |
|---|---|---|
| A01-1 | Missing prelude dependency note for single-test commands in CLAUDE.md | FIXED |
| A02-1 | Unused output-count constants; no stack depth check (dupes: A02-P4-05) | FIXED — removed unused constants, added stack.length > 0 guard |
| A02-3-P5 | Non-32-byte evidence silently skipped in AutoApprove.afterAdd | FIXED — now reverts with BadEvidenceLength |
| A02-P4-01 | Unused import: LibEvaluable in AutoApprove.sol | FIXED |
| A02-P4-02 | Unused import: LibContext in AutoApprove.sol | FIXED |
| A02-P4-03 | Unused import/type: Pointer in AutoApprove.sol | FIXED |
| A02-P4-04 | Unused constant: CALLER_META_HASH in AutoApprove.sol | FIXED — removed with A02-1 |
| A03-11 | `add` NatSpec does not document guard conditions | FIXED |
| A03-12 | Typo in `remove` @param: "suppor" → "support" | FIXED |
| A03-13 | `state` function missing @return NatSpec | FIXED |
| A03-14 | `Initialize` event missing @param NatSpec | FIXED |
| A03-P5-01 | `statusAtTime` incorrect when timestamp > type(uint32).max | DISMISSED — timestamps are uint32 in practice; status tests bound to uint32 range |
| A05-1 | No bounds check on refsIndex in LibEvidence._updateEvidenceRef | DOCUMENTED — NatSpec documents caller must ensure refsIndex < refs.length; all callers are safe |
| A05-DOC-01 | Missing NatSpec on LibEvidence._updateEvidenceRef | FIXED |
| A05-DOC-02 | Missing NatSpec on LibEvidence.asEvidences | FIXED |
| A06-DOC-01 | Missing NatSpec on LibVerifyStatus.eq | FIXED |
| A06-DOC-02 | Unused import IVerifyV1 in LibVerifyStatus.sol (dupe: A06-P4-01) | FIXED |
| A07-DOC-01 | Stale "mumbai" testnet reference in Deploy.sol NatSpec | FIXED |
| A07-DOC-02 | Missing NatSpec on Deploy functions | DISMISSED — deployment script, minimal surface |
| A07-DOC-03 | README.md is effectively empty | DISMISSED — CLAUDE.md serves as project documentation |
| A07-P4-01 | Bare `src/` import path in Deploy.sol | FIXED |
| A04-1 | No tests for ErrVerify.sol | FIXED — all 4 errors tested: ZeroAdmin (construction), NotApproved (requestBan), AlreadyExists (add), UnknownAccount (requestRemove) |
| A07-1 | No tests for Deploy.sol | DISMISSED — deployment script |
