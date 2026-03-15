# Audit Triage — 2026-03-15-01

## MEDIUM

| ID | Title | Status |
|---|---|---|
| A03-1 | `&&` vs `||` bug in `add()` guard allows banned accounts to re-add (dupes: A03-2, A03-10, A03-P4-01, A04-HIGH-01) | FIXED |
| A02-4-P5 | `afterAdd` callback reentrancy loop via `Verify.approve` → `afterApprove` | PENDING |

## HIGH (Test Coverage)

| ID | Title | Status |
|---|---|---|
| A03-9 | No tests for Verify.sol | PENDING |
| A02-5 | No tests for AutoApprove.sol | PENDING |
| A01-3 | No tests for VerifyCallback.sol | PENDING |
| A05-4 | No tests for LibEvidence.sol | PENDING |
| A06-1 | No tests for LibVerifyStatus.sol | PENDING |

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
| A01-1 | Missing prelude dependency note for single-test commands in CLAUDE.md | PENDING |
| A02-1 | Unused output-count constants; no stack depth check (dupes: A02-P4-05) | PENDING |
| A02-3-P5 | Non-32-byte evidence silently skipped in AutoApprove.afterAdd | PENDING |
| A02-P4-01 | Unused import: LibEvaluable in AutoApprove.sol | PENDING |
| A02-P4-02 | Unused import: LibContext in AutoApprove.sol | PENDING |
| A02-P4-03 | Unused import/type: Pointer in AutoApprove.sol | PENDING |
| A02-P4-04 | Unused constant: CALLER_META_HASH in AutoApprove.sol | PENDING |
| A03-11 | `add` NatSpec does not document guard conditions | PENDING |
| A03-12 | Typo in `remove` @param: "suppor" → "support" | PENDING |
| A03-13 | `state` function missing @return NatSpec | PENDING |
| A03-14 | `Initialize` event missing @param NatSpec | PENDING |
| A03-P5-01 | `statusAtTime` incorrect when timestamp > type(uint32).max | PENDING |
| A05-1 | No bounds check on refsIndex in LibEvidence._updateEvidenceRef | PENDING |
| A05-DOC-01 | Missing NatSpec on LibEvidence._updateEvidenceRef | PENDING |
| A05-DOC-02 | Missing NatSpec on LibEvidence.asEvidences | PENDING |
| A06-DOC-01 | Missing NatSpec on LibVerifyStatus.eq | PENDING |
| A06-DOC-02 | Unused import IVerifyV1 in LibVerifyStatus.sol (dupe: A06-P4-01) | PENDING |
| A07-DOC-01 | Stale "mumbai" testnet reference in Deploy.sol NatSpec | PENDING |
| A07-DOC-02 | Missing NatSpec on Deploy functions | PENDING |
| A07-DOC-03 | README.md is effectively empty | PENDING |
| A07-P4-01 | Bare `src/` import path in Deploy.sol | PENDING |
| A04-1 | No tests for ErrVerify.sol | PENDING |
| A07-1 | No tests for Deploy.sol | PENDING |
