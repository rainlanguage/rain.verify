# Audit Triage — 2026-03-16-02

## LOW

| ID | Title | Status |
|---|---|---|
| A07-1 | Deploy.sol: `new Verify()` doesn't capture deployed address | DISMISSED — Forge broadcast artifacts capture all deployed addresses; carried forward from prior audit A07-1 DISMISSED |
| A03-1 | 15 bare `vm.expectRevert()` in tests for OZ AccessControl checks | PENDING |
| A03-2 | `requestApprove` missing revert test for non-approved callers | PENDING |
| A02-P3-01 | Missing NatSpec on AutoApprove.afterAdd override | PENDING |
| A03-P3-01 | State struct NatSpec misleading about addedSince default (says 0xFFFFFFFF but EVM default is 0) | PENDING |
| A02-P4-01 | Unused `using LibUint256Array for uint256` directive in AutoApprove | PENDING |
| A02-P4-02 | Unused import `IInterpreterStoreV3` in AutoApprove | PENDING |
