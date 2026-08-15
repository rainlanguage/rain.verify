# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project

rain.verify is a Solidity smart contract library for trust-minimized on-chain
identity verification. It implements role-based (APPROVER, BANNER, REMOVER)
verification with status lifecycle: NIL -> ADDED -> APPROVED/BANNED, with batch
operations and callback hooks.

## Build & Test

All commands assume you are in the Nix dev shell (`nix develop`).

```
rainix-sol-prelude    # Setup step (run before other tasks)
rainix-sol-test       # Run Forge tests
rainix-sol-static     # Slither static analysis
rainix-sol-legal      # License compliance check
```

Run `rainix-sol-prelude` before first test run, then:

Single test: `forge test --match-test testFunctionName` Single contract:
`forge test --match-contract ContractName`

## Architecture

- **Verify.sol** (`src/concrete/`) - Core contract. Uses OpenZeppelin
  AccessControl for role management. Stores per-account `VerifyStatus` with
  timestamps for each status transition. Supports batch approve/ban/remove with
  evidence.
- **AutoApprove.sol** (`src/concrete/`) - Callback that integrates with Rain
  Interpreter V4 to evaluate custom approval logic via bytecode.
- **VerifyCallback.sol** (`src/abstract/`) - Abstract base for verification
  callbacks (afterAdd/afterApprove/afterBan/afterRemove). OwnableUpgradeable.
- **LibEvidence.sol**, **LibVerifyStatus.sol** (`src/lib/`) - Assembly-optimized
  helper libraries.
- `IVerifyV1`, `IVerifyCallbackV1`, `Evidence` and `VerifyStatus` come from the
  `rain-verify-interface` dependency, imported as
  `rain-verify-interface-0.1.0/src/interface/...`.

## Dependencies

Managed by soldeer. Declared in `foundry.toml` under `[dependencies]`, pinned by
`soldeer.lock`, and installed into the gitignored `dependencies/` directory
(`libs = ["dependencies"]`) by `forge soldeer install`. Imports carry the
version in the path prefix, per `remappings.txt` — e.g.
`rain-factory-0.1.1/src/...`.

Key deps: `rain-verify-interface` 0.1.0, `rain-interpreter-interface` 0.1.0,
`rain-factory` 0.1.1 (ICloneableV2 proxy pattern),
`@openzeppelin-contracts-upgradeable` 5.6.1.

## Compiler Settings

Solidity 0.8.25, Paris EVM (pre-PUSH0 for cross-chain compatibility), 100k
optimizer runs, no CBOR metadata.

## License

LicenseRef-DCL-1.0 (Decentralized Community License). All source files require
SPDX headers.
