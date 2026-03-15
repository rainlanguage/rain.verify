# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

rain.verify is a Solidity smart contract library for trust-minimized on-chain identity verification. It implements role-based (APPROVER, BANNER, REMOVER) verification with status lifecycle: NIL -> ADDED -> APPROVED/BANNED, with batch operations and callback hooks.

## Build & Test

All commands require the Nix dev shell. Enter it with `nix develop` first, or prefix commands with `nix develop -c`.

```
nix develop -c rainix-sol-prelude    # Setup step (run before other tasks)
nix develop -c rainix-sol-test       # Run Forge tests
nix develop -c rainix-sol-static     # Slither static analysis
nix develop -c rainix-sol-legal      # License compliance check
```

Single test: `nix develop -c forge test --match-test testFunctionName`
Single contract: `nix develop -c forge test --match-contract ContractName`

## Architecture

- **Verify.sol** (`src/concrete/`) - Core contract. Uses OpenZeppelin AccessControl for role management. Stores per-account `VerifyStatus` with timestamps for each status transition. Supports batch approve/ban/remove with evidence.
- **AutoApprove.sol** (`src/concrete/`) - Callback that integrates with Rain Interpreter V4 to evaluate custom approval logic via bytecode.
- **VerifyCallback.sol** (`src/abstract/`) - Abstract base for verification callbacks (afterAdd/afterApprove/afterBan/afterRemove). OwnableUpgradeable.
- **LibEvidence.sol**, **LibVerifyStatus.sol** (`src/lib/`) - Assembly-optimized helper libraries.
- Interfaces live in the `rain.verify.interface` submodule under `lib/`.

## Dependencies

Managed as git submodules in `lib/`. Key deps: `rain.verify.interface`, `rain.interpreter.interface`, `rain.factory` (ICloneableV2 proxy pattern), `openzeppelin-contracts-upgradeable`.

## Compiler Settings

Solidity 0.8.25, Paris EVM (pre-PUSH0 for cross-chain compatibility), 100k optimizer runs, no CBOR metadata.

## License

LicenseRef-DCL-1.0 (Decentralized Community License). All source files require SPDX headers.
