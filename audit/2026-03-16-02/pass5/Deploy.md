# Pass 5 - Correctness / Intent Verification: Deploy.sol (A07)

## Evidence of Thorough Reading

**File:** `/Users/thedavidmeister/Code/rain.verify/script/Deploy.sol`

**Contract:** `Deploy is Script` (lines 14-33)

### Functions
| Name | Line | Visibility | Modifiers |
|------|------|------------|-----------|
| `deployImplementations` | 15 | internal | - |
| `run` | 23 | external | - |

### Constants
| Name | Line | Value |
|------|------|-------|
| `DEPLOYMENT_SUITE_IMPLEMENTATIONS` | 9 | `keccak256("implementations")` |

### Imports
- `Script` from `forge-std/Script.sol`
- `Verify` from `../src/concrete/Verify.sol`

## Verification

### Does Deploy correctly deploy what it claims?

**`run()` (lines 23-32):**
1. Reads `DEPLOYMENT_KEY` env var as a uint256 private key.
2. Reads `DEPLOYMENT_SUITE` env var as a string, hashes it with `keccak256`.
3. Compares against `DEPLOYMENT_SUITE_IMPLEMENTATIONS`.
4. If match, calls `deployImplementations`. Otherwise reverts with "Unknown deployment suite".

**`deployImplementations()` (lines 15-21):**
1. Starts broadcasting with the deployment key.
2. Deploys `new Verify()` - a bare implementation contract (no proxy, no initialization).
3. Stops broadcasting.

**Verdict:** The deployment is correct for its stated purpose. The NatSpec says "This is intended to be run on every commit by CI to a testnet, then cross chain deployed to whatever mainnet is required, by users." Deploying a bare `Verify` implementation is consistent with a clone/proxy pattern where:
- The `Verify` constructor calls `_disableInitializers()` (confirmed in Verify.sol line 262), preventing direct initialization of the implementation.
- Users then clone/proxy this implementation and initialize the clone.

### Named items do what they claim

- `DEPLOYMENT_SUITE_IMPLEMENTATIONS`: Identifies the "implementations" deployment suite. Name matches the hash input string.
- `deployImplementations`: Deploys implementation contracts. Name is accurate.
- `run`: Standard Forge script entry point. Correct.

### Constants are correct

- `DEPLOYMENT_SUITE_IMPLEMENTATIONS = keccak256("implementations")`: This is a compile-time constant used for string matching. The value is deterministic and correct.

### Pragma version

The file uses `pragma solidity =0.8.25;` (exact version pin) while the source contracts use `^0.8.25`. This is appropriate for a deploy script that should be compiled with a known version.

## Findings

No findings. The deployment script correctly deploys a bare Verify implementation contract as intended for a clone-factory pattern.
