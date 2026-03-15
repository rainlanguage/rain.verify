# Pass 5 - Correctness / Intent Verification: Deploy.sol

**Agent:** A07
**File:** `/Users/thedavidmeister/Code/rain.verify/script/Deploy.sol`

## Evidence of Thorough Reading

- File is 33 lines. Pragma `=0.8.25` (exact version, stricter than `^`).
- Imports `Script` from `forge-std/Script.sol`.
- Imports `Verify` from `src/concrete/Verify.sol`.
- Defines file-level constant: `DEPLOYMENT_SUITE_IMPLEMENTATIONS = keccak256("implementations")`.
- Contract `Deploy is Script` with two functions:
  1. `deployImplementations(uint256 deploymentKey)` - internal, broadcasts and deploys `new Verify()`.
  2. `run()` - external entry point, reads env vars and dispatches to deployment suite.
- NatSpec: "This is intended to be run on every commit by CI to a testnet such as mumbai, then cross chain deployed to whatever mainnet is required, by users."

## Verification Checklist

### Does Deploy.sol correctly deploy what it claims to deploy?

**Yes.** The `deployImplementations` function:
1. Calls `vm.startBroadcast(deploymentKey)` to begin broadcasting transactions signed by the deployment key.
2. Executes `new Verify()` which deploys the `Verify` implementation contract.
3. Calls `vm.stopBroadcast()`.

The `Verify` constructor calls `_disableInitializers()`, so the deployed contract is correctly set up as an uninitialized implementation suitable for cloning/proxying. This matches the "implementations" suite name.

### Is the `run()` function correct?

**Yes.** It:
1. Reads `DEPLOYMENT_KEY` from environment as a uint256 (private key).
2. Reads `DEPLOYMENT_SUITE` from environment as a string, hashes it with keccak256.
3. Compares against `DEPLOYMENT_SUITE_IMPLEMENTATIONS`.
4. Dispatches to `deployImplementations` if matched, otherwise reverts with "Unknown deployment suite".

The dispatch logic is correct. The revert on unknown suite prevents silent no-ops.

### Are constants correct?

`DEPLOYMENT_SUITE_IMPLEMENTATIONS = keccak256("implementations")` - This is a file-level constant used for string comparison. It correctly hashes the string "implementations" to match against the environment variable.

### Is the deployed `Verify` address captured?

The result of `new Verify()` is not stored or logged. For a deployment script, this means the deployed address is only available through Forge's broadcast transaction logs. This is standard practice for Forge scripts -- the address is captured in the broadcast JSON output.

### NatSpec mentions "mumbai"

The NatSpec references "mumbai" which was a Polygon testnet that was deprecated in April 2024 (replaced by Amoy). This is a stale comment but has no functional impact.

## Findings

### A07-INFO-01: Stale testnet reference in NatSpec

**Severity:** INFO

The NatSpec comment on line 12 references "mumbai" as an example testnet. The Mumbai testnet was deprecated in April 2024 and replaced by Amoy. This has no functional impact on the script behavior.
