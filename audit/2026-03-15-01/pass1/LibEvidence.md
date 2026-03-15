# Audit Pass 1 (Security) -- LibEvidence.sol

**Agent:** A05
**File:** `src/lib/LibEvidence.sol`
**Date:** 2026-03-15

## Evidence of Reading

### Library Name
`LibEvidence`

### Functions
| Function | Line |
|---|---|
| `_updateEvidenceRef(uint256[] memory refs, Evidence memory evidence, uint256 refsIndex)` | 8 |
| `asEvidences(uint256[] memory refs)` | 14 |

### Types, Errors, and Constants
None defined in this file.

### Imports
- `Evidence` struct from `rain.verify.interface/interface/IVerifyV1.sol` (line 5)
  - `Evidence { address account; bytes data; }`

## Findings

### A05-1 -- No bounds check on `refsIndex` in `_updateEvidenceRef` (LOW)

**Location:** `src/lib/LibEvidence.sol`, line 8-12

**Description:**
`_updateEvidenceRef` uses inline assembly to write `evidence` (a memory pointer) into `refs` at position `refsIndex` without verifying that `refsIndex < refs.length`. The computed write address is `refs + 0x20 + 0x20 * refsIndex`. If `refsIndex >= refs.length`, this performs an out-of-bounds memory write past the end of the `refs` array.

All current call sites are safe because:
- `refs` is always allocated as `new uint256[](evidences.length)`.
- `refsIndex` is an incrementing counter that only increases when a branch is taken, and the loop iterates over `evidences`, so `refsIndex` is always strictly less than `evidences.length`.

However, as a library function, `_updateEvidenceRef` cannot guarantee its callers will always satisfy this invariant. A future caller could pass a `refsIndex` that exceeds the array bounds, silently corrupting adjacent memory.

**Impact:** If a future caller passes an out-of-bounds `refsIndex`, arbitrary memory corruption occurs. In practice, current callers are safe.

**Recommendation:** Add a bounds check before the assembly block, or document the precondition with a comment making the invariant explicit. A revert on `refsIndex >= refs.length` would provide defense-in-depth.

### A05-2 -- `"memory-safe"` annotation on `_updateEvidenceRef` assembly block (INFO)

**Location:** `src/lib/LibEvidence.sol`, line 9

**Description:**
The assembly block is annotated `"memory-safe"`, which tells the Solidity compiler that the assembly respects Solidity's memory model. This annotation is relied upon by the optimizer for stack-to-memory optimizations. The block writes into an already-allocated array within its bounds (assuming correct `refsIndex`), so the annotation is technically correct given the precondition that `refsIndex` is in-bounds. If the bounds check from A05-1 were violated, the `"memory-safe"` annotation would become a lie and could cause the optimizer to produce incorrect code.

**Impact:** Informational. Correct under current usage assumptions.

### A05-3 -- Type-punning `uint256[]` to `Evidence[]` in `asEvidences` (INFO)

**Location:** `src/lib/LibEvidence.sol`, lines 14-18

**Description:**
`asEvidences` reinterprets a `uint256[]` as `Evidence[]` by aliasing the pointer in assembly. This is a common Rain pattern for avoiding extra allocation. It works because both `uint256[]` and `Evidence[]` have the same memory layout: a length word followed by 32-byte slots. The `uint256` slots contain memory pointers to `Evidence` structs (placed there by `_updateEvidenceRef`), which is exactly what `Evidence[]` expects in its slots.

This is safe and correct, but relies on the assumption that the `uint256[]` exclusively contains valid `Evidence` memory pointers. The coupling between `_updateEvidenceRef` and `asEvidences` creates an implicit contract: the array must only be populated via `_updateEvidenceRef` before being cast via `asEvidences`.

**Impact:** Informational. No issue under current usage.
