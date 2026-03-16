# Pass 5 - Correctness / Intent Verification: LibEvidence.sol

**Agent:** A05
**File:** `/Users/thedavidmeister/Code/rain.verify/src/lib/LibEvidence.sol`

## Evidence of Thorough Reading

- File is 19 lines. Pragma `^0.8.25`.
- Imports `Evidence` from `rain.verify.interface/interface/IVerifyV1.sol`.
- Defines library `LibEvidence` with two internal pure functions:
  1. `_updateEvidenceRef(uint256[] memory refs, Evidence memory evidence, uint256 refsIndex)` - assembly function
  2. `asEvidences(uint256[] memory refs)` - type-punning cast

## Verification Checklist

### Assembly correctness of `_updateEvidenceRef`

```solidity
function _updateEvidenceRef(uint256[] memory refs, Evidence memory evidence, uint256 refsIndex) internal pure {
    assembly ("memory-safe") {
        mstore(add(refs, add(0x20, mul(0x20, refsIndex))), evidence)
    }
}
```

Memory layout of `uint256[] memory`:
- `refs` points to the length slot.
- `refs + 0x20` is element 0.
- `refs + 0x20 + (0x20 * i)` is element `i`.

The expression `add(refs, add(0x20, mul(0x20, refsIndex)))` computes `refs + 0x20 + 0x20 * refsIndex`, which is the memory address of `refs[refsIndex]`. The `mstore` writes the `evidence` pointer (a memory pointer to the Evidence struct) into that slot.

**Correctness:** This correctly stores a pointer to an `Evidence` struct into the `uint256[]` array at position `refsIndex`. Since `Evidence memory` is represented as a memory pointer (a uint256), and `uint256[]` elements are also uint256-sized, the pointer is stored correctly. This is the mechanism that allows the array to later be type-punned to `Evidence[]` via `asEvidences`.

**Bounds checking:** There is no bounds check against `refs.length`. The caller is responsible for ensuring `refsIndex < refs.length`. In `Verify.sol`, the array is allocated with `evidences.length` and the index is incremented from 0 with a counter, and `truncate` is called before use, so this is safe in context.

**Memory-safe annotation:** The assembly block is annotated `"memory-safe"`. The operation writes within the already-allocated array bounds (assuming correct caller behavior), so this annotation is valid.

### Assembly correctness of `asEvidences`

```solidity
function asEvidences(uint256[] memory refs) internal pure returns (Evidence[] memory evidences) {
    assembly ("memory-safe") {
        evidences := refs
    }
}
```

This performs a zero-cost type pun: it reinterprets the `uint256[]` pointer as an `Evidence[]` pointer. This works because:
- Both `uint256[]` and `Evidence[]` (where Evidence is a struct in memory) have the same memory layout: a length word followed by N pointer-sized elements.
- Each element of `uint256[]` stores a memory pointer to an `Evidence` struct, which is exactly what `Evidence[]` elements are.

**Correctness:** Valid. The `uint256[]` was populated with `Evidence` memory pointers by `_updateEvidenceRef`, so reinterpreting it as `Evidence[]` yields a correct array of Evidence structs.

**Memory-safe annotation:** This is a pointer assignment only, no memory reads or writes. Valid.

## Findings

No findings.
