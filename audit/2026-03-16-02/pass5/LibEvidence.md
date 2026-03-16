# Pass 5 - Correctness / Intent Verification: LibEvidence.sol (A05)

## Evidence of Thorough Reading

**File:** `/Users/thedavidmeister/Code/rain.verify/src/lib/LibEvidence.sol`

**Library:** `LibEvidence` (lines 7-29)

### Functions
| Name | Line | Visibility | Modifiers |
|------|------|------------|-----------|
| `_updateEvidenceRef` | 13 | internal | pure |
| `asEvidences` | 24 | internal | pure |

### Types / Errors / Constants
- None defined locally.

### Imports
- `Evidence` from `rain.verify.interface/interface/IVerifyV1.sol`

## Verification

### Assembly in `_updateEvidenceRef` (lines 14-16)

```solidity
assembly ("memory-safe") {
    mstore(add(refs, add(0x20, mul(0x20, refsIndex))), evidence)
}
```

**Analysis:**
- `refs` is a `uint256[] memory` pointer. In Solidity memory layout, the first 32 bytes at `refs` hold the array length, and elements start at `refs + 0x20`.
- Element at index `refsIndex` is at offset `refs + 0x20 + (0x20 * refsIndex)`.
- The expression `add(refs, add(0x20, mul(0x20, refsIndex)))` correctly computes this address.
- `evidence` is a `Evidence memory` pointer (a memory address as a uint256).
- `mstore` writes this pointer into the `refs` array slot, effectively storing a reference to the `Evidence` struct.
- The caller is responsible for ensuring `refsIndex < refs.length` (documented in NatSpec).

**Verdict:** The assembly is correct. It stores a memory pointer to an `Evidence` struct at the specified index of a `uint256[]` array.

### Assembly in `asEvidences` (lines 25-27)

```solidity
assembly ("memory-safe") {
    evidences := refs
}
```

**Analysis:**
- This reinterprets the `uint256[]` memory pointer as an `Evidence[]` memory pointer.
- This is valid because `_updateEvidenceRef` populated each slot of `refs` with a pointer to an `Evidence` struct, which is exactly the layout of a `Evidence[]` in memory (length word followed by N pointers to struct data).
- The `memory-safe` annotation is correct: no memory is allocated or freed, only a pointer alias is created.

**Verdict:** The assembly is correct. The pointer aliasing is safe given the invariant that `refs` was populated exclusively by `_updateEvidenceRef`.

### Named items do what they claim

- `_updateEvidenceRef`: Updates a reference (pointer) to evidence in an array. Name is accurate.
- `asEvidences`: Reinterprets an array as Evidence[]. Name is accurate.

### Usage in Verify.sol

The library is used in `approve`, `ban`, and `remove` functions. In each case:
1. A `uint256[]` array is allocated with `evidences.length` size.
2. `_updateEvidenceRef` is called with incrementing indices that are always less than `evidences.length` (ensured by the loop and counter logic).
3. `truncate` is called to resize to the actual count before `asEvidences` converts to `Evidence[]`.

The usage is consistent and correct.

## Findings

No findings. The assembly is correct and the library functions accurately implement their documented behavior.
