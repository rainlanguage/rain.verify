# A05 - LibEvidence.sol - Pass 1 (Security)

## File
`/Users/thedavidmeister/Code/rain.verify/src/lib/LibEvidence.sol`

## Evidence of Thorough Reading

### Module
`library LibEvidence`

### Functions
| Name | Line | Visibility |
|------|------|------------|
| `_updateEvidenceRef` | 13 | internal pure |
| `asEvidences` | 24 | internal pure |

### Types / Errors / Constants
None.

### Imports
| Name | Source | Line |
|------|--------|------|
| `Evidence` | `rain.verify.interface/interface/IVerifyV1.sol` | 5 |

## Findings

### A05-1: No bounds check in `_updateEvidenceRef` - caller must enforce (INFO)

**Location:** Line 13-17

**Description:** `_updateEvidenceRef` performs a raw `mstore` at an offset computed from `refsIndex` without any bounds check. The NatSpec comment on line 9 correctly documents that "Callers MUST ensure `refsIndex < refs.length`", and all call sites in `Verify.sol` (`approve`, `ban`, `remove`) use a separate counter variable (`additions`, `approvals`, `bans`, `removals`) that is always incremented after writing and the backing array is allocated with `evidences.length` as capacity. The counter can never exceed the array length because the loop iterates exactly `evidences.length` times and each branch increments the counter at most once.

**Impact:** No actual vulnerability. The invariant is maintained by all current callers. The lack of an on-chain bounds check is an intentional gas optimization for a `pure` library function.

**Classification:** INFO
