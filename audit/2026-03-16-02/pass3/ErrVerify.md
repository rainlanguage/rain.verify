# Pass 3 - Documentation Audit: ErrVerify.sol

**Agent:** A04
**File:** `src/err/ErrVerify.sol`

## Evidence of Reading

**Contract/Library:** None (file-level error declarations)

### Types/Errors/Constants
| Name | Kind | Line |
|---|---|---|
| `ZeroAdmin` | error | 6 |
| `NotApproved` | error | 9 |
| `AlreadyExists` | error | 12 |
| `UnknownAccount` | error | 15-16 |

### Functions
None.

## Documentation Check

### Error: `ZeroAdmin` (line 6)
- Has `@dev` (line 5): "Thrown when Verify is initialised with a zero address for admin." Accurate: matches usage in `Verify.initialize` at line 268-269.

### Error: `NotApproved` (line 9)
- Has `@dev` (line 8): "Thrown when msg.sender is not approved at the current timestamp." Accurate: matches usage in `Verify.onlyApproved` modifier at line 356-358.

### Error: `AlreadyExists` (line 12)
- Has `@dev` (line 11): "Thrown when an account already exists in the system and is being added." Accurate: matches usage in `Verify.add` at line 378-379.

### Error: `UnknownAccount` (line 16)
- Has `@dev` (lines 14-15): "Thrown when a NIL account attempts an action that requires the account to have been previously added to the system." Accurate: matches usage in `Verify.requestRemove` at line 594-596.

## Findings

No findings. All errors are documented accurately with `@dev` tags that match their usage in the codebase.
