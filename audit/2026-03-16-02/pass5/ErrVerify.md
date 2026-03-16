# Pass 5 - Correctness / Intent Verification: ErrVerify.sol (A04)

## Evidence of Thorough Reading

**File:** `/Users/thedavidmeister/Code/rain.verify/src/err/ErrVerify.sol`

### Errors
| Name | Line | Description (NatSpec) |
|------|------|-----------------------|
| `ZeroAdmin()` | 6 | Thrown when Verify is initialised with a zero address for admin |
| `NotApproved()` | 9 | Thrown when msg.sender is not approved at the current timestamp |
| `AlreadyExists()` | 12 | Thrown when an account already exists in the system and is being added |
| `UnknownAccount()` | 16 | Thrown when a NIL account attempts an action that requires the account to have been previously added |

### Types / Constants
- None.

## Verification: Error names match trigger conditions

### ZeroAdmin (line 6)
- **Trigger in Verify.sol (line 268-270):** `if (config.admin == address(0)) { revert ZeroAdmin(); }`
- **Verdict:** Name matches. Thrown exactly when admin is zero address during initialization.

### NotApproved (line 9)
- **Trigger in Verify.sol (line 356):** `if (!statusAtTime(sStates[msg.sender], block.timestamp).eq(VERIFY_STATUS_APPROVED)) { revert NotApproved(); }`
- **Verdict:** Name matches. Thrown when `msg.sender` status is not APPROVED at current block timestamp. Used in `onlyApproved` modifier guarding `requestApprove`, `requestBan`.

### AlreadyExists (line 12)
- **Trigger in Verify.sol (line 378-380):** Thrown when `add()` is called by an account whose status is APPROVED or BANNED.
- **Verdict:** Name matches. The account already has a non-trivially-modifiable status in the system.

### UnknownAccount (line 16)
- **Trigger in Verify.sol (line 594-596):** Thrown in `requestRemove` when `msg.sender` status is NIL.
- **Verdict:** Name matches. A NIL account is unknown to the system and cannot request removal.

## Findings

No findings. All error names accurately describe their trigger conditions and are used correctly in Verify.sol.
