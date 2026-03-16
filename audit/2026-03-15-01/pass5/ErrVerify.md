# Pass 5 - Correctness / Intent Verification: ErrVerify.sol

**Agent:** A04
**File:** `/Users/thedavidmeister/Code/rain.verify/src/err/ErrVerify.sol`

## Evidence of Thorough Reading

- File is 13 lines. Pragma `^0.8.25`.
- Defines three custom errors with no parameters:
  1. `ZeroAdmin()` - NatSpec: "Thrown when Verify is initialised with a zero address for admin."
  2. `NotApproved()` - NatSpec: "Thrown when msg.sender is not approved at the current timestamp."
  3. `AlreadyExists()` - NatSpec: "Thrown when an account already exists in the system and is being added."

## Verification Checklist

### Do error names match their trigger conditions?

Checked each error against its usage in `Verify.sol`:

1. **`ZeroAdmin()`** - Used at `Verify.sol:266-268`:
   ```
   if (config.admin == address(0)) { revert ZeroAdmin(); }
   ```
   Name matches condition exactly. Correct.

2. **`NotApproved()`** - Used in `onlyApproved` modifier at `Verify.sol:352-357`:
   ```
   if (!statusAtTime(sStates[msg.sender], block.timestamp).eq(VERIFY_STATUS_APPROVED)) {
       revert NotApproved();
   }
   ```
   Name matches condition exactly. Correct.

3. **`AlreadyExists()`** - Used in `add()` at `Verify.sol:370-372`:
   ```
   if (currentStatus.eq(VERIFY_STATUS_APPROVED) && !currentStatus.eq(VERIFY_STATUS_BANNED)) {
       revert AlreadyExists();
   }
   ```
   The NatSpec says "Thrown when an account already exists in the system and is being added." The error name and NatSpec are correct for the *intended* purpose, but the trigger condition in the consumer (`Verify.sol`) has a logic bug (see A04-HIGH-01 below). The error definition itself is correct.

## Findings

### A04-HIGH-01: `AlreadyExists` trigger condition in `Verify.sol:add()` is logically flawed

**Severity:** HIGH

The condition at `Verify.sol:370` that triggers `AlreadyExists` is:

```solidity
if (currentStatus.eq(VERIFY_STATUS_APPROVED) && !currentStatus.eq(VERIFY_STATUS_BANNED)) {
    revert AlreadyExists();
}
```

`currentStatus` is a single `VerifyStatus` value returned by `statusAtTime`. It can only equal one status at a time. Therefore `currentStatus.eq(VERIFY_STATUS_APPROVED) && !currentStatus.eq(VERIFY_STATUS_BANNED)` is logically equivalent to just `currentStatus.eq(VERIFY_STATUS_APPROVED)`, because when `currentStatus` equals `APPROVED` it can never simultaneously equal `BANNED`. The `&& !currentStatus.eq(VERIFY_STATUS_BANNED)` clause is dead code.

**Consequence:** A banned account can call `add()` without reverting. The function will:
- Not modify state (since `currentStatus` is BANNED, not NIL, so line 380 is false)
- Emit a `RequestApprove` event for a banned account
- Invoke the `afterAdd` callback with the banned account's evidence

This allows banned accounts to:
1. Spam `RequestApprove` events, polluting the event log for approvers
2. Trigger `afterAdd` callbacks, potentially causing unintended side effects in callback contracts

The likely intended condition is either:
- `if (currentStatus.eq(VERIFY_STATUS_APPROVED) || currentStatus.eq(VERIFY_STATUS_BANNED))` - revert if approved OR banned
- `if (!currentStatus.eq(VERIFY_STATUS_NIL) && !currentStatus.eq(VERIFY_STATUS_ADDED))` - only allow NIL or ADDED

Note: While this bug is in `Verify.sol`, it is the sole trigger site for `AlreadyExists` and the error's NatSpec states it is for accounts that "already exist", which should include banned accounts. The error definition is correct; its usage is not.
