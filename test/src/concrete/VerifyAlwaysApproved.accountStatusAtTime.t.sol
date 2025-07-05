// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";

import {VerifyAlwaysApproved} from "src/concrete/VerifyAlwaysApproved.sol";
import {VerifyStatus, VERIFY_STATUS_APPROVED} from "src/interface/IVerifyV1.sol";

contract VerifyAlwaysApprovedAccountStatusAtTimeTest is Test {
    function testAccountStatusAtTime(address account, uint256 timestamp) external {
        VerifyAlwaysApproved verifyAlwaysApproved = new VerifyAlwaysApproved();

        VerifyStatus status = verifyAlwaysApproved.accountStatusAtTime(account, timestamp);
        assertEq(
            VerifyStatus.unwrap(status),
            VerifyStatus.unwrap(VERIFY_STATUS_APPROVED),
            "VerifyAlwaysApproved.accountStatusAtTime should always return VERIFY_STATUS_APPROVED"
        );
    }
}
