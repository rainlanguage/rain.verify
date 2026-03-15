// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.25;

import {VerifyStatus} from "rain.verify.interface/interface/IVerifyV1.sol";

library LibVerifyStatus {
    /// @param a The first status.
    /// @param b The second status.
    /// @return True if both statuses have the same underlying value.
    function eq(VerifyStatus a, VerifyStatus b) internal pure returns (bool) {
        return VerifyStatus.unwrap(a) == VerifyStatus.unwrap(b);
    }
}
