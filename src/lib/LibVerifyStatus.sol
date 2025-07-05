// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.25;

import {IVerifyV1, VerifyStatus} from "../interface/IVerifyV1.sol";

library LibVerifyStatus {
    function eq(VerifyStatus a, VerifyStatus b) internal pure returns (bool) {
        return VerifyStatus.unwrap(a) == VerifyStatus.unwrap(b);
    }
}
