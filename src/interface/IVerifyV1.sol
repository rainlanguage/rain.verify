// SPDX-License-Identifier: CAL
pragma solidity ^0.8.25;

type VerifyStatus is uint256;

/// Structure of arbitrary evidence to support any action taken.
/// Privileged roles are expected to provide evidence just as applicants as an
/// audit trail will be preserved permanently in the logs.
/// @param account The account this evidence is relevant to.
/// @param data Arbitrary bytes representing evidence. MAY be e.g. a reference
/// to a sufficiently decentralised external system such as an IPFS hash.
struct Evidence {
    address account;
    bytes data;
}

interface IVerifyV1 {
    function accountStatusAtTime(address account, uint256 timestamp) external view returns (VerifyStatus);
}
