// SPDX-License-Identifier: CAL
pragma solidity =0.8.25;

import {AccessControlUpgradeable as AccessControl} from
    "openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol";
import {LibVerifyConstants} from "../lib/LibVerifyConstants.sol";
import {LibEvidence} from "../lib/LibEvidence.sol";
import {LibUint256Array} from "rain.solmem/lib/LibUint256Array.sol";
import {IVerifyV1, Evidence} from "../interface/IVerifyV1.sol";
import {IVerifyCallbackV1} from "../interface/IVerifyCallbackV1.sol";
import {LibVerifyStatus, VerifyStatus} from "../lib/LibVerifyStatus.sol";
import {ICloneableV2, ICLONEABLE_V2_SUCCESS} from "rain.factory/interface/ICloneableV2.sol";

/// Records the time a verify session reaches each status.
/// If a status is not reached it is left as UNINITIALIZED, i.e. 0xFFFFFFFF.
/// Most accounts will never be banned so most accounts will never reach every
/// status, which is a good thing.
/// @param addedSince Time the address was added else 0xFFFFFFFF.
/// @param approvedSince Time the address was approved else 0xFFFFFFFF.
/// @param bannedSince Time the address was banned else 0xFFFFFFFF.
struct State {
    uint32 addedSince;
    uint32 approvedSince;
    uint32 bannedSince;
}

/// Config to initialize a Verify contract with.
/// @param admin The address to ASSIGN ALL ADMIN ROLES to initially. This
/// address is free and encouraged to delegate fine grained permissions to
/// many other sub-admin addresses, then revoke it's own "root" access.
/// @param callback The address of the `IVerifyCallbackV1` contract if it exists.
/// MAY be `address(0)` to signify that callbacks should NOT run.
struct VerifyConfig {
    address admin;
    address callback;
}

/// @title Verify
/// Trust-minimised contract to record the state of some verification process.
/// When some off-chain identity is to be reified on chain there is inherently
/// some multi-party, multi-faceted trust relationship. For example, the DID
/// (Decentralized Identifiers) specification from W3C outlines that the
/// controller and the subject of an identity are two different entities.
///
/// This is because self-identification is always problematic to the point of
/// being uselessly unbelievable.
///
/// For example, I can simply say "I am the queen of England" and what
/// onchain mechanism could possibly check, let alone stop me?
/// The same problem exists in any situation where some privilege or right is
/// associated with identity. Consider passports, driver's licenses,
/// celebrity status, age, health, accredited investor, social media account,
/// etc. etc.
///
/// Typically crypto can't and doesn't want to deal with this issue. The usual
/// scenario is that some system demands personal information, which leads to:
///
/// - Data breaches that put individual's safety at risk. Consider the December
///   2020 leak from Ledger that dumped 270 000 home addresses and phone
///   numbers, and another million emails, of hardware wallet owners on a
///   public forum.
/// - Discriminatory access, undermining an individual's self-sovereign right
///   to run a full node, self-host a GUI and broadcast transactions onchain.
///   Consider the dydx airdrop of 2021 where metadata about a user's access
///   patterns logged on a server were used to deny access to presumed
///   Americans over regulatory fears.
/// - An entrenched supply chain of centralized actors from regulators, to
///   government databases, through KYC corporations, platforms, etc. each of
///   which holds an effective monopoly over, and ability to manipulate user's
///   "own" identity.
///
/// These examples and others are completely antithetical to and undermine the
/// safety of an opt-in, permissionless system based on pseudonomous actors
/// self-signing actions into a shared space.
///
/// That said, one can hardly expect a permissionless pseudonomous system
/// founded on asynchronous value transfers to succeed without at least some
/// concept of curation and reputation.
///
/// Anon, will you invest YOUR money in anon's project?
///
/// Clearly for every defi blue chip there are 10 000 scams and nothing onchain
/// can stop a scam, this MUST happen at the social layer.
///
/// Rain protocol is agnostic to how this verification happens. A government
/// regulator is going to want a government issued ID cross-referenced against
/// international sanctions. A fan of some social media influencer wants to
/// see a verified account on that platform. An open source software project
/// should show a github profile. A security token may need evidence from an
/// accountant showing accredited investor status. There are so many ways in
/// which BOTH sides of a fundraise may need to verify something about
/// themselves to each other via a THIRD PARTY that Rain cannot assume much.
///
/// The trust model and process for Rain verification is:
///
/// - There are many `Verify` contracts, each represents a specific
///   verification method with a (hopefully large) set of possible reviewers.
/// - The verifyee compiles some evidence that can be referenced in some
///   relevant system. It could be a session ID in a KYC provider's database or
///   a tweet from a verified account, etc. The evidence is passed to the
///   `Verify` contract as raw bytes so it is opaque onchain, but visible as an
///   event to verifiers.
/// - The verifyee calls `add` _for themselves_ to initialize their state and
///   emit the evidence for their account, after which they _cannot change_
///   their submission without appealing to someone who can remove. This costs
///   gas, so why don't we simply ask the user to sign something and have an
///   approver verify the signed data? Because we want to leverage both the
///   censorship resistance and asynchronous nature of the underlying
///   blockchain. Assuming there are N possible approvers, we want ANY 1 of
///   those N approvers to be able to review and approve an application. If the
///   user is forced to submit their application directly to one SPECIFIC
///   approver we lose this property. In the gasless model the user must then
///   rely on their specific approver both being online and not to censor the
///   request. It's also possible that many accounts add the same evidence,
///   after all it will be public in the event logs, so it is important for
///   approvers to verify the PAIRING between account and evidence.
/// - ANY account with the `APPROVER` role can review the evidence by
///   inspecting the event logs. IF the evidence is valid then the `approve`
///   function should be called by the approver. Approvers MAY also approve and
///   implicitly add any account atomically if the account did not previously
///   add itself.
/// - ANY account with the `BANNER` role can veto either an add OR a prior
///   approval. In the case of a false positive, i.e. where an account was
///   mistakenly approved, an appeal can be made to a banner to update the
///   status. Bad accounts SHOULD BE BANNED NOT REMOVED. When an account is
///   removed, its onchain state is once again open for the attacker to
///   resubmit new fraudulent evidence and potentially be reapproved.
///   Once an account is banned, any attempt by the account holder to change
///   their status, or an approver to approve will be rejected. Downstream
///   consumers of a `State` MUST check for an existing ban. Banners MAY ban
///   and implicity add any account atomically if the account did not
///   previously add itself.
///   - ANY account with the `REMOVER` role can scrub the `State` from an
///   account. Of course, this is a blockchain so the state changes are all
///   still visible to full nodes and indexers in historical data, in both the
///   onchain history and the event logs for each state change. This allows an
///   account to appeal to a remover in the case of a MISTAKEN BAN or also in
///   the case of a MISTAKEN ADD (e.g. mistake in evidence), effecting a
///   "hard reset" at the contract storage level.
///
/// Banning some account with an invalid session is NOT required. It is
/// harmless for an added session to remain as `Status.Added` indefinitely.
/// For as long as no approver decides to approve some invalid added session it
/// MUST be treated as equivalent to a ban by downstream contracts. This is
/// important so that admins are only required to spend gas on useful actions.
///
/// In addition to `Approve`, `Ban`, `Remove` there are corresponding events
/// `RequestApprove`, `RequestBan`, `RequestRemove` that allow for admins to be
/// notified that some new evidence must be considered that may lead to each
/// action. `RequestApprove` is automatically submitted as part of the `add`
/// call, but `RequestBan` and `RequestRemove` must be manually called
///
/// Rain uses standard Open Zeppelin `AccessControl` and is agnostic to how the
/// approver/remover/banner roles and associated admin roles are managed.
/// Ideally the more credibly neutral qualified parties assigend to each role
/// for each `Verify` contract the better. This improves the censorship
/// resistance of the verification process and the responsiveness of the
/// end-user experience.
///
/// Ideally the admin account assigned at deployment would renounce their admin
/// rights after establishing a more granular and appropriate set of accounts
/// with each specific role.
///
/// There is no requirement that any of the privileged accounts with roles are
/// a single-key EOA, they may be multisig accounts or even a DAO with formal
/// governance processes mediated by a smart contract.
///
/// Every action emits an associated event and optionally calls an onchain
/// callback on a `IVerifyCallbackV1` contract set during initialize. As each
/// action my be performed in bulk dupes are not rolled back, instead the
/// events are emitted for every time the action is called and the callbacks
/// and onchain state changes are deduped. For example, an approve may be
/// called twice for a single account, but by different approvers, potentially
/// submitting different evidence for each approval. In this case the time of
/// the first approve will be used and the onchain callback will be called for
/// the first transaction only, but BOTH approvals will emit an event. This
/// logic is applied per-account, per-action across a batch of evidences.
contract Verify is IVerifyV1, ICloneableV2, AccessControl {
    using LibUint256Array for uint256[];
    using LibEvidence for uint256[];
    using LibVerifyStatus for VerifyStatus;

    /// Any state never held is UNINITIALIZED.
    /// Note that as per default evm an unset state is 0 so always check the
    /// `addedSince` time on a `State` before trusting an equality check on
    /// any other time.
    /// (i.e. removed or never added)
    uint32 private constant UNINITIALIZED = type(uint32).max;

    /// Emitted when the `Verify` contract is initialized.
    event Initialize(address sender, VerifyConfig config);

    /// Emitted when evidence is first submitted to approve an account.
    /// The requestor is always the `msg.sender` of the user calling `add`.
    /// @param sender The `msg.sender` that submitted its own evidence.
    /// @param evidence The evidence to support an approval.
    /// NOT written to contract storage.
    event RequestApprove(address sender, Evidence evidence);
    /// Emitted when a previously added account is approved.
    /// @param sender The `msg.sender` that approved `account`.
    /// @param evidence The approval data.
    event Approve(address sender, Evidence evidence);

    /// Currently approved accounts can request that any account be banned.
    /// The requestor is expected to provide supporting data for the ban.
    /// The requestor MAY themselves be banned if vexatious.
    /// @param sender The `msg.sender` requesting a ban of `account`.
    /// @param evidence Account + data the `requestor` feels will strengthen
    /// its case for the ban. NOT written to contract storage.
    event RequestBan(address sender, Evidence evidence);
    /// Emitted when an added or approved account is banned.
    /// @param sender The `msg.sender` that banned `account`.
    /// @param evidence Account + the evidence to support a ban.
    /// NOT written to contract storage.
    event Ban(address sender, Evidence evidence);

    /// Currently approved accounts can request that any account be removed.
    /// The requestor is expected to provide supporting data for the removal.
    /// The requestor MAY themselves be banned if vexatious.
    /// @param sender The `msg.sender` requesting a removal of `account`.
    /// @param evidence `Evidence` to justify a removal.
    event RequestRemove(address sender, Evidence evidence);
    /// Emitted when an account is scrubbed from blockchain state.
    /// Historical logs still visible offchain of course.
    /// @param sender The `msg.sender` that removed `account`.
    /// @param evidence `Evidence` to justify the removal.
    event Remove(address sender, Evidence evidence);

    /// Admin role for `APPROVER`.
    bytes32 public constant APPROVER_ADMIN = keccak256("APPROVER_ADMIN");
    /// Role for `APPROVER`.
    bytes32 public constant APPROVER = keccak256("APPROVER");

    /// Admin role for `REMOVER`.
    bytes32 public constant REMOVER_ADMIN = keccak256("REMOVER_ADMIN");
    /// Role for `REMOVER`.
    bytes32 public constant REMOVER = keccak256("REMOVER");

    /// Admin role for `BANNER`.
    bytes32 public constant BANNER_ADMIN = keccak256("BANNER_ADMIN");
    /// Role for `BANNER`.
    bytes32 public constant BANNER = keccak256("BANNER");

    /// Account => State
    mapping(address => State) private sStates;

    /// Optional IVerifyCallbackV1 contract.
    /// MAY be address 0.
    IVerifyCallbackV1 public sCallback;

    constructor() {
        _disableInitializers();
    }

    /// @inheritdoc ICloneableV2
    function initialize(bytes calldata data) external initializer returns (bytes32) {
        VerifyConfig memory config = abi.decode(data, (VerifyConfig));
        require(config.admin != address(0), "0_ACCOUNT");
        __AccessControl_init();

        // `APPROVER_ADMIN` can admin each other in addition to
        // `APPROVER` addresses underneath.
        _setRoleAdmin(APPROVER_ADMIN, APPROVER_ADMIN);
        _setRoleAdmin(APPROVER, APPROVER_ADMIN);

        // `REMOVER_ADMIN` can admin each other in addition to
        // `REMOVER` addresses underneath.
        _setRoleAdmin(REMOVER_ADMIN, REMOVER_ADMIN);
        _setRoleAdmin(REMOVER, REMOVER_ADMIN);

        // `BANNER_ADMIN` can admin each other in addition to
        // `BANNER` addresses underneath.
        _setRoleAdmin(BANNER_ADMIN, BANNER_ADMIN);
        _setRoleAdmin(BANNER, BANNER_ADMIN);

        // It is STRONGLY RECOMMENDED that the `admin` delegates specific
        // admin roles then revokes the `X_ADMIN` roles. From themselves.
        // It is ALSO RECOMMENDED that each of the sub-`X_ADMIN` roles revokes
        // their admin rights once sufficient approvers/removers/banners have
        // been assigned, if possible. Admins can instantly/atomically assign
        // and revoke admin privileges from each other, so a compromised key
        // can irreperably damage a `Verify` contract instance.
        _grantRole(APPROVER_ADMIN, config.admin);
        _grantRole(REMOVER_ADMIN, config.admin);
        _grantRole(BANNER_ADMIN, config.admin);

        sCallback = IVerifyCallbackV1(config.callback);

        emit Initialize(msg.sender, config);

        return ICLONEABLE_V2_SUCCESS;
    }

    /// Typed accessor into states.
    /// @param account The account to return the current `State` for.
    function state(address account) external view returns (State memory) {
        return sStates[account];
    }

    /// Derives a single `Status` from a `State` and a reference timestamp.
    /// @param lState The raw `State` to reduce into a `Status`.
    /// @param timestamp The timestamp to compare `State` against.
    /// @return status The status in `State` given `timestamp`.
    function statusAtTime(State memory lState, uint256 timestamp) public pure returns (VerifyStatus status) {
        // The state hasn't even been added so is picking up time zero as the
        // evm fallback value. In this case if we checked other times using
        // a `<=` equality they would incorrectly return `true` always due to
        // also having a `0` fallback value.
        // Using `< 1` here to silence slither.
        if (lState.addedSince < 1) {
            status = LibVerifyConstants.STATUS_NIL;
        }
        // Banned takes priority over everything.
        else if (lState.bannedSince <= timestamp) {
            status = LibVerifyConstants.STATUS_BANNED;
        }
        // Approved takes priority over added.
        else if (lState.approvedSince <= timestamp) {
            status = LibVerifyConstants.STATUS_APPROVED;
        }
        // Added is lowest priority.
        else if (lState.addedSince <= timestamp) {
            status = LibVerifyConstants.STATUS_ADDED;
        }
        // The `addedSince` time is after `timestamp` so `Status` is nil
        // relative to `timestamp`.
        else {
            status = LibVerifyConstants.STATUS_NIL;
        }
    }

    /// @inheritdoc IVerifyV1
    function accountStatusAtTime(address account, uint256 timestamp) external view virtual returns (VerifyStatus) {
        return statusAtTime(sStates[account], timestamp);
    }

    /// Requires that `msg.sender` is approved as at the current timestamp.
    modifier onlyApproved() {
        require(
            statusAtTime(sStates[msg.sender], block.timestamp).eq(LibVerifyConstants.STATUS_APPROVED), "ONLY_APPROVED"
        );
        _;
    }

    /// @dev Builds a new `State` for use by `add` and `approve`.
    function newState() private view returns (State memory) {
        return State(uint32(block.timestamp), UNINITIALIZED, UNINITIALIZED);
    }

    /// An account adds their own verification evidence.
    /// Internally `msg.sender` is used; delegated `add` is not supported.
    /// @param data The evidence to support approving the `msg.sender`.
    function add(bytes calldata data) external {
        State memory lState = sStates[msg.sender];
        VerifyStatus currentStatus = statusAtTime(lState, block.timestamp);
        require(
            !currentStatus.eq(LibVerifyConstants.STATUS_APPROVED) && !currentStatus.eq(LibVerifyConstants.STATUS_BANNED),
            "ALREADY_EXISTS"
        );
        // An account that hasn't already been added need a new state.
        // If an account has already been added but not approved or banned
        // they can emit many `RequestApprove` events without changing
        // their state. This facilitates multi-step workflows for the KYC
        // provider, e.g. to implement a commit+reveal scheme or simply
        // request additional evidence from the applicant before final
        // verdict.
        if (currentStatus.eq(LibVerifyConstants.STATUS_NIL)) {
            sStates[msg.sender] = newState();
        }
        Evidence memory evidence = Evidence(msg.sender, data);
        emit RequestApprove(msg.sender, evidence);

        // Call the `afterAdd` hook to allow inheriting contracts to enforce
        // requirements.
        // The inheriting contract MUST `require` or otherwise enforce its
        // needs to rollback a bad add.
        IVerifyCallbackV1 callback = sCallback;
        if (address(callback) != address(0)) {
            Evidence[] memory evidences = new Evidence[](1);
            evidences[0] = evidence;
            callback.afterAdd(msg.sender, evidences);
        }
    }

    /// An `APPROVER` can review added evidence and approve accounts.
    /// Typically many approvals would be submitted in a single call which is
    /// more convenient and gas efficient than sending individual transactions
    /// for every approval. However, as there are many individual agents
    /// acting concurrently and independently this requires that the approval
    /// process be infallible so that no individual approval can rollback the
    /// entire batch due to the actions of some other approver/banner. It is
    /// possible to approve an already approved or banned account. The
    /// `Approve` event will always emit but the approved time will only be
    /// set if it was previously uninitialized. A banned account will always
    /// be seen as banned when calling `statusAtTime` regardless of the
    /// approval time, even if the approval is more recent than the ban. The
    /// only way to reset a ban is to remove and reapprove the account.
    /// @param evidences All evidence for all approvals.
    function approve(Evidence[] memory evidences) external onlyRole(APPROVER) {
        unchecked {
            State memory lState;
            uint256[] memory addedRefs = new uint256[](evidences.length);
            uint256[] memory approvedRefs = new uint256[](evidences.length);
            uint256 additions = 0;
            uint256 approvals = 0;

            for (uint256 i = 0; i < evidences.length; i++) {
                Evidence memory evidence = evidences[i];
                lState = sStates[evidence.account];
                // If the account hasn't been added an approver can still add
                // and approve it on their behalf.
                if (lState.addedSince < 1) {
                    lState = newState();

                    LibEvidence._updateEvidenceRef(addedRefs, evidence, additions);
                    additions++;
                }
                // If the account hasn't been approved we approve it. As there
                // are many approvers operating independently and concurrently
                // we do NOT `require` the approval be unique, but we also do
                // NOT change the time as the oldest approval is most
                // important. However we emit an event for every approval even
                // if the state does not change.
                // It is possible to approve a banned account but
                // `statusAtTime` will ignore the approval time for any banned
                // account and use the banned time only.
                if (lState.approvedSince == UNINITIALIZED) {
                    lState.approvedSince = uint32(block.timestamp);
                    sStates[evidence.account] = lState;

                    LibEvidence._updateEvidenceRef(approvedRefs, evidence, approvals);
                    approvals++;
                }

                // Always emit an `Approve` event even if we didn't write to
                // storage. This ensures that supporting evidence hits the logs
                // for offchain review.
                emit Approve(msg.sender, evidence);
            }
            IVerifyCallbackV1 callback = sCallback;
            if (address(callback) != address(0)) {
                if (additions > 0) {
                    addedRefs.truncate(additions);
                    callback.afterAdd(msg.sender, addedRefs.asEvidences());
                }
                if (approvals > 0) {
                    approvedRefs.truncate(approvals);
                    callback.afterApprove(msg.sender, approvedRefs.asEvidences());
                }
            }
        }
    }

    /// Any approved address can request some address be approved.
    /// Frivolous requestors SHOULD expect to find themselves banned.
    /// @param evidences Array of evidences to request approvals for.
    function requestApprove(Evidence[] calldata evidences) external onlyApproved {
        unchecked {
            for (uint256 i = 0; i < evidences.length; i++) {
                emit RequestApprove(msg.sender, evidences[i]);
            }
        }
    }

    /// A `BANNER` can ban an added OR approved account.
    /// @param evidences All evidence appropriate for all bans.
    function ban(Evidence[] calldata evidences) external onlyRole(BANNER) {
        unchecked {
            State memory lState;
            uint256[] memory addedRefs = new uint256[](evidences.length);
            uint256[] memory bannedRefs = new uint256[](evidences.length);
            uint256 additions = 0;
            uint256 bans = 0;
            for (uint256 i = 0; i < evidences.length; i++) {
                Evidence memory evidence = evidences[i];
                lState = sStates[evidence.account];

                // There is no requirement that an account be formerly added
                // before it is banned. For example some fraud may be detected
                // in an affiliated `Verify` contract and the evidence can be
                // used to ban the same address in the current contract. In
                // this case the account will be added and banned in this call.
                if (lState.addedSince < 1) {
                    lState = newState();

                    LibEvidence._updateEvidenceRef(addedRefs, evidence, additions);
                    additions++;
                }
                // Respect prior bans by leaving onchain storage as-is.
                if (lState.bannedSince == UNINITIALIZED) {
                    lState.bannedSince = uint32(block.timestamp);
                    sStates[evidence.account] = lState;

                    LibEvidence._updateEvidenceRef(bannedRefs, evidence, bans);
                    bans++;
                }

                // Always emit a `Ban` event even if we didn't write state. This
                // ensures that supporting evidence hits the logs for offchain
                // review.
                emit Ban(msg.sender, evidence);
            }
            IVerifyCallbackV1 callback = sCallback;
            if (address(callback) != address(0)) {
                if (additions > 0) {
                    addedRefs.truncate(additions);
                    callback.afterAdd(msg.sender, addedRefs.asEvidences());
                }
                if (bans > 0) {
                    bannedRefs.truncate(bans);
                    callback.afterBan(msg.sender, bannedRefs.asEvidences());
                }
            }
        }
    }

    /// Any approved address can request some address be banned.
    /// Frivolous requestors SHOULD expect to find themselves banned.
    /// @param evidences Array of evidences to request banning for.
    function requestBan(Evidence[] calldata evidences) external onlyApproved {
        unchecked {
            for (uint256 i = 0; i < evidences.length; i++) {
                emit RequestBan(msg.sender, evidences[i]);
            }
        }
    }

    /// A `REMOVER` can scrub state mapping from an account.
    /// A malicious account MUST be banned rather than removed.
    /// Removal is useful to reset the whole process in case of some mistake.
    /// @param evidences All evidence to suppor the removal.
    function remove(Evidence[] memory evidences) external onlyRole(REMOVER) {
        unchecked {
            State memory lState;
            uint256[] memory removedRefs = new uint256[](evidences.length);
            uint256 removals = 0;
            for (uint256 i = 0; i < evidences.length; i++) {
                Evidence memory evidence = evidences[i];
                lState = sStates[evidences[i].account];
                if (lState.addedSince > 0) {
                    delete (sStates[evidence.account]);
                    LibEvidence._updateEvidenceRef(removedRefs, evidence, removals);
                    removals++;
                }
                emit Remove(msg.sender, evidence);
            }
            IVerifyCallbackV1 callback = sCallback;
            if (address(callback) != address(0)) {
                if (removals > 0) {
                    removedRefs.truncate(removals);
                    callback.afterRemove(msg.sender, removedRefs.asEvidences());
                }
            }
        }
    }

    /// Any approved address can request some address be removed.
    /// Frivolous requestors SHOULD expect to find themselves banned.
    /// @param evidences Array of evidences to request removal of.
    function requestRemove(Evidence[] calldata evidences) external onlyApproved {
        unchecked {
            for (uint256 i = 0; i < evidences.length; i++) {
                emit RequestRemove(msg.sender, evidences[i]);
            }
        }
    }
}
