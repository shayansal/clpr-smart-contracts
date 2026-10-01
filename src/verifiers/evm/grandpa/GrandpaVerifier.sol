// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {GrandpaLib} from "@hiero-ledger/clpr/libraries/proof/substrate/GrandpaLib.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";
import {SubstrateHeader} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateHeader.sol";
import {SubstrateEvmVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/grandpa/SubstrateEvmVerifierBase.sol";

/// @title GrandpaVerifier
/// @notice "Substrate solo chain → Hiero" verifier: GRANDPA finality (ed25519) plus Frontier EVM
///         storage through the Substrate state trie. Built for Bittensor (subtensor runtime:
///         Aura + GRANDPA + Frontier, pallet "EVM"); any solo chain with the same pieces is a
///         deploy-time profile. See README.md in this directory.
///
/// ## Trust anchor (44 bytes)
///   setId(u64 BE) ‖ authoritiesHash(32) ‖ minHeight(u32 BE)
///   `authoritiesHash` = keccak256 of the packed GRANDPA authority list (key(32) ‖ weight(u64 LE))*;
///   the set `setId` justifies blocks at or above `minHeight`.
///
/// ## Verification chain (verifyBundle)
///   For each step (in order, all but the last must change the authority set):
///     1. The supplied authority list must hash to the working anchor.
///     2. headers[0] is the justified block J (number ≥ minHeight); headers[k+1] is the parent of
///        headers[k]; the last header may carry a GRANDPA `ScheduledChange`.
///     3. The GRANDPA commit for (blake2_256(J), J.number) under (round, setId) must reach the
///        2/3+ weight threshold of the working set (ed25519 via {IEd25519Verifier}).
///     4. ScheduledChange{next, delay} signalled at block N (J ≤ N + delay): the working anchor
///        becomes (setId + 1, keccak256(next), N + delay + 1). A `ForcedChange` reverts.
///   The last step's J provides `state_root`; Frontier `AccountStorages` proofs give the channel's
///   queue metadata. A new anchor is returned iff the set changed.
contract GrandpaVerifier is SubstrateEvmVerifierBase {
    /// @dev One GRANDPA finality step. `votes`/`ancestry` are the re-packed justification (GrandpaLib).
    struct Step {
        bytes[] headers;
        uint64 round;
        bytes votes;
        bytes[] ancestry;
        bytes authorities;
    }

    struct BundleProof {
        Step[] steps;
        bytes[] stateProof;
        bool lastMessageSlot;
        bytes bundleContent;
        bytes manifestPreimage;
    }

    struct ConfigProof {
        Step[] steps;
        bytes[] stateProof;
        bytes ledgerConfig;
    }

    struct Anchor {
        uint64 setId;
        bytes32 authoritiesHash;
        uint32 minHeight;
    }

    uint256 internal constant ANCHOR_LENGTH = 44;

    IEd25519Verifier public immutable ED25519;
    uint64 public immutable BOOTSTRAP_SET_ID;
    bytes32 public immutable BOOTSTRAP_AUTHORITIES_HASH;
    uint32 public immutable BOOTSTRAP_MIN_HEIGHT;

    error InvalidProfile();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error AuthoritySetMismatch();
    error BrokenHeaderChain();
    error StepWithoutChange();
    error UnexpectedChange();
    error JustifiedPastChange();

    /// @param ed25519Verifier          Pure-Solidity Ed25519 verifier (no ed25519 precompile on Hedera).
    /// @param evmPalletPrefix          twox128 of the Frontier EVM pallet name.
    /// @param chainId                  CAIP-2 id the peer ClprService reports, e.g. "eip155:964".
    /// @param bootstrapSetId           Weak-subjectivity checkpoint: GRANDPA set id …
    /// @param bootstrapAuthoritiesHash … keccak256 of its packed authority list …
    /// @param bootstrapMinHeight       … and the first block number it justifies.
    constructor(
        address ed25519Verifier,
        bytes16 evmPalletPrefix,
        string memory chainId,
        uint64 bootstrapSetId,
        bytes32 bootstrapAuthoritiesHash,
        uint32 bootstrapMinHeight
    ) SubstrateEvmVerifierBase(evmPalletPrefix, chainId) {
        if (ed25519Verifier == address(0) || bootstrapAuthoritiesHash == bytes32(0)) {
            revert InvalidProfile();
        }
        ED25519 = IEd25519Verifier(ed25519Verifier);
        BOOTSTRAP_SET_ID = bootstrapSetId;
        BOOTSTRAP_AUTHORITIES_HASH = bootstrapAuthoritiesHash;
        BOOTSTRAP_MIN_HEIGHT = bootstrapMinHeight;
    }

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = abi.encode(BundleProof); trustAnchor = 44-byte {Anchor}.
    function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        view
        override
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        )
    {
        Anchor memory anchor = _decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        if (proofBytes.length == 0) revert InvalidPayloadShape();
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        (Anchor memory next, bytes32 stateRoot) = _applySteps(p.steps, anchor);
        (metadata, newEndpointManifest) = _verifyChannelState(
            p.stateProof, stateRoot, ctx.remoteServiceAddress, ctx.channelId, p.lastMessageSlot, p.manifestPreimage
        );
        messagePayloads = _decodeBundleContent(p.bundleContent);

        if (next.setId != anchor.setId) {
            newTrustAnchor = _encodeAnchor(next);
            newTrustAnchorId = abi.encodePacked(next.setId);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof), followed from the deploy-time bootstrap
    ///      checkpoint; endpointManifestProofBytes = the manifest preimage (or empty), proven against
    ///      the same state root as the config.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        override
        returns (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        )
    {
        if (configProofBytes.length == 0) revert InvalidPayloadShape();
        ConfigProof memory p = abi.decode(configProofBytes, (ConfigProof));
        (Anchor memory anchor, bytes32 stateRoot) = _applySteps(
            p.steps,
            Anchor({
                setId: BOOTSTRAP_SET_ID, authoritiesHash: BOOTSTRAP_AUTHORITIES_HASH, minHeight: BOOTSTRAP_MIN_HEIGHT
            })
        );
        ClprTypes.LedgerConfiguration memory lc;
        (lc, endpointManifest) = _verifyConfigState(p.stateProof, stateRoot, p.ledgerConfig, endpointManifestProofBytes);

        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        initialTrustAnchor = _encodeAnchor(anchor);
        initialTrustAnchorId = abi.encodePacked(anchor.setId);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Light client
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Applies the finality steps; returns the working anchor and the last justified state root.
    function _applySteps(Step[] memory steps, Anchor memory a)
        internal
        view
        returns (Anchor memory, bytes32 stateRoot)
    {
        if (steps.length == 0) revert InvalidPayloadShape();
        for (uint256 i; i < steps.length; ++i) {
            Step memory s = steps[i];
            if (s.headers.length == 0) revert InvalidPayloadShape();
            if (GrandpaLib.authoritiesHash(s.authorities) != a.authoritiesHash) revert AuthoritySetMismatch();

            SubstrateHeader.Header memory j = SubstrateHeader.decode(s.headers[0]);
            if (j.number < a.minHeight) revert HeightTooOld();

            // Parent-linked chain J → … → signal header; only the last header may signal a change.
            SubstrateHeader.Header memory h = j;
            SubstrateHeader.GrandpaChange memory change;
            uint256 last = s.headers.length - 1;
            for (uint256 k; k <= last; ++k) {
                if (k > 0) {
                    if (SubstrateHeader.hash(s.headers[k]) != h.parentHash) revert BrokenHeaderChain();
                    h = SubstrateHeader.decode(s.headers[k]);
                }
                change = SubstrateHeader.grandpaChange(s.headers[k], h);
                if (change.present && k != last) revert UnexpectedChange();
            }
            if (last > 0 && !change.present) revert StepWithoutChange();

            GrandpaLib.verifyCommit(
                GrandpaLib.Commit({
                    targetHash: SubstrateHeader.hash(s.headers[0]),
                    targetNumber: j.number,
                    round: s.round,
                    setId: a.setId,
                    votes: s.votes,
                    ancestry: s.ancestry
                }),
                s.authorities,
                ED25519
            );

            if (change.present) {
                // h is the signal header N. An honest set never finalizes past N + delay.
                uint256 enactedAt = uint256(h.number) + change.delay;
                if (j.number > enactedAt) revert JustifiedPastChange();
                a = Anchor({
                    setId: a.setId + 1,
                    authoritiesHash: ScaleCodec.keccakRange(
                        s.headers[last], change.authoritiesOffset, change.authoritiesLength
                    ),
                    // forge-lint: disable-next-line(unsafe-typecast)
                    minHeight: uint32(enactedAt + 1)
                });
            } else if (i + 1 != steps.length) {
                revert StepWithoutChange();
            }
            stateRoot = j.stateRoot;
        }
        return (a, stateRoot);
    }

    // ── Anchor codec ─────────────────────────────────────────────────────────

    function _decodeAnchor(bytes calldata t) internal pure returns (Anchor memory a) {
        if (t.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        a.setId = uint64(bytes8(t[0:8]));
        a.authoritiesHash = bytes32(t[8:40]);
        a.minHeight = uint32(bytes4(t[40:44]));
        if (a.authoritiesHash == bytes32(0)) revert InvalidTrustAnchor();
    }

    function _encodeAnchor(Anchor memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(a.setId, a.authoritiesHash, a.minHeight);
    }
}
