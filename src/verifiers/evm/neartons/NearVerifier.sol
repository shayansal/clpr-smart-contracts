// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {NearLightClient} from "@hiero-ledger/clpr/libraries/proof/near/NearLightClient.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";
import {ClprNearTonBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprNearTonBundleVerifier.sol";

/// @title NearVerifier
/// @notice NEAR → Hiero CLPR verifier: a NEAR light client (block-producer Ed25519 approvals, epoch
///         by epoch) plus a NEAR state-trie proof of the CLPR Service's contract storage.
///
/// Trust anchor (128 bytes): `epochId ‖ nextEpochId ‖ sha256(producers(epochId)) ‖ sha256(producers(nextEpochId))`,
/// exactly the state a NEP-25 light client keeps. Anchor id: `epochId`.
///
/// Proof chain:
///   light-client block(s) (> 2/3 stake of the epoch's producers approve `next_block_hash`)
///   → `inner_lite.prev_state_root` = merklize(chunk prev_state_roots)
///   → shard state root → trie path to `ContractData{service, key}` → value.
///
/// Storage keys the NEAR CLPR Service must use (near-sdk `LookupMap` / raw `env::storage_write`):
///   `"q" ‖ channelId(32)` → Borsh `ChannelQueue` (89 bytes, see {ClprNearTonBundleVerifier}),
///   `"m"` → keccak256 of the endpoint-manifest protobuf (32 bytes),
///   `"c"` → keccak256 of the configuration ControlMessage protobuf (32 bytes).
contract NearVerifier is ClprNearTonBundleVerifier {
    using NearLightClient for NearLightClient.EpochState;

    /// @dev Proven state root: the shard roots of the last block, in shard order, and the shard index.
    struct ShardRoots {
        bytes32[] roots;
        uint256 index;
    }

    struct BundleProof {
        NearLightClient.Block[] blocks; // applied in order; the last block's state root is used
        ShardRoots shards;
        bytes[] queueNodes; // trie path to "q" ‖ channelId
        bytes queueRecord; // Borsh ChannelQueue
        bytes bundleContent; // ClprBundleContent protobuf
        bytes[] manifestNodes; // trie path to "m"; empty = no manifest in this bundle
        bytes manifestPreimage;
    }

    struct ConfigProof {
        NearLightClient.Block[] blocks; // from the deploy-time checkpoint
        ShardRoots shards;
        bytes[] configNodes; // trie path to "c"
        bytes controlMessage; // ClprMessagePayload{control{config_update}} protobuf; keccak == value at "c"
    }

    /// @dev Optional `endpointManifestProofBytes` of {verifyConfig}: proven against the same shard
    ///      root as the configuration.
    struct ManifestProof {
        bytes[] manifestNodes;
        bytes manifestPreimage;
    }

    /// @dev Generic proof of any contract storage entry (used by the live tests: no CLPR Service is
    ///      deployed on NEAR yet).
    struct StateProof {
        NearLightClient.Block[] blocks;
        ShardRoots shards;
        bytes accountId;
        bytes dataKey;
        bytes[] nodes;
        bytes value;
    }

    bytes internal constant KEY_QUEUE_PREFIX = "q";
    bytes internal constant KEY_MANIFEST = "m";
    bytes internal constant KEY_CONFIG = "c";
    uint256 internal constant ANCHOR_LENGTH = 128;
    uint256 internal constant QUEUE_RECORD_LENGTH = 89;

    IEd25519Verifier public immutable ED25519;
    /// @notice Optional (zero = disabled) cache that lets a relayer pre-verify approvals in earlier txs.
    ClprEd25519SignatureCache public immutable SIGNATURE_CACHE;
    /// @notice keccak256 of the CAIP-2 chain id this verifier accepts (e.g. "near:mainnet").
    bytes32 public immutable CHAIN_ID_HASH;
    /// @notice Weak-subjectivity checkpoint `verifyConfig` starts from.
    bytes32 public immutable CHECKPOINT_EPOCH_ID;
    bytes32 public immutable CHECKPOINT_NEXT_EPOCH_ID;
    bytes32 public immutable CHECKPOINT_EPOCH_BP_HASH;
    bytes32 public immutable CHECKPOINT_NEXT_BP_HASH;

    error InvalidAnchor();
    error NoBlocks();
    error ZeroAddress();

    constructor(
        string memory chainId,
        NearLightClient.EpochState memory checkpoint_,
        IEd25519Verifier ed25519,
        ClprEd25519SignatureCache signatureCache
    ) {
        if (address(ed25519) == address(0)) revert ZeroAddress();
        ED25519 = ed25519;
        SIGNATURE_CACHE = signatureCache;
        CHAIN_ID_HASH = keccak256(bytes(chainId));
        CHECKPOINT_EPOCH_ID = checkpoint_.epochId;
        CHECKPOINT_NEXT_EPOCH_ID = checkpoint_.nextEpochId;
        CHECKPOINT_EPOCH_BP_HASH = checkpoint_.epochBpHash;
        CHECKPOINT_NEXT_BP_HASH = checkpoint_.nextBpHash;
    }

    // ── IClprVerifier ────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = abi.encode(BundleProof).
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
        NearLightClient.EpochState memory st = decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        _checkAccountId(ctx.remoteServiceAddress);
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        (bytes32 shardRoot, NearLightClient.EpochState memory end) = _verifyBlocks(st, p.blocks, p.shards);

        NearLightClient.verifyValue(
            shardRoot,
            NearLightClient.contractDataKey(
                ctx.remoteServiceAddress, abi.encodePacked(KEY_QUEUE_PREFIX, ctx.channelId)
            ),
            p.queueNodes,
            p.queueRecord
        );
        metadata = _decodeQueueRecord(p.queueRecord);
        messagePayloads = _decodeBundleContent(p.bundleContent);

        if (p.manifestNodes.length == 0) {
            newEndpointManifest = _absentEndpointManifest();
        } else {
            bytes32 commitment = keccak256(p.manifestPreimage);
            _proveCommitment(shardRoot, ctx.remoteServiceAddress, KEY_MANIFEST, p.manifestNodes, commitment);
            newEndpointManifest = _bindManifest(p.manifestPreimage, commitment, ctx.remoteServiceAddress);
        }

        if (end.epochId != st.epochId) {
            newTrustAnchor = encodeAnchor(end);
            newTrustAnchorId = abi.encodePacked(end.epochId);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof), starting from the deploy-time checkpoint. The
    ///      configuration is the ControlMessage whose keccak256 the NEAR service stores under "c", so
    ///      chain id, service address, timestamp and throttles are all proven. A non-empty
    ///      `endpointManifestProofBytes` = abi.encode(ManifestProof) against the same shard root.
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
        ConfigProof memory p = abi.decode(configProofBytes, (ConfigProof));
        (bytes32 shardRoot, NearLightClient.EpochState memory end) = _verifyBlocks(checkpoint(), p.blocks, p.shards);

        // The service account is named by the message itself; proving keccak256(message) is stored
        // under "c" of that account makes every field of the message proven.
        bytes32 commitment = keccak256(p.controlMessage);
        ClprTypes.LedgerConfiguration memory lc = _bindConfig(p.controlMessage, commitment, CHAIN_ID_HASH);
        _checkAccountId(lc.serviceAddress);
        _proveCommitment(shardRoot, lc.serviceAddress, KEY_CONFIG, p.configNodes, commitment);

        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        initialTrustAnchor = encodeAnchor(end);
        initialTrustAnchorId = abi.encodePacked(end.epochId);

        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            ManifestProof memory mp = abi.decode(endpointManifestProofBytes, (ManifestProof));
            bytes32 mc = keccak256(mp.manifestPreimage);
            _proveCommitment(shardRoot, serviceAddress, KEY_MANIFEST, mp.manifestNodes, mc);
            endpointManifest = _bindManifest(mp.manifestPreimage, mc, serviceAddress);
        }
    }

    // ── Generic entry points ─────────────────────────────────────────────────

    /// @notice Verify light-client blocks from `trustAnchor` and one contract storage entry under the
    ///         last block's state root. Returns the proven value, the last block hash and its height,
    ///         and the new anchor (empty when the epoch did not change).
    function verifyStateValue(bytes calldata proofBytes, bytes calldata trustAnchor)
        external
        view
        returns (bytes memory value, bytes32 lastBlockHash, uint64 height, bytes memory newTrustAnchor)
    {
        NearLightClient.EpochState memory st = decodeAnchor(trustAnchor);
        StateProof memory p = abi.decode(proofBytes, (StateProof));
        _checkAccountId(p.accountId);
        (bytes32 shardRoot, NearLightClient.EpochState memory end) = _verifyBlocks(st, p.blocks, p.shards);
        NearLightClient.verifyValue(
            shardRoot, NearLightClient.contractDataKey(p.accountId, p.dataKey), p.nodes, p.value
        );
        value = p.value;
        NearLightClient.Block memory last = p.blocks[p.blocks.length - 1];
        lastBlockHash = NearLightClient.blockHash(last);
        height = NearLightClient.parseInnerLite(last.innerLite).height;
        if (end.epochId != st.epochId) newTrustAnchor = encodeAnchor(end);
    }

    /// @notice The deploy-time checkpoint as an epoch window.
    function checkpoint() public view returns (NearLightClient.EpochState memory) {
        return NearLightClient.EpochState({
            epochId: CHECKPOINT_EPOCH_ID,
            nextEpochId: CHECKPOINT_NEXT_EPOCH_ID,
            epochBpHash: CHECKPOINT_EPOCH_BP_HASH,
            nextBpHash: CHECKPOINT_NEXT_BP_HASH
        });
    }

    function encodeAnchor(NearLightClient.EpochState memory st) public pure returns (bytes memory) {
        return abi.encodePacked(st.epochId, st.nextEpochId, st.epochBpHash, st.nextBpHash);
    }

    function decodeAnchor(bytes calldata a) public pure returns (NearLightClient.EpochState memory st) {
        if (a.length != ANCHOR_LENGTH) revert InvalidAnchor();
        st.epochId = bytes32(a[0:32]);
        st.nextEpochId = bytes32(a[32:64]);
        st.epochBpHash = bytes32(a[64:96]);
        st.nextBpHash = bytes32(a[96:128]);
    }

    // ── internals ────────────────────────────────────────────────────────────

    function _verifyBlocks(
        NearLightClient.EpochState memory st,
        NearLightClient.Block[] memory blocks,
        ShardRoots memory shards
    ) internal view returns (bytes32 shardRoot, NearLightClient.EpochState memory end) {
        if (blocks.length == 0) revert NoBlocks();
        NearLightClient.InnerLite memory lite;
        end = st;
        for (uint256 i = 0; i < blocks.length; i++) {
            (lite, end) = NearLightClient.verifyBlock(end, blocks[i], ED25519, SIGNATURE_CACHE);
        }
        shardRoot = NearLightClient.shardStateRoot(lite.prevStateRoot, shards.roots, shards.index);
    }

    /// @dev Prove that the service stores `commitment` (32 bytes) under `key`.
    function _proveCommitment(
        bytes32 shardRoot,
        bytes memory account,
        bytes memory key,
        bytes[] memory nodes,
        bytes32 commitment
    ) internal pure {
        NearLightClient.verifyValue(
            shardRoot, NearLightClient.contractDataKey(account, key), nodes, abi.encodePacked(commitment)
        );
    }

    function _decodeQueueRecord(bytes memory r) internal pure returns (ClprTypes.QueueMetadata memory) {
        if (r.length != QUEUE_RECORD_LENGTH) revert InvalidQueueRecord();
        return _queueMetadata(
            uint8(r[0]),
            NearLightClient._readLe64(r, 1),
            NearLightClient._readLe64(r, 9),
            _bytes32At(r, 17),
            _bytes32At(r, 49),
            NearLightClient._readLe64(r, 81)
        );
    }

    /// @dev NEAR account ids are 2–64 bytes (nearcore `AccountId` validation); the trie key embeds it.
    function _checkAccountId(bytes memory id) internal pure {
        if (id.length < 2 || id.length > 64) revert InvalidServiceAddress();
        for (uint256 i = 0; i < id.length; i++) {
            bytes1 c = id[i];
            bool ok = (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-" || c == "_" || c == ".";
            if (!ok) revert InvalidServiceAddress();
        }
    }
}
