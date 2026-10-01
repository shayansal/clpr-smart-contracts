// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Runtimes3TestBase} from "./Runtimes3TestBase.sol";
import {MockEthL1StateVerifier} from "./MockEthL1StateVerifier.sol";
import {FuelVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/FuelVerifier.sol";
import {FuelBlockProof} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/FuelBlockProof.sol";
import {ClprQueueRecordVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/ClprQueueRecordVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev FuelVerifier against a synthetic Fuel chain (two blocks below the commit), synthetic
///      FuelChainState storage (a real MPT branch with four leaves) and a mock L1 light client.
///      The real Ethereum light client and real Fuel data run in fuel-live.spec.ts.
contract FuelVerifierTest is Runtimes3TestBase {
    MockEthL1StateVerifier internal l1;
    FuelVerifier internal verifier;

    address internal constant CHAIN_STATE = address(0xF0E1);
    bytes32 internal constant CODE_HASH = keccak256("FuelChainState proxy code");
    address internal constant IMPL = address(0x1111);
    bytes32 internal constant RECIPIENT = bytes32(uint256(0xC1C1));
    bytes32 internal constant SERVICE = keccak256("fuel clpr contract id");
    uint64 internal constant COMMIT_TS = 1_000_000;
    uint64 internal constant TTF = 3600;
    uint64 internal constant FINAL_SLOT = (COMMIT_TS + TTF) / 12 + 1;

    function setUp() public {
        l1 = new MockEthL1StateVerifier();
        verifier = new FuelVerifier(_profile(TTF, IMPL));
    }

    function _profile(uint64 ttf, address impl) internal view returns (FuelVerifier.Profile memory p) {
        p = FuelVerifier.Profile({
            l1StateVerifier: IEthL1StateVerifier(address(l1)),
            l1GenesisTime: 0,
            l1SecondsPerSlot: 12,
            chainState: CHAIN_STATE,
            chainStateCodeHash: CODE_HASH,
            chainStateImplementation: impl,
            commitSlotsBase: 301,
            pausedSlot: 51,
            numCommitSlots: 240,
            blocksPerCommitInterval: 1,
            timeToFinalize: ttf,
            messageRecipient: RECIPIENT
        });
    }

    // ── Synthetic Fuel chain ─────────────────────────────────────────────────

    struct Msg {
        bytes32 sender;
        bytes32 recipient;
        bytes32 nonce;
        uint64 amount;
        bytes data;
    }

    struct FuelChain {
        bytes commitHeader;
        bytes messageHeader;
        bytes blockProof;
        bytes messageProof;
        bytes message;
        bytes32 commitId;
    }

    function _msg(bytes memory record) internal pure returns (Msg memory) {
        return Msg({
            sender: SERVICE,
            recipient: RECIPIENT,
            nonce: keccak256("nonce"),
            amount: 0,
            data: abi.encodePacked(CHANNEL_ID, record)
        });
    }

    function _merkle(uint256 index, bytes32[] memory siblings) internal pure returns (bytes memory) {
        bytes[] memory s = new bytes[](siblings.length);
        for (uint256 i; i < siblings.length; ++i) {
            s[i] = RLP.encode(siblings[i]);
        }
        bytes[] memory f = new bytes[](2);
        f[0] = RLP.encode(index);
        f[1] = RLP.encode(s);
        return RLP.encode(f);
    }

    /// @dev Message block at height 1 (one message), committed block at height 2 whose prevRoot
    ///      covers blocks 0 and 1.
    function _chain(Msg memory m) internal pure returns (FuelChain memory c) {
        bytes32 id = FuelBlockProof.messageId(m.sender, m.recipient, m.nonce, m.amount, m.data);
        c.messageHeader = abi.encodePacked(
            keccak256("prev root of block 1"),
            uint32(1),
            uint64(4611686020218000000),
            uint64(7),
            uint32(1),
            uint32(1),
            uint16(1),
            uint32(1),
            keccak256("tx root"),
            FuelBlockProof.leafDigest(id),
            keccak256("event inbox root")
        );
        bytes32 messageBlockId = FuelBlockProof.fullHeader(c.messageHeader).id;
        bytes32 block0Leaf = FuelBlockProof.leafDigest(keccak256("block 0 id"));
        bytes32 prevRoot = FuelBlockProof.nodeDigest(block0Leaf, FuelBlockProof.leafDigest(messageBlockId));
        c.commitHeader = abi.encodePacked(prevRoot, uint32(2), uint64(4611686020218000100), keccak256("app hash 2"));
        c.commitId = sha256(c.commitHeader);
        bytes32[] memory sib = new bytes32[](1);
        sib[0] = block0Leaf;
        c.blockProof = _merkle(1, sib);
        c.messageProof = _merkle(0, new bytes32[](0));
        bytes[] memory mf = new bytes[](5);
        mf[0] = RLP.encode(m.sender);
        mf[1] = RLP.encode(m.recipient);
        mf[2] = RLP.encode(m.nonce);
        mf[3] = RLP.encode(uint256(m.amount));
        mf[4] = RLP.encode(m.data);
        c.message = RLP.encode(mf);
    }

    // ── Synthetic FuelChainState storage (MPT: one branch, four leaves) ─────

    function _leaf(bytes32 slot, bytes32 value) internal pure returns (bytes memory) {
        bytes32 k = keccak256(abi.encodePacked(slot));
        bytes memory compact = new bytes(32);
        compact[0] = bytes1(0x30 | (uint8(k[0]) & 0x0f));
        for (uint256 i = 1; i < 32; i++) {
            compact[i] = k[i];
        }
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(compact);
        items[1] = RLP.encode(RLP.encode(uint256(value)));
        return RLP.encode(items);
    }

    function _storage(bytes32[] memory slots, bytes32[] memory values)
        internal
        pure
        returns (bytes32 root, bytes memory storageProof)
    {
        bytes[] memory leaves = new bytes[](slots.length);
        bytes[] memory branch = new bytes[](17);
        for (uint256 n; n < 17; ++n) {
            branch[n] = RLP.encode(new bytes(0));
        }
        for (uint256 i; i < slots.length; ++i) {
            leaves[i] = _leaf(slots[i], values[i]);
            uint8 nib = uint8(keccak256(abi.encodePacked(slots[i]))[0]) >> 4;
            require(keccak256(branch[nib]) == keccak256(RLP.encode(new bytes(0))), "nibble collision");
            branch[nib] = RLP.encode(abi.encodePacked(keccak256(leaves[i])));
        }
        bytes memory branchNode = RLP.encode(branch);
        root = keccak256(branchNode);
        bytes[] memory entries = new bytes[](slots.length);
        for (uint256 i; i < slots.length; ++i) {
            bytes[] memory nodes = new bytes[](2);
            nodes[0] = RLP.encode(branchNode);
            nodes[1] = RLP.encode(leaves[i]);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slots[i]));
            entry[1] = RLP.encode(nodes);
            entries[i] = RLP.encode(entry);
        }
        storageProof = RLP.encode(entries);
    }

    function _account(bytes32 storageRoot, bytes32 codeHash) internal pure returns (bytes32 root, bytes memory proof) {
        bytes32 k = keccak256(abi.encodePacked(CHAIN_STATE));
        bytes memory path = abi.encodePacked(bytes1(0x20), k);
        bytes[] memory acct = new bytes[](4);
        acct[0] = RLP.encode(uint256(1));
        acct[1] = RLP.encode(uint256(0));
        acct[2] = RLP.encode(storageRoot);
        acct[3] = RLP.encode(codeHash);
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(path);
        items[1] = RLP.encode(RLP.encode(acct));
        bytes memory leaf = RLP.encode(items);
        root = keccak256(leaf);
        bytes[] memory nodes = new bytes[](1);
        nodes[0] = RLP.encode(leaf);
        proof = RLP.encode(nodes);
    }

    struct L1Opts {
        bytes32 committedId;
        uint64 commitTs;
        bool paused;
        address impl;
        bytes32 codeHash;
    }

    function _l1(FuelChain memory c) internal pure returns (L1Opts memory) {
        return L1Opts({committedId: c.commitId, commitTs: COMMIT_TS, paused: false, impl: IMPL, codeHash: CODE_HASH});
    }

    function _bundle(FuelChain memory c, L1Opts memory o, uint64 slot, bytes memory manifest)
        internal
        returns (bytes memory)
    {
        bytes32[] memory slots = verifier.chainStateSlots(2);
        bytes32[] memory values = new bytes32[](4);
        values[0] = o.committedId;
        values[1] = bytes32(uint256(o.commitTs));
        values[2] = o.paused ? bytes32(uint256(1)) : bytes32(0);
        values[3] = bytes32(uint256(uint160(o.impl)));
        (bytes32 storageRoot, bytes memory storageProof) = _storage(slots, values);
        (bytes32 stateRoot, bytes memory accountProof) = _account(storageRoot, o.codeHash);
        l1.set(stateRoot, slot, "");

        bytes[] memory items = new bytes[](manifest.length == 0 ? 9 : 10);
        items[0] = RLP.encode(bytes("light client proof (mocked)"));
        items[1] = accountProof;
        items[2] = storageProof;
        items[3] = RLP.encode(c.commitHeader);
        items[4] = RLP.encode(c.messageHeader);
        items[5] = c.blockProof;
        items[6] = c.messageProof;
        items[7] = c.message;
        items[8] = RLP.encode(_bundleContent());
        if (manifest.length != 0) items[9] = RLP.encode(manifest);
        return RLP.encode(items);
    }

    function _anchor(bytes32 channelId) internal pure returns (bytes memory) {
        return abi.encodePacked(
            keccak256("gvr"), bytes4(0x06000000), channelId, new bytes(128), keccak256("committee root"), CODE_HASH
        );
    }

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE)})
        );
    }

    function _default() internal returns (bytes memory) {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        return _bundle(c, _l1(c), FINAL_SLOT, "");
    }

    // ── Happy paths ──────────────────────────────────────────────────────────

    function test_verifyBundle_provesRecordMessage() public {
        bytes memory proof = _default();
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory newAnchor,,
            ClprTypes.ClprEndpointManifest memory man
        ) = verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
        _assertDefaultMetadata(m);
        assertEq(payloads.length, 2);
        assertEq(newAnchor.length, 0);
        assertEq(man.version, 0);
    }

    function test_verifyBundle_passesRotationThrough() public {
        bytes memory proof = _default();
        l1.set(l1.stateRoot(), FINAL_SLOT, hex"aabb");
        (,, bytes memory newAnchor, bytes memory newId,) = verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
        assertEq(newAnchor, hex"aabb");
        assertEq(newId, abi.encodePacked(uint64(7)));
    }

    function test_verifyBundle_withManifest() public {
        bytes memory manifest = _manifest(abi.encodePacked(SERVICE));
        FuelChain memory c = _chain(_msg(_record(1, 7, 3, 2, keccak256(manifest))));
        (,,,, ClprTypes.ClprEndpointManifest memory man) =
            verifier.verifyBundle(_bundle(c, _l1(c), FINAL_SLOT, manifest), _anchor(CHANNEL_ID), _ctx());
        assertEq(man.version, 3);
    }

    function test_verifyFuelMessage_returnsMessage() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        bytes[] memory items = new bytes[](8);
        items[0] = RLP.encode(bytes("lc"));
        bytes32[] memory slots = verifier.chainStateSlots(2);
        bytes32[] memory values = new bytes32[](4);
        values[0] = c.commitId;
        values[1] = bytes32(uint256(COMMIT_TS));
        values[3] = bytes32(uint256(uint160(IMPL)));
        (bytes32 storageRoot, bytes memory storageProof) = _storage(slots, values);
        (bytes32 stateRoot, bytes memory accountProof) = _account(storageRoot, CODE_HASH);
        l1.set(stateRoot, FINAL_SLOT, "");
        items[1] = accountProof;
        items[2] = storageProof;
        items[3] = RLP.encode(c.commitHeader);
        items[4] = RLP.encode(c.messageHeader);
        items[5] = c.blockProof;
        items[6] = c.messageProof;
        items[7] = c.message;
        (FuelVerifier.FuelMessage memory m,,) = verifier.verifyFuelMessage(RLP.encode(items), _anchor(CHANNEL_ID));
        assertEq(m.sender, SERVICE);
        assertEq(m.blockHeight, 1);
        assertEq(m.commitHeight, 2);
        assertEq(m.commitTimestamp, COMMIT_TS);
    }

    // ── Negative cases ───────────────────────────────────────────────────────

    function test_revert_otherChannelAnchor() public {
        bytes memory proof = _default();
        vm.expectRevert(FuelVerifier.ChannelMismatch.selector);
        verifier.verifyBundle(proof, _anchor(keccak256("other")), _ctx());
    }

    function test_revert_commitNotFinal() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        bytes memory proof = _bundle(c, _l1(c), (COMMIT_TS + TTF) / 12 - 1, "");
        vm.expectRevert(FuelVerifier.CommitNotFinal.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_commitMismatch() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        L1Opts memory o = _l1(c);
        o.committedId = keccak256("another committed block");
        bytes memory proof = _bundle(c, o, FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.CommitMismatch.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_paused() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        L1Opts memory o = _l1(c);
        o.paused = true;
        bytes memory proof = _bundle(c, o, FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.ChainStatePaused.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_upgradedImplementation() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        L1Opts memory o = _l1(c);
        o.impl = address(0x2222);
        bytes memory proof = _bundle(c, o, FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.ImplementationMismatch.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_wrongCodeHash() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        L1Opts memory o = _l1(c);
        o.codeHash = keccak256("other code");
        bytes memory proof = _bundle(c, o, FINAL_SLOT, "");
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_blockNotInHistory() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        c.blockProof = _merkle(0, new bytes32[](1));
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.BlockNotInHistory.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_tamperedMessageData() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        FuelChain memory forged = _chain(_msg(_record(1, 99, 3, 2, bytes32(0))));
        c.message = forged.message; // same outbox root, other data
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.MessageNotInBlock.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_wrongSender() public {
        Msg memory m = _msg(_defaultRecord());
        m.sender = keccak256("another contract");
        FuelChain memory c = _chain(m);
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.InvalidMessage.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_wrongRecipient() public {
        Msg memory m = _msg(_defaultRecord());
        m.recipient = bytes32(uint256(0xBAD));
        FuelChain memory c = _chain(m);
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.InvalidMessage.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_nonZeroAmount() public {
        Msg memory m = _msg(_defaultRecord());
        m.amount = 1;
        FuelChain memory c = _chain(m);
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.InvalidMessage.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_recordForOtherChannel() public {
        Msg memory m = _msg(_defaultRecord());
        m.data = abi.encodePacked(keccak256("other channel"), _defaultRecord());
        FuelChain memory c = _chain(m);
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.InvalidMessage.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_badRecord() public {
        FuelChain memory c = _chain(_msg(_record(9, 7, 3, 2, bytes32(0))));
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(ClprQueueRecordVerifier.InvalidQueueRecord.selector);
        verifier.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    // ── verifyConfig ─────────────────────────────────────────────────────────

    function test_verifyConfig() public view {
        bytes memory cfg = abi.encode(
            _anchor(CHANNEL_ID), abi.encodePacked(uint64(5)), _controlMessage("fuel:9889", abi.encodePacked(SERVICE))
        );
        (bytes memory ctx, string memory chainId,,,, bytes memory anchor,, ClprTypes.ClprEndpointManifest memory man) =
            verifier.verifyConfig(cfg, CHANNEL_ID, "");
        assertEq(ctx, _ctx());
        assertEq(chainId, "fuel:9889");
        assertEq(anchor, _anchor(CHANNEL_ID));
        assertEq(man.version, 0);
    }

    function test_revert_config_wrongCodeHash() public {
        bytes memory badAnchor = _anchor(CHANNEL_ID);
        badAnchor[259] = 0x00;
        bytes memory cfg = abi.encode(badAnchor, hex"05", _controlMessage("fuel:9889", abi.encodePacked(SERVICE)));
        vm.expectRevert(FuelVerifier.InvalidTrustAnchor.selector);
        verifier.verifyConfig(cfg, CHANNEL_ID, "");
    }

    function test_revert_config_manifestProof() public {
        bytes memory cfg =
            abi.encode(_anchor(CHANNEL_ID), hex"05", _controlMessage("fuel:9889", abi.encodePacked(SERVICE)));
        vm.expectRevert(FuelVerifier.ManifestProofUnsupported.selector);
        verifier.verifyConfig(cfg, CHANNEL_ID, hex"01");
    }

    function test_revert_config_namespace() public {
        bytes memory cfg =
            abi.encode(_anchor(CHANNEL_ID), hex"05", _controlMessage("eip155:1", abi.encodePacked(SERVICE)));
        vm.expectRevert(ClprQueueRecordVerifier.WrongChainNamespace.selector);
        verifier.verifyConfig(cfg, CHANNEL_ID, "");
    }

    // ── FuelBlockProof ───────────────────────────────────────────────────────

    function _root(bytes32[] memory leaves, uint256 from, uint256 n) internal pure returns (bytes32) {
        if (n == 1) return FuelBlockProof.leafDigest(leaves[from]);
        uint256 k = 1;
        while (k * 2 < n) k *= 2;
        return FuelBlockProof.nodeDigest(_root(leaves, from, k), _root(leaves, from + k, n - k));
    }

    function _path(bytes32[] memory leaves, uint256 from, uint256 n, uint256 idx, bytes32[] memory acc, uint256 depth)
        internal
        pure
        returns (uint256)
    {
        if (n == 1) return depth;
        uint256 k = 1;
        while (k * 2 < n) k *= 2;
        uint256 d;
        if (idx < k) {
            d = _path(leaves, from, k, idx, acc, depth);
            acc[d] = _root(leaves, from + k, n - k);
        } else {
            d = _path(leaves, from + k, n - k, idx - k, acc, depth);
            acc[d] = _root(leaves, from, k);
        }
        return d + 1;
    }

    function test_binaryMerkle_everyIndexOfOddTrees() public pure {
        for (uint256 n = 1; n <= 9; n++) {
            bytes32[] memory leaves = new bytes32[](n);
            for (uint256 i; i < n; ++i) {
                leaves[i] = keccak256(abi.encode(n, i));
            }
            bytes32 root = _root(leaves, 0, n);
            for (uint256 i; i < n; ++i) {
                bytes32[] memory acc = new bytes32[](8);
                uint256 len = _path(leaves, 0, n, i, acc, 0);
                bytes32[] memory proof = new bytes32[](len);
                for (uint256 j; j < len; ++j) {
                    proof[j] = acc[j];
                }
                assertTrue(FuelBlockProof.verifyInclusion(root, leaves[i], i, n, proof));
                if (n > 1) assertFalse(FuelBlockProof.verifyInclusion(root, leaves[(i + 1) % n], i, n, proof));
            }
        }
    }
}
