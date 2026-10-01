// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Runtimes3TestBase} from "./Runtimes3TestBase.sol";
import {MockCometBftHeaderSource} from "./MockCometBftHeaderSource.sol";
import {InitiaMoveVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/InitiaMoveVerifier.sol";
import {ClprQueueRecordVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/ClprQueueRecordVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ICometBftHeaderSource} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/ICometBftHeaderSource.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev InitiaMoveVerifier against synthetic IAVL / multistore proofs and a mock header source
///      (finality itself is the CometBFT family's accumulator, PR #6; see MockCometBftHeaderSource).
contract InitiaMoveVerifierTest is Runtimes3TestBase {
    MockCometBftHeaderSource internal source;
    InitiaMoveVerifier internal verifier;

    bytes32 internal constant SET_A = keccak256("validator set A");
    bytes32 internal constant SET_B = keccak256("validator set B");
    bytes32 internal constant SERVICE = bytes32(uint256(0xc1a9));
    bytes32 internal constant HANDLE = keccak256("channels table handle");
    uint64 internal constant ANCHOR_HEIGHT = 1000;

    function setUp() public {
        source = new MockCometBftHeaderSource();
        verifier = new InitiaMoveVerifier(source, SET_A, ANCHOR_HEIGHT);
    }

    // ── Builders ─────────────────────────────────────────────────────────────

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE)})
        );
    }

    function _anchor(bytes32 setHash, uint64 height) internal pure returns (bytes memory) {
        return abi.encodePacked(setHash, height, HANDLE);
    }

    function _headerRef(bytes32 headerHash) internal pure returns (bytes memory) {
        return PB.encodeBytesField(3, abi.encodePacked(headerHash));
    }

    function _register(bytes32 headerHash, bytes32 setHash, bytes32 nextSet, bytes32 appHash, uint64 height) internal {
        source.setFinalized(
            headerHash,
            ICometBftHeaderSource.Header({
                validatorsHash: setHash, nextValidatorsHash: nextSet, appHash: appHash, height: height
            })
        );
    }

    struct Built {
        bytes multistore;
        bytes entry;
        bytes32 appHash;
    }

    function _proofs(bytes memory key, bytes memory value) internal pure returns (Built memory b) {
        Ics23Proof memory iavl = _iavlProof(key, value, keccak256("right sibling"));
        Ics23Proof memory ms = _multistoreProof("move", iavl.root, keccak256("acc store"));
        b.multistore = ms.encoded;
        b.entry = iavl.encoded;
        b.appHash = ms.root;
    }

    function _bundle(
        bytes[] memory hops,
        bytes32 headerHash,
        Built memory b,
        bytes memory record,
        bytes memory manifest
    ) internal pure returns (bytes memory) {
        bytes[] memory hopItems = new bytes[](hops.length);
        for (uint256 i; i < hops.length; ++i) {
            hopItems[i] = RLP.encode(hops[i]);
        }
        bytes[] memory items = new bytes[](manifest.length == 0 ? 6 : 7);
        items[0] = RLP.encode(hopItems);
        items[1] = RLP.encode(_headerRef(headerHash));
        items[2] = RLP.encode(b.multistore);
        items[3] = RLP.encode(b.entry);
        items[4] = RLP.encode(record);
        items[5] = RLP.encode(_bundleContent());
        if (manifest.length != 0) items[6] = RLP.encode(manifest);
        return RLP.encode(items);
    }

    function _recordKey() internal view returns (bytes memory) {
        return verifier.tableEntryKey(HANDLE, abi.encodePacked(CHANNEL_ID));
    }

    function _simpleBundle(bytes memory record, bytes32 nextSet) internal returns (bytes memory) {
        Built memory b = _proofs(_recordKey(), record);
        bytes32 hh = keccak256("header 1200");
        _register(hh, SET_A, nextSet, b.appHash, 1200);
        return _bundle(new bytes[](0), hh, b, record, "");
    }

    // ── Happy paths ──────────────────────────────────────────────────────────

    function test_verifyBundle_provesQueueRecord() public {
        bytes memory proof = _simpleBundle(_defaultRecord(), SET_A);
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory newAnchor,
            bytes memory newId,
            ClprTypes.ClprEndpointManifest memory man
        ) = verifier.verifyBundle(proof, _anchor(SET_A, ANCHOR_HEIGHT), _ctx());
        _assertDefaultMetadata(m);
        assertEq(payloads.length, 2);
        assertEq(payloads[0], hex"0a03010203");
        assertEq(newAnchor.length, 0);
        assertEq(newId.length, 0);
        assertEq(man.version, 0);
    }

    function test_verifyBundle_rotationReturnsNextSet() public {
        bytes memory proof = _simpleBundle(_defaultRecord(), SET_B);
        (,, bytes memory newAnchor, bytes memory newId,) =
            verifier.verifyBundle(proof, _anchor(SET_A, ANCHOR_HEIGHT), _ctx());
        assertEq(newAnchor, abi.encodePacked(SET_B, uint64(1201), HANDLE));
        assertEq(newId, abi.encodePacked(SET_B, uint64(1201)));
    }

    function test_verifyBundle_throughHop() public {
        bytes32 hop = keccak256("hop 1100");
        _register(hop, SET_A, SET_B, bytes32(uint256(1)), 1100);
        Built memory b = _proofs(_recordKey(), _defaultRecord());
        bytes32 hh = keccak256("header 1300");
        _register(hh, SET_B, SET_B, b.appHash, 1300);
        bytes[] memory hops = new bytes[](1);
        hops[0] = _headerRef(hop);
        (ClprTypes.QueueMetadata memory m,, bytes memory newAnchor,,) =
            verifier.verifyBundle(_bundle(hops, hh, b, _defaultRecord(), ""), _anchor(SET_A, ANCHOR_HEIGHT), _ctx());
        _assertDefaultMetadata(m);
        assertEq(newAnchor, abi.encodePacked(SET_B, uint64(1301), HANDLE));
    }

    function test_verifyBundle_withManifest() public {
        bytes memory manifest = _manifest(abi.encodePacked(SERVICE));
        bytes memory record = _record(1, 7, 3, 2, keccak256(manifest));
        Built memory b = _proofs(_recordKey(), record);
        bytes32 hh = keccak256("header m");
        _register(hh, SET_A, SET_A, b.appHash, 1200);
        (,,,, ClprTypes.ClprEndpointManifest memory man) = verifier.verifyBundle(
            _bundle(new bytes[](0), hh, b, record, manifest), _anchor(SET_A, ANCHOR_HEIGHT), _ctx()
        );
        assertEq(man.version, 3);
        assertEq(man.endpoints.length, 1);
    }

    // ── Negative cases ───────────────────────────────────────────────────────

    function test_revert_wrongValidatorSet() public {
        bytes memory proof = _simpleBundle(_defaultRecord(), SET_A);
        vm.expectRevert(InitiaMoveVerifier.ValidatorSetHashMismatch.selector);
        verifier.verifyBundle(proof, _anchor(SET_B, ANCHOR_HEIGHT), _ctx());
    }

    function test_revert_staleHeader() public {
        bytes memory proof = _simpleBundle(_defaultRecord(), SET_A);
        vm.expectRevert(InitiaMoveVerifier.HeightTooOld.selector);
        verifier.verifyBundle(proof, _anchor(SET_A, 1201), _ctx());
    }

    function test_revert_unfinalizedHeader() public {
        Built memory b = _proofs(_recordKey(), _defaultRecord());
        bytes memory proof = _bundle(new bytes[](0), keccak256("never accumulated"), b, _defaultRecord(), "");
        vm.expectRevert(MockCometBftHeaderSource.NotFinalized.selector);
        verifier.verifyBundle(proof, _anchor(SET_A, ANCHOR_HEIGHT), _ctx());
    }

    function test_revert_tamperedRecord() public {
        bytes memory proof = _simpleBundle(_defaultRecord(), SET_A);
        // Same proofs, record claims a later next_message_id.
        Built memory b = _proofs(_recordKey(), _defaultRecord());
        bytes memory forged = _bundle(new bytes[](0), keccak256("header 1200"), b, _record(1, 8, 3, 2, bytes32(0)), "");
        verifier.verifyBundle(proof, _anchor(SET_A, ANCHOR_HEIGHT), _ctx());
        vm.expectRevert(InitiaMoveVerifier.StorageValueMismatch.selector);
        verifier.verifyBundle(forged, _anchor(SET_A, ANCHOR_HEIGHT), _ctx());
    }

    function test_revert_otherChannelRecord() public {
        bytes memory otherKey = verifier.tableEntryKey(HANDLE, abi.encodePacked(keccak256("other channel")));
        Built memory b = _proofs(otherKey, _defaultRecord());
        bytes32 hh = keccak256("header x");
        _register(hh, SET_A, SET_A, b.appHash, 1200);
        vm.expectRevert(InitiaMoveVerifier.StorageKeyMismatch.selector);
        verifier.verifyBundle(
            _bundle(new bytes[](0), hh, b, _defaultRecord(), ""), _anchor(SET_A, ANCHOR_HEIGHT), _ctx()
        );
    }

    function test_revert_wrongTableHandle() public {
        bytes memory proof = _simpleBundle(_defaultRecord(), SET_A);
        vm.expectRevert(InitiaMoveVerifier.StorageKeyMismatch.selector);
        verifier.verifyBundle(proof, abi.encodePacked(SET_A, ANCHOR_HEIGHT, keccak256("other table")), _ctx());
    }

    function test_revert_wrongStore() public {
        Ics23Proof memory iavl = _iavlProof(_recordKey(), _defaultRecord(), keccak256("right sibling"));
        Ics23Proof memory ms = _multistoreProof("evm", iavl.root, keccak256("acc store"));
        bytes32 hh = keccak256("header evm");
        _register(hh, SET_A, SET_A, ms.root, 1200);
        Built memory b = Built({multistore: ms.encoded, entry: iavl.encoded, appHash: ms.root});
        vm.expectRevert(InitiaMoveVerifier.InvalidStoreKey.selector);
        verifier.verifyBundle(
            _bundle(new bytes[](0), hh, b, _defaultRecord(), ""), _anchor(SET_A, ANCHOR_HEIGHT), _ctx()
        );
    }

    function test_revert_appHashMismatch() public {
        Built memory b = _proofs(_recordKey(), _defaultRecord());
        bytes32 hh = keccak256("header bad app");
        _register(hh, SET_A, SET_A, keccak256("another app hash"), 1200);
        vm.expectRevert(Ics23Lib.RootMismatch.selector);
        verifier.verifyBundle(
            _bundle(new bytes[](0), hh, b, _defaultRecord(), ""), _anchor(SET_A, ANCHOR_HEIGHT), _ctx()
        );
    }

    function test_revert_badRecordStatus() public {
        bytes memory record = _record(9, 7, 3, 2, bytes32(0));
        bytes memory proof = _simpleBundle(record, SET_A);
        vm.expectRevert(ClprQueueRecordVerifier.InvalidQueueRecord.selector);
        verifier.verifyBundle(proof, _anchor(SET_A, ANCHOR_HEIGHT), _ctx());
    }

    function test_revert_manifestMismatch() public {
        bytes memory manifest = _manifest(abi.encodePacked(SERVICE));
        bytes memory record = _record(1, 7, 3, 2, keccak256("something else"));
        Built memory b = _proofs(_recordKey(), record);
        bytes32 hh = keccak256("header mm");
        _register(hh, SET_A, SET_A, b.appHash, 1200);
        vm.expectRevert(ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector);
        verifier.verifyBundle(_bundle(new bytes[](0), hh, b, record, manifest), _anchor(SET_A, ANCHOR_HEIGHT), _ctx());
    }

    function test_revert_badAnchorLength() public {
        bytes memory proof = _simpleBundle(_defaultRecord(), SET_A);
        vm.expectRevert(InitiaMoveVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(proof, abi.encodePacked(SET_A, ANCHOR_HEIGHT), _ctx());
    }

    // ── verifyConfig ─────────────────────────────────────────────────────────

    function _config(string memory chainId, bytes memory resource) internal returns (bytes memory) {
        bytes memory key = verifier.resourceKey(SERVICE, "clpr", "Service");
        Built memory b = _proofs(key, resource);
        bytes32 hh = keccak256("config header");
        _register(hh, SET_A, SET_A, b.appHash, 1500);
        bytes[] memory items = new bytes[](6);
        items[0] = RLP.encode(_controlMessage(chainId, abi.encodePacked(SERVICE)));
        items[1] = RLP.encode(new bytes[](0));
        items[2] = RLP.encode(_headerRef(hh));
        items[3] = RLP.encode(b.multistore);
        items[4] = RLP.encode(b.entry);
        items[5] = RLP.encode(resource);
        return RLP.encode(items);
    }

    function test_verifyConfig_pinsTableHandle() public {
        bytes memory manifest = _manifest(abi.encodePacked(SERVICE));
        bytes memory resource = abi.encodePacked(HANDLE, _le64(4), uint8(32), keccak256(manifest), hex"0102");
        (
            bytes memory ctx,
            string memory chainId,
            bytes memory service,,,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory man
        ) = verifier.verifyConfig(_config("cosmos:interwoven-1", resource), CHANNEL_ID, manifest);
        assertEq(chainId, "cosmos:interwoven-1");
        assertEq(service, abi.encodePacked(SERVICE));
        assertEq(ctx, _ctx());
        assertEq(anchor, abi.encodePacked(SET_A, uint64(1501), HANDLE));
        assertEq(anchorId, abi.encodePacked(SET_A, uint64(1501)));
        assertEq(man.version, 3);
    }

    function test_verifyConfig_bringUpWithoutManifest() public {
        bytes memory resource = abi.encodePacked(HANDLE, _le64(0), uint8(0));
        (,,,,,,, ClprTypes.ClprEndpointManifest memory man) =
            verifier.verifyConfig(_config("cosmos:interwoven-1", resource), CHANNEL_ID, "");
        assertEq(man.version, 0);
        assertEq(man.serviceAddress, abi.encodePacked(SERVICE));
    }

    function test_revert_config_wrongNamespace() public {
        bytes memory resource = abi.encodePacked(HANDLE, _le64(0), uint8(0));
        bytes memory cfg = _config("eip155:1", resource);
        vm.expectRevert(ClprQueueRecordVerifier.WrongChainNamespace.selector);
        verifier.verifyConfig(cfg, CHANNEL_ID, "");
    }

    function test_revert_config_badResource() public {
        bytes memory cfg = _config("cosmos:interwoven-1", abi.encodePacked(HANDLE, _le64(0)));
        vm.expectRevert(InitiaMoveVerifier.InvalidServiceResource.selector);
        verifier.verifyConfig(cfg, CHANNEL_ID, "");
    }

    // ── Key derivation (initia x/move/types/keys.go) ─────────────────────────

    function test_resourceKey_matchesInitiaLayout() public view {
        // 0x21 ‖ 0x1 ‖ 0x02 ‖ BCS(StructTag{0x1, "dex", "ModuleStore", []}) — the key the live fixture proves.
        assertEq(
            verifier.resourceKey(bytes32(uint256(1)), "dex", "ModuleStore"),
            hex"210000000000000000000000000000000000000000000000000000000000000001020000000000000000000000000000000000000000000000000000000000000001036465780b4d6f64756c6553746f726500"
        );
    }
}
