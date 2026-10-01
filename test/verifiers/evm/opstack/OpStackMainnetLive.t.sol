// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {OpStackVerifier} from "@hiero-ledger/clpr/verifiers/evm/opstack/OpStackVerifier.sol";
import {OpStackProposedVerifier} from "@hiero-ledger/clpr/verifiers/evm/opstack/OpStackProposedVerifier.sol";
import {RiseProfile} from "@hiero-ledger/clpr/verifiers/evm/opstack/profiles/RiseProfile.sol";
import {RoninProfile} from "@hiero-ledger/clpr/verifiers/evm/opstack/profiles/RoninProfile.sol";
import {EthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthL1StateVerifier.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {OpStackOutputRootProof as OP} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";

/// @notice A deployment profile against REAL Ethereum-mainnet data: the mainnet sync committee's signature,
///         the chain's AnchorStateRegistry / DisputeGameFactory / dispute games at the attested L1 block, and
///         the L2 headers the games claim. Inputs: `fixtures/<chain>-live.json`, written by
///         `npx tsx test/e2e/relay/buildOpStackLiveProof.ts --chain <chain> --refresh`. The verifiers are
///         deployed from the PINNED profile library, never from captured values.
abstract contract OpStackMainnetLiveBase is Test {
    string internal json;
    EthL1StateVerifier internal l1;
    OpStackVerifier internal finalized;
    OpStackProposedVerifier internal proposed;
    bytes internal anchor;
    uint64 internal genesisTime;
    uint256 internal l1Time;

    function _fixtureName() internal pure virtual returns (string memory);
    function _profile() internal pure virtual returns (OP.Profile memory);
    function _gameType() internal pure virtual returns (uint32);

    function setUp() public {
        json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/verifiers/evm/opstack/fixtures/", _fixtureName(), "-live.json")
        );
        l1 = new EthL1StateVerifier(
            ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY,
            9,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE,
            6,
            8192
        );
        genesisTime = uint64(vm.parseJsonUint(json, ".l1GenesisTime"));
        l1Time = vm.parseJsonUint(json, ".l1Time");
        finalized = new OpStackVerifier(l1, genesisTime, 12, _profile());
        proposed = new OpStackProposedVerifier(l1, genesisTime, 12, _profile());
        anchor = vm.parseJsonBytes(json, ".trustAnchor");
    }

    function _has(string memory key) internal view returns (bool) {
        return
            vm.keyExistsJson(json, string.concat(".", key)) && vm.keyExistsJson(json, string.concat(".", key, ".proof"));
    }

    function _proof(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, string.concat(".", key, ".proof"));
    }

    function _root(string memory key) internal view returns (bytes32) {
        return vm.parseJsonBytes32(json, string.concat(".", key, ".l2StateRoot"));
    }

    function _uint(string memory key, string memory field) internal view returns (uint256) {
        return vm.parseJsonUint(json, string.concat(".", key, ".", field));
    }

    /// @dev Intrinsic gas of a Hedera/EVM transaction calling `verifyL2StateRoot(proof, anchor)`.
    function _intrinsicGas(bytes memory proof) internal view returns (uint256 gas, uint256 size) {
        bytes memory data = abi.encodeCall(finalized.verifyL2StateRoot, (proof, anchor));
        gas = 21_000;
        for (uint256 i; i < data.length; ++i) {
            gas += data[i] == 0 ? 4 : 16;
        }
        size = data.length;
    }

    /// @dev Verifies `key` on `v` and logs `21000 + calldata + execution` gas and the calldata size.
    function _verifyAndLog(OpStackVerifier v, string memory key, string memory label) internal view {
        bytes memory proof = _proof(key);
        uint256 g = gasleft();
        (bytes32 root,,) = v.verifyL2StateRoot(proof, anchor);
        g -= gasleft();
        assertEq(root, _root(key));
        (uint256 intrinsic, uint256 size) = _intrinsicGas(proof);
        console.log(string.concat(_fixtureName(), " ", label, ": gas ~"), intrinsic + g, "calldata B", size);
    }

    function test_profileMatchesLiveChain() public view {
        OP.Profile memory p = _profile();
        assertEq(uint8(p.rootFormat), vm.parseJsonUint(json, ".profile.rootFormat"), "rootFormat");
        assertEq(p.l2ChainId, vm.parseJsonUint(json, ".profile.l2ChainId"), "l2ChainId");
        assertEq(p.anchorStateRegistry, vm.parseJsonAddress(json, ".profile.anchorStateRegistry"), "ASR");
        assertEq(
            p.anchorStateRegistryImplCodeHash,
            vm.parseJsonBytes32(json, ".profile.anchorStateRegistryImplCodeHash"),
            "ASR impl code hash"
        );
        assertEq(
            p.disputeGameFinalityDelaySeconds,
            vm.parseJsonUint(json, ".profile.disputeGameFinalityDelaySeconds"),
            "finality delay"
        );
        assertEq(p.gameImplementation, vm.parseJsonAddress(json, ".profile.gameImplementation"), "game impl");
        assertEq(p.gameArgsHash, vm.parseJsonBytes32(json, ".profile.gameArgsHash"), "game args");
        assertEq(uint256(_gameType()), vm.parseJsonUint(json, ".profile.respectedGameType"), "game type");
        assertEq(uint8(finalized.FINALITY()), 0);
        assertEq(uint8(proposed.FINALITY()), 1);
    }

    /// FINALIZED, ANCHOR mode: the ASR anchor root (anchor game, or starting anchor root).
    function test_finalized_anchorMode() public {
        _verifyAndLog(finalized, "anchorMode", "FINALIZED ANCHOR");
    }

    /// FINALIZED, GAME mode: the newest game final at the proven L1 time (else the anchor game).
    function test_finalized_gameMode() public {
        string memory key = _has("finalized") ? "finalized" : "anchorGame";
        vm.skip(!_has(key));
        assertEq(_uint(key, "status"), 2);
        assertGt(l1Time - _uint(key, "resolvedAt"), _profile().disputeGameFinalityDelaySeconds);
        _verifyAndLog(finalized, key, "FINALIZED GAME");
    }

    /// The newest resolved game: FINALIZED accepts it only once past the delay; PROPOSED always does.
    function test_resolvedGame() public {
        vm.skip(!_has("resolved"));
        bytes memory proof = _proof("resolved");
        uint256 resolvedAt = _uint("resolved", "resolvedAt");
        if (l1Time - resolvedAt <= _profile().disputeGameFinalityDelaySeconds) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    OP.GameNotFinalized.selector,
                    vm.parseJsonAddress(json, ".resolved.game"),
                    uint64(resolvedAt),
                    uint64(l1Time),
                    _profile().disputeGameFinalityDelaySeconds
                )
            );
            finalized.verifyL2StateRoot(proof, anchor);
        } else {
            (bytes32 r,,) = finalized.verifyL2StateRoot(proof, anchor);
            assertEq(r, _root("resolved"));
        }
        (bytes32 root,,) = proposed.verifyL2StateRoot(proof, anchor);
        assertEq(root, _root("resolved"));
    }

    /// The newest game (IN_PROGRESS): FINALIZED rejects it, PROPOSED accepts it.
    function test_newestGame_proposedOnly() public {
        bytes memory proof = _proof("newest");
        if (_uint("newest", "status") == 0) {
            vm.expectRevert(
                abi.encodeWithSelector(OP.GameNotResolved.selector, vm.parseJsonAddress(json, ".newest.game"), uint8(0))
            );
            finalized.verifyL2StateRoot(proof, anchor);
        }
        bytes memory p = _proof("newest");
        uint256 g = gasleft();
        (bytes32 root,,) = proposed.verifyL2StateRoot(p, anchor);
        g -= gasleft();
        assertEq(root, _root("newest"));
        (uint256 intrinsic, uint256 size) = _intrinsicGas(p);
        console.log(string.concat(_fixtureName(), " PROPOSED newest: gas ~"), intrinsic + g, "calldata B", size);
    }

    /// A profile pinning other game args (DGF 1.6: another prestate, proposer or challenger; DGF < 1.6: any
    /// args at all) rejects the same live game.
    function test_rejectsOtherGameArgs() public {
        OP.Profile memory p = _profile();
        p.gameArgsHash = p.gameArgsHash == bytes32(0) ? keccak256("other") : bytes32(0);
        OpStackProposedVerifier other = new OpStackProposedVerifier(l1, genesisTime, 12, p);
        vm.expectRevert(abi.encodeWithSelector(OP.GameArgsMismatch.selector, vm.parseJsonAddress(json, ".newest.game")));
        other.verifyL2StateRoot(_proof("newest"), anchor);
    }

    /// A profile pinning another game implementation rejects the same live game.
    function test_rejectsOtherGameImplementation() public {
        OP.Profile memory p = _profile();
        p.gameImplementation = address(0xdEaD);
        OpStackProposedVerifier other = new OpStackProposedVerifier(l1, genesisTime, 12, p);
        vm.expectRevert(
            abi.encodeWithSelector(OP.GameImplementationMismatch.selector, vm.parseJsonAddress(json, ".newest.game"))
        );
        other.verifyL2StateRoot(_proof("newest"), anchor);
    }

    /// A profile pinning another ASR implementation code hash rejects every proof.
    function test_rejectsOtherAsrImplementation() public {
        OP.Profile memory p = _profile();
        p.anchorStateRegistryImplCodeHash = keccak256("other");
        OpStackVerifier other = new OpStackVerifier(l1, genesisTime, 12, p);
        vm.expectRevert();
        other.verifyL2StateRoot(_proof("anchorMode"), anchor);
    }

    /// The real signature no longer verifies under another fork version.
    function test_rejectsTamperedSignature() public {
        bytes memory bad = bytes.concat(anchor);
        bad[32] = 0x05; // Electra fork version
        vm.expectRevert();
        finalized.verifyL2StateRoot(_proof("anchorMode"), bad);
    }
}

contract OpStackRiseLiveTest is OpStackMainnetLiveBase {
    function _fixtureName() internal pure override returns (string memory) {
        return "rise";
    }

    function _profile() internal pure override returns (OP.Profile memory) {
        return RiseProfile.profile();
    }

    function _gameType() internal pure override returns (uint32) {
        return RiseProfile.GAME_TYPE;
    }
}

contract OpStackRoninLiveTest is OpStackMainnetLiveBase {
    function _fixtureName() internal pure override returns (string memory) {
        return "ronin";
    }

    function _profile() internal pure override returns (OP.Profile memory) {
        return RoninProfile.profile();
    }

    function _gameType() internal pure override returns (uint32) {
        return RoninProfile.GAME_TYPE;
    }
}
