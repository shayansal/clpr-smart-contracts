// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {BscParliaVerifier} from "@hiero-ledger/clpr/verifiers/evm/bsc/BscParliaVerifier.sol";
import {ClprParlia} from "@hiero-ledger/clpr/libraries/proof/parlia/ClprParlia.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @dev BscParliaVerifier on REAL chain data: BSC testnet (Chapel, 9 validators) and BSC mainnet
///      (21 validators), recorded by `npm run bsc-live:refresh` into test/e2e/fixtures/bsc-live/.
///      Each vector set covers verifyConfig on a real epoch block, a real epoch rotation (the next
///      epoch block finalized by the outgoing set's BLS attestation, with a changed validator set) and
///      a real finalized state header with its account/storage MPT proofs.
contract BscParliaLiveTest is Test {
    BscParliaVerifier internal verifier;

    struct Vectors {
        bytes configProof;
        bytes trustAnchor;
        bytes rotatedAnchor;
        bytes proofBytes;
        bytes proofBytesNoRotation;
        bytes channelContext;
        bytes32 channelId;
        uint64 rotationEpoch;
    }

    function setUp() public {
        verifier = new BscParliaVerifier();
    }

    function _load(string memory network) internal view returns (Vectors memory v) {
        string memory json = vm.readFile(string.concat("test/e2e/fixtures/bsc-live/", network, "-vectors.json"));
        v.configProof = vm.parseJsonBytes(json, ".configProof");
        v.trustAnchor = vm.parseJsonBytes(json, ".trustAnchor");
        v.rotatedAnchor = vm.parseJsonBytes(json, ".rotatedAnchor");
        v.proofBytes = vm.parseJsonBytes(json, ".proofBytes");
        v.proofBytesNoRotation = vm.parseJsonBytes(json, ".proofBytesNoRotation");
        v.channelContext = vm.parseJsonBytes(json, ".channelContext");
        v.channelId = vm.parseJsonBytes32(json, ".channelId");
        v.rotationEpoch = uint64(vm.parseJsonUint(json, ".rotationEpoch"));
    }

    function _checkNetwork(string memory network, string memory caip2) internal {
        Vectors memory v = _load(network);

        // verifyConfig on the real anchor epoch block reproduces the expected anchor.
        (bytes memory ctx, string memory chainId,,,, bytes memory anchor,,) =
            verifier.verifyConfig(v.configProof, v.channelId, "");
        assertEq(chainId, caip2);
        assertEq(anchor, v.trustAnchor, "verifyConfig anchor");
        assertEq(ctx, v.channelContext, "channel context");

        // Rotation + finalized state.
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m, bytes[] memory msgs, bytes memory newAnchor, bytes memory newId,) =
            verifier.verifyBundle(v.proofBytes, v.trustAnchor, v.channelContext);
        uint256 rotGas = g - gasleft();
        assertEq(newAnchor, v.rotatedAnchor, "rotated anchor");
        assertEq(newId, abi.encodePacked(v.rotationEpoch));
        assertEq(m.nextMessageId, 0, "channel slots absent in the probe account");
        assertEq(msgs.length, 0);

        // Same state under the rotated anchor, no rotation.
        g = gasleft();
        (,, newAnchor,,) = verifier.verifyBundle(v.proofBytesNoRotation, v.rotatedAnchor, v.channelContext);
        uint256 plainGas = g - gasleft();
        assertEq(newAnchor.length, 0);

        console.log(string.concat("[bsc-live] ", network, " verifyBundle with 1 rotation (execution gas):"), rotGas);
        console.log(string.concat("[bsc-live] ", network, " verifyBundle without rotation (execution gas):"), plainGas);
        console.log(string.concat("[bsc-live] ", network, " proofBytes bytes (rotation / plain):"), v.proofBytes.length);
        console.log("                                                         ", v.proofBytesNoRotation.length);
    }

    function test_live_chapel() public {
        _checkNetwork("chapel", "eip155:97");
    }

    function test_live_mainnet() public {
        _checkNetwork("mainnet", "eip155:56");
    }

    // ── Negative cases on real data ───────────────────────────────────────────

    function test_live_revertWhen_anchorForOtherChainId() public {
        Vectors memory v = _load("chapel");
        bytes memory anchor = v.trustAnchor;
        anchor[135] = bytes1(uint8(56)); // chainId 97 → 56: every real seal recovers a foreign address
        vm.expectPartialRevert(ClprParlia.UnauthorizedSealer.selector);
        verifier.verifyBundle(v.proofBytes, anchor, v.channelContext);
    }

    function test_live_revertWhen_codeHashNotPinned() public {
        Vectors memory v = _load("mainnet");
        bytes memory anchor = v.rotatedAnchor;
        anchor[63] = bytes1(uint8(anchor[63]) ^ 1);
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        verifier.verifyBundle(v.proofBytesNoRotation, anchor, v.channelContext);
    }

    function test_live_revertWhen_stateBundleUnderPreviousSet() public {
        // The real state attestation is signed by the rotated-in set; the pre-rotation anchor's
        // tenure ends before it (and its keys differ).
        Vectors memory v = _load("mainnet");
        vm.expectRevert(BscParliaVerifier.ValidatorSetMismatch.selector);
        verifier.verifyBundle(v.proofBytesNoRotation, v.trustAnchor, v.channelContext);
    }

    function test_live_revertWhen_rotationReplayedOnRotatedAnchor() public {
        Vectors memory v = _load("chapel");
        vm.expectRevert(BscParliaVerifier.ValidatorSetMismatch.selector);
        verifier.verifyBundle(v.proofBytes, v.rotatedAnchor, v.channelContext);
    }
}
