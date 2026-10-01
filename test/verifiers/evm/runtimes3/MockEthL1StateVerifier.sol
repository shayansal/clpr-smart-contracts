// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";

/// @title MockEthL1StateVerifier
/// @notice TEST ONLY. Returns a state root and beacon slot the test sets; checks nothing. The real
///         {EthL1StateVerifier} runs in the live replay spec (test/e2e/tests/verifiers/fuel-live.spec.ts).
contract MockEthL1StateVerifier is IEthL1StateVerifier {
    bytes32 public stateRoot;
    uint64 public slot;
    bytes public rotation;

    function set(bytes32 stateRoot_, uint64 slot_, bytes calldata rotation_) external {
        stateRoot = stateRoot_;
        slot = slot_;
        rotation = rotation_;
    }

    function verifyL1State(bytes calldata, bytes calldata)
        external
        view
        returns (bytes32, uint64, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        if (rotation.length != 0) {
            newTrustAnchor = rotation;
            newTrustAnchorId = abi.encodePacked(uint64(7));
        }
        return (stateRoot, slot, newTrustAnchor, newTrustAnchorId);
    }

    /// @dev `configProof` = abi.encode(trustAnchor, trustAnchorId, ledgerConfiguration).
    function genesisTrustAnchor(bytes calldata configProof, bytes32)
        external
        pure
        returns (bytes memory trustAnchor, bytes memory trustAnchorId, bytes memory ledgerConfiguration)
    {
        return abi.decode(configProof, (bytes, bytes, bytes));
    }
}
