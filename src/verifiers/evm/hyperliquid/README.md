# Hyperliquid HyperEVM verifier (`HyperEvmVerifier`)

HyperEVM (chain 999) → Hiero `IClprVerifier`. This is the release-today design from
`~/clpr/hard4-release.md`.

> **Trust: ATTESTOR-TRUSTED.** HyperEVM finality is not proven. A K-of-N set of CLPR attestors
> signs `(chainId, blockNumber, blockHash)`, and the verifier trusts any block that K of them sign.
> If K attestors collude, they can forge any queue state. Everything from the block hash down is
> proven: header → receiptsRoot → receipt → log.

| File | Role |
|---|---|
| `HyperEvmVerifier.sol` | `IClprVerifier`: the attestor set and its rotation, the attested block, the receipt proof and the beacon record. |
| `ClprHyperEvmBeacon.sol` | Deployed on HyperEVM next to the ClprService. `publish(channelId)` reads the channel, configuration and manifest, and emits them as a `ClprQueueRecord` event. |
| `../../../libraries/proof/attestor/ClprAttestorQuorum.sol` | K-of-N secp256k1 set: `keccak256(abi.encode(threshold, attestors))`, ascending signers, low-s only. |
| `../../../libraries/proof/evm/ClprReceiptProof.sol` | Receipts-trie inclusion (key `RLP(txIndex)`), typed receipts, status 1, log extraction. |
| `../../../libraries/codec/ClprQueueRecord.sol` | The 190-byte queue record, shared with the Mixin design. |

## Why this design (live probes, 2026-10-01)

- **No state proofs.** HyperEVM headers carry `stateRoot = 0x0`, re-checked on block 47,353,393, and
  `eth_getProof` is not served. ClprService storage cannot be proven the way
  `ClprEvmBundleVerifier` does it.
- **Receipts are committed.** The block hash is keccak256 of a standard Cancun RLP header (20
  fields; no `requestsHash`). Its `receiptsRoot` matches the trie rebuilt from
  `eth_getBlockReceipts` for every receipt in the block. The refresh script checks both on every
  capture.
- **Nothing Hyperliquid signs covers HyperEVM.** Bridge2 validators sign bridge actions only. Hence
  the attestors.

The queue state therefore travels as an event. `ClprHyperEvmBeacon.publish` reads the live service
state in the same transaction (`getChannel`, `getEndpointManifest`, `getLedgerConfiguration`) and
emits `ClprQueueRecord(address indexed service, bytes32 indexed channelId, bytes record)`. HyperEVM
execution is what makes the record match the service's storage. The attestors only vouch for the
block.

## Proofs

Bundle (RLP):
```
[0] attestor set [threshold, [attestor...]]   hashes to the anchor's setHash
[1] rotations [[newSet, [sig...]], ...]        epoch e+1 signed by the epoch-e set
[2] block header (RLP)                         number = header[8], receiptsRoot = header[5]
[3] [sig...] over keccak256(abi.encode(BLOCK_DOMAIN, 999, number, blockHash))
[4] [transactionIndex, [trie node...]]         receipt must have status 1
[5] log index                                   emitter = pinned beacon; topics = (event, service, channel)
[6] ClprBundleContent                           messages, bound by the record's sentRunningHash
[7] optional endpoint manifest preimage         bound by the record's manifestCommitment
```

Trust anchor: `abi.encode(bytes32 setHash, uint256 epoch, uint256 minBlock, address beacon)`.
A rotation returns a new anchor (the new set, `epoch + 1`, `minBlock` = this block), so blocks from
before the handover cannot be replayed under it. Replaying an old rotation fails, because each
rotation signs its epoch. Sets must have `threshold > N/2`.

Config: `[set, header, attestation, receipt, logIndex, controlMessage, beacon]`. The record (channel
0 or this channel) must commit to the control message, and the event must name the service that
LedgerConfiguration declares.

## Live results

`npm run test:e2e:hyperevm-live` uses HyperEVM mainnet block 47,353,393. The header is re-encoded,
the receipts trie is rebuilt from all 7 receipts, and the real log of tx 2 is proven. **The
attestation uses test attestor keys**, because no attestor set exists yet.

| Case | Gas | Calldata |
|---|---|---|
| block + receipt + log, 3-of-5 | 433k | 2.4 KB |
| block + receipt + log, 13-of-19 | 556k | 3.3 KB |
| + one attestor-set rotation (13-of-19 → 13-of-19) | 735k | 4.6 KB |
| synthetic full `verifyBundle`, 3-of-5, 2 messages (unit test, no base cost) | 303k | — |

There is no beacon on HyperEVM yet, so the real log is not a `ClprQueueRecord`. `verifyBundle` runs
the same steps on it and stops at the event check. The live harness returns the log that was
proven. The whole record path is covered by the synthetic and compliance tests.

## Limits and follow-up

- Hyperliquid itself attests nothing. The upgrade path is to ask Hyperliquid Labs for
  validator-signed HyperEVM block hashes (Bridge2-style), or a real state root. The Bridge2 hot
  validator set is provable from Arbitrum storage with the Arbitrum verifier, which would make the
  trust validator-based (>2/3).
- Someone must call `publish` for each bundle; any relay can.
- HyperEVM has no EIP-2537 precompiles (probed). This does not matter here: attestors use secp256k1.
