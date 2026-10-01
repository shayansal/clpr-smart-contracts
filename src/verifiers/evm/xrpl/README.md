# XRP Ledger verifier (`XrplVerifier`)

XRP Ledger → Hiero `IClprVerifier`. It is a light client for XRPL consensus (UNL validations) plus
SHAMap inclusion proofs of transactions with their metadata, applied to the CLPR outbox design in
`~/clpr/xrpl-design.md` §1.

| File | Role |
|---|---|
| `XrplLib.sol` | rippled binary formats: the STObject field walker, ledger header hashing, STValidation signing digests, DER signatures, secp256k1 key → address, SHAMap path checks, tx+meta and state leaf hashes, the LedgerHashes skip list and manifests. |
| `XrplLightClient.sol` | Stateless. Checks the UNL quorum, ledger headers and ancestor links (parent hash or skip list), and transaction inclusion with tesSUCCESS. Also proves ledger objects (`verifyLedgerEntry`) and the config AccountRoot. |
| `XrplUnlKeys.sol` | Validator manifests (signing-key rotation), config-time UNL key conversion and state-tree proofs. Split out for EIP-170. |
| `XrplVerifier.sol` | `IClprVerifier`: the clpr/v1 outbox rules, queue metadata, the trust anchor and config. |
| `../../../libraries/crypto/ClprSha512Hasher.sol` | SHA-512 as a contract (raw calldata in, 64-byte digest out), compiled with the legacy pipeline. |

Every rule below was checked against rippled `develop` @ `ddbc5f1` (2026-09-30) and against live
mainnet and testnet data (2026-10-01).

## XRPL consensus, as rippled implements it

| Item | Rule | Source |
|---|---|---|
| Ledger hash | `sha512Half("LWR\0" ‖ seq ‖ drops ‖ parentHash ‖ txHash ‖ accountHash ‖ parentCloseTime ‖ closeTime ‖ resolution ‖ flags)`; the header is 118 bytes | `LedgerHeader.cpp` `calculateLedgerHash` |
| Validation | STValidation signed over `sha512Half("VAL\0" ‖ fields without sfSignature)`; must carry `vfFullValidation` | `STValidation.cpp`, `STObject::getSigningHash` |
| Validation keys | **secp256k1 only.** The constructor throws on any other key type ("We can only use secp256k1 keys for signing validations") | `STValidation.h` |
| ed25519 | Only for validator master keys, which sign manifests over the raw `"MAN\0" ‖ fields` bytes | `PublicKey.cpp` `verify`, `Manifest.cpp` |
| Quorum | `max(ceil(0.8 × effectiveUNL), ceil(0.6 × UNL))`. The verifier requires `ceil(0.8 × UNL)` and ignores the negative UNL, which is stricter | `ValidatorList::calculateQuorum` |
| SHAMap | inner = `sha512Half("MIN\0" ‖ 16 child hashes)`; branch d = key nibble d; tx+meta leaf = `sha512Half("SND\0" ‖ VL(tx) ‖ VL(meta) ‖ txid)`, txid = `sha512Half("TXN\0" ‖ tx)`; state leaf = `sha512Half("MLN\0" ‖ data ‖ key)` | `SHAMapInnerNode.cpp`, `SHAMapTxPlusMetaLeafNode.h`, `Ledger::rawTxInsert` |
| tesSUCCESS | sfTransactionResult (UINT8 3) has the highest field code in the metadata template and fields are sorted, so serialized metadata always ends `03 10 <result>` | `TxMeta.cpp`, `STObject::add` |
| Skip list | `keylet::skip()` = `sha512Half(0x0073)` holds the hashes of the previous 256 ledgers, newest at `sfLastLedgerSequence` | `Ledger::updateSkipList` |
| Memos | the serialized sfMemos array is at most 1024 bytes | `STTx.cpp` `isMemoOkay` |

The earlier brief said validators "sign validations with secp256k1 or ed25519". That is only half
right: rippled rejects any validation whose signing key is not secp256k1. Validator master keys are
usually ed25519, but they only sign manifests. The verifier therefore checks validations with
`ecrecover` and supports both key types for manifest master signatures.

## Design

### Bundle

`proofBytes` is an RLP list:

```
[0] UNL          [[masterKey(33), signingAddress(20), manifestSeq], ...]  must hash to the anchor
[1] manifests    [manifest, ...]                 signing-key rotations, applied first
[2] header       the validated ledger (118 bytes)
[3] validations  [[unlIndex, STValidation], ...]  strictly increasing, >= ceil(0.8 n)
[4] ancestors    [[header] | [header, [inner...], skipList] | [header, ""], ...]
[5] messages     [[ledgerRef, tx, meta, [inner(512)...]], ...]  in Sequence order
[6] runningHash  the channel's running hash before message [5][0] (untrusted, see below)
```

An ancestor is either the parent of the previous header, or a ledger listed in the validated
ledger's skip list. The skip list is proven once, by the first entry that carries it. A message
sits in the validated ledger (`ledgerRef` 0) or in ancestor `k` (`ledgerRef` k).

### The outbox rules (`xrpl-design.md` §1)

- The sender is the channel's outbox account: the top-level sfAccount (never a Signer's) must equal
  `ChannelContext.remoteServiceAddress`.
- Each message is an **AccountSet with Flags 0** and no other fields. The allowed top-level fields
  are TransactionType, Flags, Sequence (non-zero), NetworkID, LastLedgerSequence, Fee,
  SigningPubKey, TxnSignature, Account, Signers and Memos. Anything else is rejected. That includes
  TicketSequence (Tickets), tfInnerBatchTxn (Batch), Delegate, SetFlag and Domain.
- **Exactly one memo**, with MemoType `clpr/v1`, no MemoFormat, and serialized Memos of at most 1024
  bytes. MemoData is protobuf `ClprXrplMemo {bytes channel_id = 1; ChannelSyncData sync_data = 2;
  ClprMessagePayload payload = 3}`, decoded strictly: field 3 is required and no field may repeat.
- **message_id = Sequence − seq_base + 1.** Sequences in a bundle must be consecutive, and each
  memo's `sync_data.next_message_id` must equal `message_id + 1`.
- The payload is returned as the message bytes (spec §1.4, unchanged). `channel_id` must equal the
  channel's id.

The returned metadata is: `nextMessageId` = last message id + 1, `receivedMessageId` and `status`
from the last memo's `sync_data`, and `sentRunningHash` = the chain `sha256(prev ‖ sha256(payload))`
starting at field [6]. Field [6] needs no authentication. The proof already fixes every payload and
its id, and BundleLib recomputes the chain from the channel's own `receivedRunningHash` over the new
payloads. It reverts unless the result equals `sentRunningHash`, so a wrong starting hash only makes
the bundle fail. XRPL publishes no `receivedRunningHash` or endpoint-manifest version, so both are
zero, and bundles never carry a manifest.

Gaps cannot be hidden. Within a bundle, Sequences must be consecutive. Across bundles, BundleLib
rejects a bundle whose messages do not start at `receivedMessageId + 1` (`ClprReplayDetected`).

### Trust anchor and rotation

`abi.encode(bytes32 unlHash, uint256 unlCount, uint256 seqBase, uint256 minLedgerSeq)`, 128 bytes.
`unlHash = keccak256(‖ masterKey(33) ‖ signingAddress(20) ‖ manifestSeq(4))` in UNL order.

Validator signing-key rotations are proven: a manifest must be signed by the validator's master key
(ed25519 or secp256k1) and countersigned by the new key, with a higher sequence (rippled
`Manifest::verify`). The new key must be secp256k1. A bundle that applies manifests returns a new
anchor with the re-committed UNL and `minLedgerSeq` = this ledger, so ledgers validated by the
superseded keys can no longer be submitted. Replaying a manifest fails on its sequence.

UNL **membership** changes are not proven on-chain. The publisher's signed list (vl.ripple.com) is a
base64 JSON blob, which is impractical to verify on-chain. A membership change needs a channel
re-configuration. This is the same trust the operator of a rippled node places in its configured
publisher key.

### Config

`verifyConfig` proves, in a UNL-validated ledger, the outbox's AccountRoot: it must have
`lsfDisableMaster` set and no sfRegularKey, so only its signer list can send. The proof is RLP
`[UNL with compressed signing keys, header, validations, [inner...], AccountRoot, seqBase,
controlMessage, manifestCommitment]`. XRPL publishes none of `seq_base`, the LedgerConfiguration
or the endpoint manifest. The design makes them part of the channel config, so the party opening the
channel supplies them. The manifest proof is the manifest preimage, bound to that commitment.

## Trust assumptions

1. **XRPL consensus:** at least 80% of the configured UNL is honest. This matches what a rippled node
   with the same UNL accepts.
2. **The UNL and the config inputs** (seq_base, LedgerConfiguration, manifest commitment) are
   correct at channel setup.
3. **The outbox's signer list** (k-of-n, design §1) decides message content. XRPL has no contracts,
   so nothing on-ledger checks that a memo matches a real CLPR queue. The ledger proves only that the
   signer list sent it, in order, exactly once.

## Live results (anvil, `npm run test:e2e:xrpl-live`)

Gas is `eth_estimateGas` (including the 21k base and calldata). Ledger data is real; nothing is
re-signed.

| Case | Gas | Calldata |
|---|---|---|
| mainnet ledger 107352581: memo Payment tx+meta, 28 of 35 validations | 5.88M | 11.8 KB |
| mainnet: sender AccountRoot state proof (depth 7) | 6.33M | 12.7 KB |
| mainnet: + one real validator manifest rotation (ed25519 master) | 7.67M | 13.7 KB |
| testnet `verifyConfig`: outbox AccountRoot, 6 of 6 validations | 3.37M | 6.4 KB |
| testnet `verifyBundle`: the 5 clpr/v1 outbox messages, linked via the skip list | 11.22M | 21.4 KB |
| testnet `verifyBundle`: 1 message via the skip list | 6.89M | 15.2 KB |
| synthetic: 1 message, 4 of 5 validations (unit test, no base cost) | 1.03M | 1.7 KB |

All fit Hedera's limits (15M gas, 128 KB). Costs are dominated by SHA-512, about 47k gas per
128-byte block:
- a validation is about 2 blocks plus `ecrecover`, so a mainnet quorum of 28 is about 3.5M;
- a 1 KB memo transaction is about 20 blocks;
- a parent-linked ancestor is 2 blocks;
- the skip list is a ~8.2 KB leaf, about 65 blocks plus a depth-7 path, about 4.5M.

The five outbox messages had to go through the skip list because the emitter did not record
validations. Validations are only broadcast live (the `validations` stream), so a relay must capture
them when the message ledger closes. With that done, a message in the validated ledger itself costs
the quorum plus about 1M.

## Limits and notes

- **Relays must record validations live.** Older ledgers can only be reached from a current
  validated ledger, through parent links (100k gas per ledger) or the skip list (the last 256
  ledgers). Flag-ledger skip lists (`keylet::skip(seq)`) would reach further; they are not
  implemented.
- **Proof data.** No public RPC returns SHAMap inner nodes. Transaction paths are rebuilt from the
  full ledger (`ledger` with `binary`, `expand`). State paths (AccountRoot, skip list) come from the
  peer protocol (`TMGetLedger` / `liAS_NODE`), using `test/e2e/relay/xrplPeer.ts`. That client does
  the rippled handshake with a throwaway node key, and was checked against r.ripple.com and
  s.altnet.rippletest.net.
- **SHA-512.** `ClprSha512Hasher` is built with the legacy pipeline and no optimizer. Via-IR spills
  its working variables, and the legacy Yul optimizer runs out of stack on the unrolled rounds. An
  optimized build (legacy, Yul optimizer off) would roughly halve the cost again, but foundry cannot
  express that per file.
- **One outbox account per channel**, because Sequence numbers are per account.
- **Findings on the emitter fixture (`feat/xrpl-design`):**
  - It encodes `ChannelSyncData.status` with ACTIVE = 0. `clpr-service-spec` `ClprChannelStatus` has
    PENDING = 0 and ACTIVE = 1. The verifier follows the spec, so the fixture's messages read as
    PENDING.
  - Its `running_hash_after_processing` is `sha256(prev ‖ payload)`. BundleLib uses
    `sha256(prev ‖ sha256(payload))`. The verifier derives the chain itself, so this does not affect
    verification, but the emitter's recorded values are not the protocol's.

## Refresh

`npm run xrpl-live:refresh`:
1. `captureXrplLive.ts mainnet`: waits for a ledger with a memo Payment or AccountSet and a full UNL
   quorum, then records it.
2. `captureXrplLive.ts testnet --account <outbox>`: does the same and proves the outbox AccountRoot.
3. `linkXrplMessages.ts`: fetches the skip list. Run it within 256 ledgers (~15 minutes) of the
   message ledgers, or re-emit with `tools/xrpl-clpr-emitter`.
