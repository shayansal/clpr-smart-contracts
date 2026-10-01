# Stellar verifier (`StellarScpVerifier`)

Stellar → Hiero `IClprVerifier`. It is an SCP light client over a trusted quorum set (Stellar's
tier-1 organizations). Queue state is proven as a Soroban contract event, because the ledger's
state commitment cannot be opened for a single entry.

| File | Role |
|---|---|
| `StellarXdr.sol` | Strict XDR decoders: `LedgerHeader` (and `StellarValue`), `SCPStatement` (EXTERNALIZE), `SCPQuorumSet` with stellar-core's sanity rules and slice evaluation, the Soroban `TransactionResult`, and `InvokeHostFunctionSuccessPreImage`. |
| `StellarScpVerifier.sol` | `IClprVerifier`: trust anchor, SCP finality, checkpoints, header walk, event proof, quorum-set rotation. |
| `../sei/Ed25519Verifier.sol` | Pure-Solidity Ed25519, reused as an external contract. Hedera has no Ed25519 precompile. |

Every protocol rule below was checked against `stellar/stellar-core` master @ `cf8f96d` (29 Sep 2026),
`stellar/stellar-xdr` @ `ee040cd`, and live testnet and pubnet data (1 Oct 2026; pubnet protocol 28,
testnet 29).

## What a Stellar ledger commits to

| Question | Finding | Evidence |
|---|---|---|
| What does a validator sign? | One Ed25519 signature per SCP envelope over `networkID ‖ ENVELOPE_TYPE_SCP (1) ‖ XDR(SCPStatement)`, raw (not prehashed). An EXTERNALIZE statement carries the slot (= ledger sequence), the externalized `StellarValue`, and `D` = SHA-256 of the signer's own quorum set. | `HerderImpl::signEnvelope` / `verifyEnvelope`, `PubKeyUtils::verifySig`; `Stellar-SCP.x`. All 2 + 14 + 10 live signatures verify. |
| Is the ledger header signed? | **No.** SCP agrees on the *input* `StellarValue {txSetHash, closeTime, upgrades, ext}`. The header (the *output*) is not signed. | `Stellar-ledger.x`; `LedgerHeader.scpValue` |
| Then what authenticates a header? | The next ledger's tx set. `GeneralizedTransactionSet v1 = {previousLedgerHash, phases}`, and `txSetHash = SHA-256(XDR)`. A node votes for a tx set only if `previousLedgerHash` equals its last closed ledger. Ledger hash = SHA-256(XDR(LedgerHeader)). | `TxSetFrame.cpp` (`mHash(xdrSha256(xdrTxSet))`, checkValid `PREVIOUS_LEDGER_HASH_MISMATCH`), `LedgerManagerImpl` (`lcl.hash = xdrSha256(header)`); re-checked on 64-ledger archive ranges of both networks. |
| Can older headers be reached faster than one by one? | **No.** `skipList` holds old *bucket-list* hashes, not ledger hashes, despite the XDR comment. | `BucketManager::calculateSkipValues` (`skipList[0] = bucketListHash`) |
| What is `bucketListHash`? | `SHA-256(liveBucketList ‖ hotArchiveBucketList)` (since protocol 23). Each list is `SHA-256` over 11 levels of `SHA-256(curr ‖ snap)`, and a bucket's hash is SHA-256 over the whole bucket file. There is no Merkle tree inside a bucket. | `BucketManager::snapshotLedger`, `BucketListBase::getHash`, `BucketLevel::getHash`, `BucketOutputIterator` |
| Can one `ContractData` entry be proven against it? | **Not in practice.** The proof would need the entire bucket that holds the newest version of the entry. Measured on the current archives: pubnet level 0 is 509 KB and level 1 is 1.4–1.6 MB; level 9 is 415 MB and level 10 is 2.4 GB (gzip). Testnet level 0 is 96 KB. Only an entry written in the last one or two ledgers sits in level 0. No public RPC returns entry proofs (`getLedgerEntries` returns values only). | `history.stellar.org` HAS + bucket files; Stellar RPC API |
| What else does the header commit to? | `txSetResultHash = SHA-256(XDR(TransactionResultSet))`, all of the ledger's results. A successful `InvokeHostFunction` result holds `sha256(InvokeHostFunctionSuccessPreImage {returnValue, events})`. The events there are the host's contract events, and each carries a `contractID` that the host sets. | `LedgerManagerImpl` (`txSetResultHash = xdrSha256(txResultSet)`), `InvokeHostFunctionOpFrame::collectEvents` / `finalizeSuccess` |

So the verifier proves **a contract event in a closed ledger** through the transaction-result path,
and does not use the bucket list.

## Design

### Finality: a slice of the trusted quorum set

A slot S is accepted when the distinct signers of valid EXTERNALIZE envelopes for `(S, V)` satisfy the
trusted quorum set. Satisfaction is evaluated like stellar-core's `LocalNode::isQuorumSlice`: at
least `threshold` entries per level, where a validator entry counts if it signed and an inner set
counts if it is itself satisfied. The threshold is therefore organization-based, not a flat k-of-n.

| Network | Trusted set (live) | Minimum signatures |
|---|---|---|
| pubnet | 10 organizations × 3 validators; 7 of 10 organizations, 2 of 3 in each | **14** |
| pubnet, before the Sept 2026 expansion | 7 organizations × 3; 5 of 7, 2 of 3 | 10 |
| testnet | SDF's 3 validators, 2 of 3 | 2 |

Envelopes are sorted by node id, so each signer counts once. Each signer must be a member of the set.
All envelopes must have the same slot and the same value. The value's ext must be BASIC or SIGNED.
`STELLAR_VALUE_EMPTY_TX_SET` (a skipped ledger whose applied tx set differs from `txSetHash`) is
rejected. Only EXTERNALIZE is accepted. Archives sometimes keep a node's last CONFIRM instead, and
the relayer skips those envelopes.

### From the signed value to a header, then to the event

```
SCP EXTERNALIZE(S, V) ×14 ──► V.txSetHash ══ SHA-256(txSet S) ──► txSet.previousLedgerHash = hash(header S-1)
header S-1 ──previousLedgerHash──► header S-2 … ──► header N (ledgerSeq checked at every step)
header N.txSetResultHash ══ SHA-256(TransactionResultSet N)
   resultSet[o:o+32] ══ SHA-256(networkID ‖ ENVELOPE_TYPE_TX ‖ Transaction)   (supplied tx payload)
   result at o+32: txSUCCESS, 1 × opINNER/INVOKE_HOST_FUNCTION/SUCCESS → successHash
   successHash ══ SHA-256(preimage = SCV_VOID ‖ events…)
   events[0].contractID == channel's service contract id; topics and data == clpr_queue layout
```

The transaction hash locates the result pair. Its preimage begins with the network id, and no other
32-byte value in a result set is a SHA-256 over a networkID-prefixed preimage. So a matching window is
the transaction's own `TransactionResultPair`, or the `InnerTransactionResultPair` of a fee bump, whose
`InnerTransactionResult` has the same success layout. The verifier never parses the other results.

### CLPR on Stellar: the attestation event (Soroban side, not deployed)

No CLPR service exists on Stellar. The verifier fixes this interface for the Soroban `ClprService`. A
permissionless `attest_queue(channel_id)` reads the channel, emits exactly one event and returns
nothing:

```rust
// topics: (Symbol "clpr_queue", BytesN<32> channel_id); data: Bytes, 124 bytes big-endian
env.events().publish(
    (symbol_short!("clpr_queue"), channel_id),
    Bytes::from(next_message_id.to_be_bytes() ‖ sent_running_hash ‖ received_message_id.to_be_bytes()
        ‖ received_running_hash ‖ (status as u32).to_be_bytes() ‖ endpoint_manifest_version.to_be_bytes()
        ‖ manifest_commitment),
);
// attest_manifest(): topics (Symbol "clpr_manifest"), data Bytes(32) = keccak256(manifest protobuf)
```

The topics and the data are compared byte for byte with their XDR (`SCV_SYMBOL`, `SCV_BYTES`). Message
payloads come from the bundle content, and `ClprService` binds them to `sentRunningHash`. The emitter
must be the channel's peer service address, which for Stellar is the 32-byte contract id.

### Checkpoints and two-transaction bundles

| Pubnet (768 ledgers: 12 checkpoints over the 5 days to 1 Oct 2026) | min | p5 | median | p95 | ≤ 115 KB |
|---|---|---|---|---|---|
| tx set | 99.5 KB | 135 KB | 306 KB | 413 KB | **1.4 %** |
| result set | 37 KB | 54 KB | 78 KB | 117 KB | 94 % |

A pubnet proof with both rarely fits 128 KB, so the trust anchor keeps a checkpoint, a proven
`(ledgerSeq, hash)`:

1. **Step 1** (`scp` only): finality of a slot S whose tx set fits. The checkpoint becomes ledger S-1. No
   queue state is proven, so the verifier re-returns the last proven metadata (the preimage of
   `anchor.lastMetadataHash`). Before the first attestation it returns the empty queue
   `{nextMessageId 1, …, PENDING}`. `ClprService` accepts this as a trust-anchor-only update, with zero
   new messages and the same running hash. `IntegrationStellar.t.sol` checks this on an unmodified
   service.
2. **Step 2** (`headers` and `attestation`, no signatures): walk back from the checkpoint to the
   event's ledger.

Testnet tx sets are 5–44 KB, so one transaction does both steps. A relayer on pubnet waits for a
ledger with a small tx set: about 1 in 70, or about 6 minutes. Calling `attest_queue` once per ledger
while waiting keeps the header walk to one or two headers.

Replay protection: SCP slots must increase (`StaleSlot`). A bundle returns a new anchor only when
the anchor changed, so re-proving the same queue state from the same checkpoint returns no anchor, and
the service rejects it with `NoProgress`. Older queue states are rejected by the service's replay,
ack and state-machine checks (`ClprReplayDetected`), as with every other verifier.
`IntegrationStellar.t.sol` covers both.

### Quorum-set rotation

The trusted set moves to a new set Q' when the bundle carries Q' and the signers whose statements
declare `D = SHA-256(Q')` satisfy the *current* set. The tier-1 quorum itself declares Q' as its quorum.
Q' must pass stellar-core's sanity checks, including the "extra checks" that every level has a
threshold of at least 51 %, a nesting depth of at most 4 and no duplicates. Q' may have at most 64
validators. The rotation counts the same signatures as finality, so it costs nothing extra.

Live proof: the pubnet tier-1 expansion from 7 to 10 organizations. Validators switched `D` between
ledgers ~64,146,400 and ~64,160,000. Slot **64,150,367** is the first slot with a fitting tx set where
10 old-set validators (2 in each of 5 organizations) declare the new set. `verifyBundle` rotates
`958e72b8… → 040355b7…`, and today's finality proof runs under that rotated set.

### Formats

```
anchor  = abi.encode(bytes32 qsetHash, uint64 lastSlot, uint32 checkpointSeq, bytes32 checkpointHash,
                     bytes32 lastMetadataHash)                     (160 bytes; id = lastSlot ‖ lastMetadataHash)
bundle  = RLP[qsetXdr, scp, headers, attestation, lastMetadata, bundleContent, manifestPreimage]
scp     = [] | [[[statementXdr, sig64], ...], txSetXdr, newQsetXdr | ""]
headers = [headerXdr, ...] from the checkpoint backwards ([] only without an attestation)
attestation = [] | [txPayload, resultSetXdr, pairOffset, successPreimage]
config  = RLP[qsetXdr, scp, ledgerConfigControlMessage]; manifest proof = RLP[headers, attestation, preimage]
```

The constructor takes the Ed25519 verifier, the network id (SHA-256 of the passphrase) and the CAIP-2
id (`stellar:pubnet`, `stellar:testnet`). `verifyConfig` pins the CAIP-2 id.

## Trust model

1. **Signature safety.** A forged finality proof needs Ed25519 keys of at least 7 of the 10 tier-1
   organizations, 2 in each, signing EXTERNALIZE for a value the network did not externalize. A single
   honest intact node's EXTERNALIZE already implies that the network externalized V (SCP safety).
   Demanding a full slice is what makes forging require a colluding tier-1 majority. This is the trust
   that every pubnet node places in tier-1.
2. **A fixed view of a federated network.** SCP has no global validator set: each node chooses its own
   quorum slices. This verifier behaves like a watcher node configured with the tier-1 quorum set.
   That set follows tier-1 only through rotation proofs signed by tier-1 itself. Validators that left
   tier-1 keep their signing power until the next rotation is relayed.
3. **Weak subjectivity at setup.** The initial quorum set comes from the config proof. `verifyConfig`
   checks only that it is sane and that it externalized a real slot. Whoever completes the channel
   must check that set against the network, for example against stellarbeat.io or the archives' `D`
   values.
4. **Rotation liveness.** A rotation needs an old-set slice that declares the new set while its tx set
   fits. In the September 2026 change this held about 4,000 ledgers after the first validator switched.
   If tier-1 ever changes so fast that no old-set slice declares the new set, the channel needs a new
   config.
5. **The Soroban service contract.** Only its contract id is pinned. Soroban contracts can replace their
   own Wasm (`update_current_contract_wasm`), and the code hash is in state, which cannot be proven
   here. The verifier therefore trusts the service's upgrade authority, unlike the EVM verifiers, which
   pin a code hash. The service must emit `clpr_queue` only with its true state.
6. **Fail closed on protocol change.** An unknown `StellarValue`, header extension or result arm reverts.
   A protocol upgrade that changes these layouts halts verification until the code is reviewed.

## Gas and calldata (Hedera: 15M gas, 128 KB)

Figures are `eth_estimateGas` on anvil (with 21k and calldata) for live data, and forge gas for
synthetic data. "Harness" means the production steps up to the event's emitter (see Tests). The live
event is not `clpr_queue`.

| Case | Gas | Calldata | Fits |
|---|---|---|---|
| Testnet, one transaction: 2 sigs, 27 KB tx set, 2 headers, 15-tx result set | 2.21M (harness) | 32.2 KB | yes |
| Testnet `verifyConfig` (2 sigs) | 2.15M | 28.2 KB | yes |
| **Pubnet step 1**: 14 of 30 envelopes, 77.6 KB tx set (complete `verifyBundle`) | **13.38M** | 83.7 KB | yes, 1.6M spare |
| **Pubnet step 2**: 3 headers, 184-tx result set (62 KB) | **1.92M** (harness) | 68.4 KB | yes |
| Pubnet in one transaction (the same data) | 14.35M | 150 KB | **no**: over 128 KB |
| **Pubnet rotation** 5/7 → 7/10: 10 endorsers, 107.5 KB tx set | **10.58M** | 113.2 KB | yes |
| Synthetic `submitBundle` on `ClprService` (4 sigs, DATA + REPLY) | 4.05M | 3.5 KB | yes |
| Marginal Ed25519 signature (statement 244 B, signed message 280 B) | **834k** | ~0.3 KB | |

**Signature budget.** About 835k gas per signature, more than the ~640k CometBFT figure, because the
signed message is 280 bytes and needs one more SHA-512 block. That allows 17 signatures in 15M with
no calldata, and about 15 next to an 80 KB tx set. Pubnet's 14 fit today. If tier-1 grows to 11
organizations (threshold 8, 16 signatures), step 1 no longer fits. The options then are a signature
accumulator across transactions, a SNARK of the slice, or an Ed25519 precompile on Hedera.

Contract size: `StellarScpVerifier` 17,489 B (EIP-170 headroom 7.1 KB); `Ed25519Verifier` 12,206 B.

## Limits and known gaps

- **No CLPR service on Stellar.** The event format above is this verifier's proposal. A Soroban
  `ClprService` port, and the Hiero → Stellar direction, are separate work.
- **Pubnet latency.** Archive checkpoints are published every 64 ledgers (~6 min). Waiting for a tx
  set under ~120 KB takes ~6 min on average, and longer during busy periods. A relayer can also take
  EXTERNALIZE envelopes from the overlay as a watcher node, which avoids the archive delay.
- **Event shape.** The attestation must be the invocation's first event, with a void return value. A
  CONFIRM-only quorum is not accepted.
- **Ed25519 strictness.** The vendored Ed25519 library is not libsodium's strict verifier
  (small-order and non-canonical checks). Only distinct signers are counted, so malleability cannot
  inflate the count.
- **Fixture dependencies.** The relay scripts import `@noble/curves` (a dependency of `viem`, not
  declared in `package.json`).

## Tests and live data

- `test/verifiers/evm/stellar/StellarScpVerifier.t.sol` (49 tests) uses a synthetic chain with real
  Ed25519 signatures and real XDR (`fixtures/synthetic.json`, generated by
  `npm run stellar-synthetic:refresh`; forge 1.5 cannot sign Ed25519). Negative cases: bad signature,
  tampered statement, wrong network id, below threshold (one organization; one signer per
  organization), unknown signer, duplicate signer, wrong validator set, mixed slots, conflicting
  value, wrong tx set, stale slot, replayed bundle, rotation not endorsed, rotation to an undeclared
  or insane set, broken or tampered header chain, no checkpoint, tampered result set, wrong pair
  offset, another transaction's payload, other network, tampered preimage, wrong emitter, wrong
  channel, other event, invalid status, wrong last metadata, nothing proven, malformed anchor, and
  truncations that never panic.
- `test/verifiers/compliance/StellarComplianceTest.t.sol`: the shared `IClprVerifier` compliance
  suite (21 tests). Every manifest the suite commits to is pre-published as a signed `clpr_manifest`
  event in the synthetic chain.
- `test/integration/IntegrationStellar.t.sol`: on an unmodified `ClprService`, config → bundle (DATA
  delivered, REPLY acked) → replay rejected. Then the two-step form: checkpoint, then headers + event
  + messages, then the same state again (`NoProgress`) and an older state (`ClprReplayDetected`).
- `test/e2e/fixtures/stellar-live/{testnet,pubnet}.json` are refreshed with `npm run stellar-live:refresh`
  (SDF history archives, plus a public Stellar RPC for one transaction's envelope and events). They are
  checked by `npm run test:e2e:stellar-live` (anvil, 23 tests). The live events are real Soroban events
  that stand in for `clpr_queue`: a `new_block_event` on testnet, and a RedStone `REDSTONE` price
  update on pubnet. `verifyBundle` passes every step and stops at `WrongAttestationEvent`. Steps 1 and
  the rotation pass completely.

## Family coverage

Any stellar-core network (pubnet, testnet, futurenet, private networks): configure the network id,
CAIP-2 id and initial quorum set. Stellar-core forks such as Pi Network share the SCP envelope and
header formats. The finality half should apply to them unchanged (not verified here), and the event
half needs Soroban.
