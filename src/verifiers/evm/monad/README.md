# Monad → Hiero verifier

`MonadVerifier` (an `IClprVerifier`) and its helper `MonadValsetRotation` verify the Monad side of a
CLPR channel on Hedera's EVM:

1. a **MonadBFT quorum certificate** (BLS12-381 aggregate signature of the epoch's stake-weighted
   validator set) over a block;
2. the **2-chain commit rule**, so the block is final;
3. Monad's **delayed execution result**: a block carries the Ethereum header — and state root — of the
   block executed `D = 3` blocks earlier;
4. the ClprService queue metadata via **MIP-8 page-storage proofs** against that state root;
5. **validator-set rotation by epoch**, proven from the staking precompile's own storage.

It reuses `ClprEvmBundleVerifier` for the CLPR storage layout, metadata decode and bundle content.

## Protocol facts and where they come from

Every rule below was read from source: `category-labs/monad-bft` @ `ac3ae48` (2026-09-29) and
`category-labs/monad` @ `06afa49` (2026-09-30), plus docs.monad.xyz.

| Fact | Source |
|---|---|
| `BlockId = blake3(rlp(ConsensusBlockHeader))`; the header has 13 RLP fields (`block_round, epoch, qc, author, seq_num, timestamp_ns, round_signature, delayed_execution_results, execution_inputs, block_body_id, base_fee, base_fee_trend, base_fee_moment`) | monad-bft `monad-consensus-types/src/block.rs` (`get_id`, `Encodable`), `monad-crypto/src/hasher.rs` (`HasherType = Blake3Hash`) |
| `QuorumCertificate = [Vote{id, round, epoch}, BlsSignatureCollection{SignerMap, sig}]`; `SignerMap = [num_bits, bytes]` with validator 0 as the most significant bit | `quorum_certificate.rs`, `voting.rs`, `monad-bls/src/aggregation_tree.rs` |
| Votes are BLS `min_pk` (G1 keys, G2 signatures), DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, message `"\x0dmonad/vote/1\n" ‖ rlp(vote)`; verification is fast-aggregate-verify | `monad-bls/src/bls.rs`, `monad-crypto/src/signing_domain.rs`, `monad-consensus/src/validation/signing.rs::verify_qc` |
| Signer bitmap index = position in `BTreeMap<NodeId<secp PubKey>>`, i.e. ascending 33-byte compressed secp key (`secp256k1_ec_pubkey_cmp`) | `monad-validator/src/validator_mapping.rs`; rust-secp256k1 0.31 `Ord for PublicKey` |
| Supermajority: signed stake ≥ ⌊2·total/3⌋ + 1 | `monad-validator/src/validator_set.rs::has_super_majority_votes` |
| Commit rule: a QC on B with `round == B.qc.round + 1` commits B's parent P | `QuorumCertificate::get_committable_id` |
| `EXECUTION_DELAY = 3`; a proposal with `seq_num = n` must carry exactly `[EthHeader(n − 3)]`, and validators vote only for coherent blocks | `monad-node/src/main.rs`, `monad-eth-block-policy` (`get_expected_execution_results`, `check_coherency`), `monad-consensus-state` ("not voting on proposal, is not coherent"); docs "Asynchronous Execution → Delayed Merkle Root" |
| MIP-8 (testnet 2026-08-12, mainnet 2026-09-02): the storage trie commits to 128-slot pages; trie path `keccak(slot >> 7)`, leaf `RLP(page_commit)`; `page_commit` = BLAKE3 induced-subtree Merkle commitment sealed with the slot bitmap | monad `category/execution/monad/db/storage_page.cpp`, `ethereum/db/util.cpp` (`PagedStorageLeafProcessor`), docs "MonadDb", "MIP-8 activation" |
| Next epoch's set = staking `valset_consensus` (ids), `consensus_view(id).stake`, `val_execution(id).keys` (secp 33 ‖ bls 48, immutable), read when `epoch == E` and `in_epoch_delay_period` | monad `staking/read_valset.cpp`, `staking_contract.hpp` (slot layout), `syscall_snapshot` / `syscall_on_epoch_change` |

## Proof formats

`proofBytes` is RLP; the first item selects the kind.

**FINALIZED (0)** — `[0, finality, valsetBlob, serviceAccountProof, channelPages, bundleContent, rotationStart, (manifestPages, manifestPreimage)?]`

- `finality = [headerP, headerB, qcOnB, signature]`: P and B as raw consensus-header RLP, `qcOnB` the
  QC on B as carried in B's child's header, `signature` its aggregate in uncompressed EIP-2537 form
  (bound byte-for-byte to the compressed signature in the QC).
- `valsetBlob`: n × (EIP-2537 G1 key 128 B ‖ stake 32 B) in consensus order; must hash to the anchor.
- `channelPages` / `manifestPages`: pooled page proofs `[nodePool, [[pageKey, nodeIndices, bitmap, values]…]]`.
- `rotationStart`: `[]`, or `[stakingAccountProof, stakingPages]` to begin a rotation.

**ROTATION (1)** — `[1, channelPages, bundleContent, chunk, finalize]`, against the roots pinned at
rotation start. `chunk = [ids, registry, hints, stakingPages, count]`, `finalize = [sortedSet, permutation, ids]`.

**Trust anchor** (12 words): `epoch, valsetHash, codeHash, pendingEpoch, pendingBlock, stakingRoot,
serviceRoot, pendingLength, pendingProven, pendingAcc, pendingIds, keysHash`.

**Config proof**: `[chainId, serviceAddress, codeHash, peerConfigNanos, throttles, epoch, valsetBlob, finality, (keyRegistry)?]`.

## Validator-set rotation

Rotating from epoch E to E+1 spans several bundles (Hedera allows 15M gas / 128 KiB per transaction):

1. **start** (inside a FINALIZED bundle with an epoch-E QC): prove `epoch == E`,
   `in_epoch_delay_period == true`, and the whole `valset_consensus` id array; pin the staking and
   ClprService storage roots of that state. `valset_consensus`, `consensus_view` and the keys are written
   only by `syscall_snapshot` (guarded by the delay flag) and `syscall_on_epoch_change`, so every state in
   the delay period gives the set consensus read at the boundary block. A later restart (newer block)
   keeps the progress.
2. **chunks**: per validator, prove its stake page and — only if it was not in the previous set's key
   registry — its keys page; fold `(secp, bls, stake)` into an array-order accumulator.
3. **finalize**: the set in consensus order with uncompressed keys and a permutation to array order;
   the verifier recomputes the accumulator (compressing every key, on-curve check), then installs
   `keccak(valsetBlob)` for E+1 and the new key registry.

A QC of epoch E+1 is rejected (`EpochMismatch`) until the rotation is installed; a bundle signed by an
old epoch's set is rejected after it (`ValidatorSetMismatch` / `EpochMismatch`).

## Gas and calldata (196 validators, the mainnet size)

`forge test --match-path test/verifiers/evm/monad/GasUsage.t.sol -vv`; tx gas = 21000 + calldata + execution.

| Step | Execution gas | Calldata | Tx gas |
|---|---|---|---|
| Typical bundle (QC + 2 headers + account + channel pages + 2 messages) | 1.43M | 37.1 KB | 1.89M |
| Rotation start (finalized bundle + staking epoch/flag + id array) | 6.40M | 47.4 KB | 6.95M |
| Warm rotation: 3 chunks of 66 (+ finalize in the last) | 7.8M / 8.5M / 9.0M | 45 / 47 / 85 KB | 8.4M / 9.1M / 10.2M |
| Cold rotation (no key registry yet): 7 chunks of 28 (+ finalize) | 9.6M–9.8M, last 11.3M | 31–33 KB, last 72 KB | ≤ 12.2M |

All steps are under 15M gas and 128 KiB. A steady-state epoch change (every 50,000 blocks, ~5.5 h on
mainnet) costs 4 transactions (~35M gas); the first rotation after bootstrap without a key registry
costs 8. The synthetic staking trie is shallower than mainnet's (an estimated 5–6 levels instead of
3), which adds about 1 KB and 10k gas per proven page; chunk sizes are relayer parameters
(`MONAD_CHUNK`, `MONAD_COLD_CHUNK`) and leave room for that.

Contract sizes: `MonadVerifier` 22,511 B, `MonadValsetRotation` 14,507 B (EIP-170: 24,576 B).

## Trust assumptions

- Fewer than 1/3 of the epoch's stake is Byzantine (MonadBFT's own assumption). Under it a QC implies
  honest voters checked the block, including its parent QC and its delayed execution result.
- The bootstrap validator set (config) is trusted, like any light-client genesis; the config must carry a
  QC by that set so a stale or wrong set is caught at channel setup.
- Code-hash pinning of the ClprService (as in the other EVM verifiers).
- Validator keys are immutable per id and ids are never reused (staking `ValExecution::keys`,
  `last_val_id`), which the key registry relies on.
- Not covered: governance or hard-fork changes to these rules (e.g. a new `EXECUTION_DELAY`, header
  layout or staking layout) need a new verifier version, like any light client.

## Live data

Monad's public RPC has **no `eth_getProof`** (the method is not implemented in `monad-rpc`;
`rpc.monad.xyz`, `testnet-rpc.monad.xyz` and `rpc-mainnet.monadinfra.com` answer "Method not found",
Alchemy's `rpc1.monad.xyz` "not available on MONAD_MAINNET") and **no endpoint for consensus headers**;
the public archive buckets are requester-pays (AWS credentials needed). So a full live bundle cannot be
built from public data today. What the live fixture (`test/e2e/fixtures/monad-live/capture.json`, refreshed with
`npm run monad-live:refresh`) does cover, verified on anvil by `npm run test:e2e:monad-live`:

- **Live QCs, verified on-chain** by the production code path, mainnet (epoch 2190, 196 validators) and
  testnet (epoch 1343, 199 validators): the Monad Foundation publishes each node's latest high QC every
  minute (`bucket.monadinfra.com/forkpoint/<net>/`) and the validator sets (`validators/<net>/validators.toml`).
  About 0.98M gas, 32 KB calldata. Tampered vote, cleared signer bit, wrong stakes, swapped keys and a
  mismatched uncompressed signature are rejected.
- **Rotation layout on live state**: raw staking-precompile storage read at a pinned block decodes to
  exactly the next epoch's published set (ids → keys, stakes, ordering) on both networks; the bundle
  validator-set blob rebuilt from it is the one the verifier expects.
- **Delayed-root header**: the live Ethereum header RLP hashes to the block hash, with the state root
  and number at the indices the verifier reads.

The finality chain (consensus headers P/B), the MIP-8 page proofs and the rotation chunks are covered by
the 196-validator synthetic fixture (`test/verifiers/evm/monad/fixtures/synthetic`, built by
`npm run monad:fixtures` with the same encodings), which the anvil spec also runs end to end.

### Sourcing live bundles (checked 2026-10-01)

- **Storage proofs.** None of the 29 keyless Monad endpoints listed on chainlist (mainnet and testnet:
  Monad Foundation, Alchemy, Ankr, dRPC, OnFinality, Tatum, Sentio, thirdweb, Huginn and others) serves
  `eth_getProof`, and no Monad-specific proof method exists: `monad-rpc` @ `ac3ae48` implements none, and
  the only proof-generation work upstream (category-labs/monad #986/#987, Oct 2024, slot-level and
  pre-MIP-8) is unmerged. Running our own node therefore does not give proofs out of the box either: the
  relayer needs a small proof tool on `category/mpt` that reads `/dev/triedb` and emits the account path
  plus the MIP-8 page leaf in the `channelPages` format.
- **State snapshots.** Category Labs publishes a keyless state snapshot (`d3b0ffqjb9bqrg.cloudfront.net/latest.txt`,
  mainnet; about 8.2 GB, `monad-cli --dump-binary-snapshot` format). It holds account values and
  slot-granular storage, not trie nodes, so proofs need the whole state trie (with page commitments)
  rebuilt offline. That gives page proofs only at the snapshot block, which is useful for testing but
  not for relaying.
- **Consensus headers and QCs.** No RPC method serves them (`monadNewHeads` carries only the block id).
  The forkpoint files give a QC and a root block id, not header preimages. The archiver uploads
  `bft_block/<id>.header` to the archive buckets (`mainnet-deu-010-0`, `testnet-can-004-0-aavn9ll`),
  but those are requester-pays and need AWS credentials, so their contents are unverified.
- **Receipts.** The `receiptsRoot` of live mainnet and testnet blocks is the standard keccak MPT over
  `debug_getRawReceipts` (checked on 6 blocks), so event inclusion proofs can be built from the public RPC.
  The verifier does not use them today.
- **Own node.** Requires x86-64 (AVX2, asmjit x86 JIT), Linux with io_uring (Ubuntu 24.04 packages),
  16 cores at 4.5 GHz or more, 32 GB of RAM or more, a dedicated 2 TB NVMe for TrieDB plus 500 GB, and
  bare metal. A Mac cannot run it. A full node's ledger (`ledger/headers/`) holds the consensus headers;
  the QC on B is the `qc` of B's child.

## Chain family

Monad mainnet (chain id 143) and testnet (10143) — same verifier, different config. MonadBFT with
BLAKE3 block ids and MIP-8 page storage is specific to Monad; the reusable pieces are the BLAKE3
library, the POP hash-to-G2 / aggregate BLS check, and the pooled MPT walker.

## Files

- `MonadVerifier.sol`, `MonadValsetRotation.sol`
- `src/libraries/proof/monad/`: `MonadBlake3`, `MonadBls`, `MonadMpt`, `MonadPageProof`
- Tests: `test/verifiers/evm/monad/` (unit, negative, gas), `test/verifiers/compliance/MonadComplianceTest.t.sol`,
  `test/libraries/proof/monad/`, `test/e2e/tests/verifiers/monad-live.spec.ts`
- Builders: `test/e2e/relay/monad/` (`buildMonadFixtures.ts`, `refreshMonadLive.ts`, `monad.ts`, `blake3.ts`, `mpt.ts`)
