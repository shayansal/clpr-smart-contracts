# Substrate verifiers: GRANDPA and BEEFY

> **Sources**: [GrandpaVerifier.sol](./GrandpaVerifier.sol) (Bittensor and other solo chains) ·
> [BeefyParachainVerifier.sol](./BeefyParachainVerifier.sol) (Hydration and other Polkadot parachains) ·
> shared [SubstrateEvmVerifierBase.sol](./SubstrateEvmVerifierBase.sol) ·
> libraries in [libraries/proof/substrate](../../../libraries/proof/substrate):
> `Blake2b`, `ScaleCodec`, `SubstrateHeader`, `SubstrateTrie`, `GrandpaLib`, `BeefyLib` ·
> Ed25519: [Ed25519Verifier](../sei/Ed25519Verifier.sol)
> **Interface**: [IClprVerifier.sol](../../../interfaces/IClprVerifier.sol)

These are "Substrate chain → Hiero" verifiers. Each one runs on Hedera's EVM and checks two things:
(1) that a block is final, and (2) the CLPR Service's queue storage in that block. The CLPR Service
here is a Solidity contract running on the chain's Frontier EVM (`pallet_evm`). Its storage sits in
the Substrate state trie, not in an Ethereum MPT.

| | Bittensor (#13) | Hydration (#38) |
|---|---|---|
| Kind | Solo chain (Aura + GRANDPA) | Polkadot parachain 2034 |
| Finality source | Its own GRANDPA, ed25519 | Polkadot relay chain **BEEFY**, secp256k1 |
| Signers per proof | 14 of 20 authorities | 401 of 600 relay validators |
| Head of the chain | justified header | `Paras::Heads(2034)` in relay state |
| EVM storage | `EVM::AccountStorages` (Frontier) | `EVM::AccountStorages` (Frontier) |
| Live `verifyBundle`, typical | **9.36M gas, 14.3 KB** | **4.22M gas, 52.5 KB** |
| Live, with a set rotation | 9.34M gas, 14.1 KB | 4.16M gas, 50.9 KB (7.39M / 91.7 KB with a catch-up hop) |

The figures above come from `eth_estimateGas` of the full transaction on anvil (Prague rules, so
EIP-7623 calldata pricing applies). They use the mainnet data recorded on 2026-10-01 (§6). Hedera's
limits are 15M gas and 128 KB of calldata.

## 1. Shared state layer (both verifiers)

Once a finalized `state_root` is authenticated, both verifiers read the CLPR Service in the same way.

**Storage key** (frontier `frame/evm`, `StorageDoubleMap<_, Blake2_128Concat, H160, Blake2_128Concat, H256, H256, ValueQuery>`):

```
twox128("EVM") ‖ twox128("AccountStorages") ‖ blake2_128(address) ‖ address ‖ blake2_128(slot) ‖ slot   (116 B)
```

`twox128(pallet)` is a constructor parameter (`EVM_PALLET_PREFIX`). Both chains name the pallet
`EVM`. The `blake2_128` parts are computed on-chain with the BLAKE2F precompile (0x09). The
derivation was checked live: `accountStorageKey()` on-chain matches the keys that
`state_getKeysPaged` returns on Bittensor and Hydration. The value is the raw 32-byte word. Frontier
removes a slot when zero is written to it (`runner/stack.rs::set_storage`). So a key that is proven
absent reads as zero, the same as an EVM `SLOAD`.

**Trie** (`SubstrateTrie`, sp-trie `node_header.rs` / `node_codec.rs`):

- It is base-16 and uses `BlakeTwo256` node hashes.
- It supports LayoutV0 and LayoutV1. In V1, values of 33 bytes or more live in separate hashed value
  nodes.
- It handles all five node kinds, inline children (under 32 bytes), branch values, and padded odd
  partial keys.
- A proof is the unordered node set from `state_getReadProof`. Every node is looked up by its
  `blake2_256`. If the walk needs a node that the proof lacks, the call reverts with
  `MissingProofNode`. A key is only reported absent when a node actually rules it out.

**Slots** come from the CLPR storage layout, never from the proof. They are the same as in
`ClprEvmBundleVerifier`: Channel `+1, +2, +4, +5, +16`, an optional last-message running hash, and
manifest commitment slot 18. `verifyConfig` additionally proves `_config.serviceAddress` (slot 25)
and `_config.nanosSinceEpoch` (slot 26) against the claimed LedgerConfiguration. It also requires
the configuration's chain id to equal the profile's CAIP-2 id (`eip155:964` for Bittensor,
`eip155:222222` for Hydration).

**Headers** (`SubstrateHeader`): a header is `parent ‖ Compact<u32> number ‖ state_root ‖
extrinsics_root ‖ Vec<DigestItem>`, and its hash is `blake2_256` of the SCALE encoding, seal
included. The digest is decoded strictly: item kinds 0, 4, 5, 6 and 8 are accepted, and trailing
bytes are rejected.

## 2. GrandpaVerifier (Bittensor)

**Anchor** (44 B): `setId(u64) ‖ keccak256(authorities) ‖ minHeight(u32)`. Here `authorities` is the
packed GRANDPA list `(ed25519 key ‖ weight u64 LE)*`. Those are exactly the bytes inside a
`ScheduledChange` digest, so a rotation needs no re-encoding.

**Bundle** = `abi.encode(BundleProof{steps[], stateProof, lastMessageSlot, bundleContent, manifestPreimage})`.
Each step is `{headers[], round, votes, ancestry[], authorities}`:

1. `authorities` must hash to the working anchor.
2. `headers[0]` is the justified block J, and J.number must be at least `minHeight`. Each
   `headers[k+1]` is the parent of `headers[k]`. Only the last header may carry a GRANDPA signal.
3. The GRANDPA commit for `(blake2_256(J), J.number)` is checked. Each precommit signs
   `0x01 ‖ target_hash ‖ target_number(u32 LE) ‖ round(u64 LE) ‖ set_id(u64 LE)`
   (`sp_consensus_grandpa::localized_payload`, `Message::Precommit` = variant 1). Votes are
   re-packed by the relay as `index(u16) ‖ target_hash ‖ target_number ‖ sig(64)`, sorted, with no
   duplicates. A precommit for a descendant of J is linked back to J through `votes_ancestries`
   headers. Every supplied vote is verified, and their weight must reach
   `total − (total − 1) / 3` (finality-grandpa `VoterSet::threshold`).
4. Suppose the last header (block N) carries `ScheduledChange{next, delay}`. Then J must satisfy
   `J ≤ N + delay`, and the new anchor becomes `(setId + 1, keccak256(next), N + delay + 1)`. A
   `ForcedChange` reverts (§5). Every step except the last must perform a change.
5. The last J's `state_root` feeds §1. A new anchor is returned only if the set changed.

`verifyConfig` runs the same steps, starting from the deploy-time checkpoint
`(BOOTSTRAP_SET_ID, BOOTSTRAP_AUTHORITIES_HASH, BOOTSTRAP_MIN_HEIGHT)`.

**Live Bittensor facts (finney, spec 470):**

- 20 authorities, all with weight 1, so the threshold is 14.
- `CurrentSetId` is 6. The 5 → 6 change at #8,867,448 was a `ScheduledChange` with delay 0. It was
  scheduled through `AdminUtils` (subtensor `GrandpaInterfaceImpl`, which bumps `CurrentSetId`
  itself and can also issue forced or delayed changes).
- Nodes store a justification for every set-change block and periodically for others (the newest
  one found was #9,183,744).
- The public RPCs do not expose `grandpa_*` methods, so the relay reads `chain_getBlock(...).justifications`.

## 3. BeefyParachainVerifier (Hydration)

**Why BEEFY rather than relay GRANDPA.** Polkadot GRANDPA has 600 voters, so a proof needs 401
ed25519 signatures. At about 585k gas each in pure Solidity, that is roughly 235M gas, which is far
over 15M. BEEFY is run by the same validator set, signs with secp256k1 (so `ecrecover` costs about
3k gas each), and commits to an MMR whose leaves name the parent block hash.

**Why `Paras::Heads` and not the BEEFY leaf's para-heads root.** The Polkadot runtime's
`ParaHeadsRootProvider` merkelizes only lifecycle-`Parachain` paras plus a whitelist (3367). The
live set is `[1002, 1004, 1005]`. Hydration's lifecycle is `Parathread` (`0x01`, under agile
coretime), so its head is not in `leaf_extra`. It is proven from relay state instead.

**Anchor** (92 B): `current{id, len, root} ‖ next{id, len, root} ‖ minRelayBlock`. These are the
`BeefyAuthoritySet` values that `pallet_beefy_mmr` stores (`BeefyAuthorities` and
`BeefyNextAuthorities`).

**Bundle** = `abi.encode(BundleProof{commits[], relayHeader, relayStateProof, paraStateProof, …})`.
Each commit is `{commitment, signers, signatures, authorities, mmrLeaf, mmrPath, mmrPathSides}`:

1. Decode the SCALE commitment (`payload ‖ u32 block ‖ u64 set id`). It must carry exactly one 32-byte
   `"mh"` entry, and the block must be at least `minRelayBlock`.
2. The set id must equal `current.id`, or `next.id`, which means a rotation.
3. The authority addresses (20 bytes each, all of them) are re-merkelized:
   `binary_merkle_tree::merkle_root::<Keccak256>`, with leaves `keccak(address)` and an odd node
   promoted. The result must equal the set root and length. Then at least `n − (n−1)/3` signatures
   are checked, `ecrecover(keccak256(commitment))` with low-s, following the bitfield order (MSB
   first, as in `CompactSignedCommitment`).
4. The MMR leaf (113 B: `version ‖ parent_number ‖ parent_hash ‖ next set ‖ leaf_extra`) must sit
   under the commitment's MMR root. The path rules (verified against the live root): mountain
   siblings hash as `keccak(left ‖ right)`, the bag of right peaks as `keccak(bag ‖ acc)`, and each
   left peak as `keccak(acc ‖ peak)`. pallet-mmr bags peaks right to left as `keccak(right ‖ left)`.
   The leaf must be the commitment block's own leaf (`parent_number + 1 == block`), and its
   `next.id` must equal the set id plus 1.
5. On rotation, the anchor becomes `(next, leaf.next, block)`. Every commit except the last must
   rotate. A relay that missed one session can catch up in a single transaction: a rotation hop
   plus a newer commitment (live: 7.39M gas, 91.7 KB).
6. From the last leaf: `blake2_256(relayHeader)` must equal `leaf.parent_hash`. Then the relay state
   root gives `Paras::Heads(2034)` (`twox128("Paras") ‖ twox128("Heads") ‖ twox64(id) ‖ id`, a
   constructor parameter). The `HeadData` value is the SCALE Hydration header, which gives the
   Hydration `state_root` and then §1.

**Live Polkadot facts:**

- 600 BEEFY authorities, threshold 401.
- The set id rotates every session (about 2,400 blocks, roughly 4 h), even when the keys stay the
  same.
- `BEEF` justifications are stored about every 8 blocks.
- `mmr_generateProof` needs a node with offchain indexing. `rpc.polkadot.io` answers
  `LeafNotFound`, while `dot-rpc.stakeworld.io` works.

## 4. Trust assumptions

- **Bootstrap.** Each deployment pins a weak-subjectivity checkpoint: a set id plus an authorities
  hash, or the BEEFY current and next sets. `verifyConfig` never accepts a validator set that the
  proof itself supplies.
- **Honest supermajority.** No set the verifier trusts ever has more than 1/3 of its weight sign
  two conflicting blocks. As with every sequential light client, a retired set could later sign a
  fork. GRANDPA signatures bind `set_id`, so such a fork can only extend that set's own epoch. The
  relay must keep the anchor current. On Polkadot that means at least one bundle per session, or a
  hop.
- **BEEFY** is a separate gadget that follows GRANDPA. Its security is the same 2/3-honest
  validator assumption, enforced by BEEFY equivocation slashing.
- **Parachain finality.** A para head included in a finalized relay block is final. The verifier
  takes the head that relay state holds at `leaf.parent_number`.
- **Code pinning.** Neither verifier pins the service contract's code hash.
  `AccountCodesMetadata` exists in Frontier, but it is only written for contracts created after its
  introduction. A ClprService that is not upgradeable cannot change its code on Frontier.
- **Ed25519** goes through the pure-Solidity `Ed25519Verifier`. Hedera has no ed25519 precompile.
  It is the same contract the Sei and CometBFT verifiers use.
- **BLAKE2F (0x09)** is required. Hedera registers the full Prague precompile set
  (hiero-consensus-node `V070Module` → Besu `populateForPrague`). `Blake2b` reverts with
  `Blake2fFailed` if the precompile is missing.

## 5. Limits

| Item | Value | Note |
|---|---|---|
| ed25519 per signature | ~585k gas (53-byte message) | Bittensor: 14 × 585k ≈ 8.2M of the 9.36M |
| Largest GRANDPA set that fits | ~34 equal-weight authorities (23 signatures) | Bittensor has 20 today |
| GRANDPA hop + final step in one tx | ~18M: **does not fit** | Prove state at the change block instead (the rotation bundle above). One step per bundle. |
| BEEFY bundle with one catch-up hop | 7.39M / 91.7 KB | Two hops (≈ 131 KB) exceed 128 KB |
| ForcedChange | reverts | Needs a new bootstrap (governance re-deploy) |
| ScheduledChange with delay > 0 | supported | Header chain from N to the justified block (tested with delay 2) |

**If Bittensor's set outgrows a single transaction** (more than about 34 authorities), there are
two documented options. Neither is built.

1. **Multi-transaction accumulation.** A small stateful `GrandpaCommitAccumulator` receives signature
   batches over several transactions, each under 15M. It records the verified weight per
   `(setId, round, target)`. `verifyBundle`, which is `view`, then reads that record instead of
   re-verifying. The trust model is unchanged. The cost is about 585k gas per signature spread over
   ⌈t/23⌉ transactions, plus storage.
2. **SNARK.** Prove "≥ threshold ed25519 signatures over the GRANDPA payload by keys hashing to
   `authoritiesHash`" in a circuit (for example gnark's emulated ed25519, wrapped to Groth16 on
   BN254). Verify it with the BN254 precompiles for about 300k gas, independent of set size. This
   adds a circuit and a trusted setup to the trust base.

Bittensor has no BEEFY, so the secp256k1 route that Hydration uses is not available there.

## 6. Live data, tests, relay

- **Fixtures**: `test/e2e/fixtures/grandpa-live/{bittensor,hydration}.json`. They hold raw public-RPC
  responses recorded on 2026-10-01: Bittensor justifications at #9,183,744 (set 6) and #8,867,448
  (the 5 → 6 change); Polkadot BEEFY at #33,235,730, giving relay #33,235,729 and Hydration
  #15,244,831; and a BEEFY rotation 5728 → 5729 at #33,235,434. The refresh script checks every
  signature, root and link off-chain before writing:
  `npm run grandpa-live:refresh [-- bittensor|hydration]` (RPCs can be overridden with
  `BITTENSOR_RPC`, `POLKADOT_RPC`, `POLKADOT_MMR_RPC` and `HYDRATION_RPC`).
- **Anvil replay**: `forge build && npm run test:e2e:grandpa-live`. It runs 21 cases: typical
  bundles, rotations, the catch-up hop, real non-zero storage slots, and negative cases (tampered
  signature, below threshold, wrong or old set, set id replay, stale block, missing trie node,
  relay header mismatch, wrong para block).
- No ClprService is deployed on either chain. The "service" is therefore a live contract with
  storage (Bittensor `0x6647…7e3c`, Hydration `0xc918…bc48`). Its channel slots are proven absent,
  which yields zero metadata. Real non-zero slots of the same contracts are read through the trie
  harness.
- **Forge**: `test/verifiers/evm/grandpa/` covers the libraries (BLAKE2b vectors, compact, every
  trie node kind, digest parsing, BEEFY merkle/MMR) and both verifiers on a synthetic chain. The
  synthetic chain is built by `test/e2e/relay/buildSubstrateSyntheticFixture.ts` and uses real
  ed25519 and secp256k1 signatures, delay-0 and delay-2 changes, `votes_ancestries`, a
  `ForcedChange` and multi-mountain MMRs. Compliance adapters live at
  `test/verifiers/compliance/{Grandpa,BeefyParachain}ComplianceTest.t.sol`. The GRANDPA adapter
  replaces only the ed25519 curve operation, with a message-binding stub, because forge 1.5 cannot
  sign ed25519.
- **Relay helpers**: `test/e2e/relay/substrate.ts` provides SCALE, xxhash/twox, justification and
  commitment re-packing, the MMR path conversion, ABI payloads, and a LayoutV1 trie builder.

## 7. Family coverage

- **GrandpaVerifier** fits any Substrate solo chain with GRANDPA, ed25519 authorities, a `u32` block
  number, and Frontier under a pallet whose name is a profile parameter. Bittensor is verified live.
- **BeefyParachainVerifier** fits any Frontier parachain of a BEEFY relay chain whose head is in
  `Paras::Heads`, whether the para is a Parachain or a Parathread. Astar (para 2006) and peaq both
  expose `EVM::AccountStorages` (checked live), but neither was run end to end. Kusama also runs
  BEEFY, with 1,400 authorities. That is estimated to fit (about 934 signatures, around 100 KB, about 6M gas) but
  was not verified.
- The existing EVM-family verifiers do not cover these chains, because their state is not an
  Ethereum MPT.
