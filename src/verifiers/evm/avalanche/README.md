# AvalancheWarpVerifier — Avalanche C-Chain → Hiero

`AvalancheWarpVerifier` is an `IClprVerifier` for the Avalanche C-Chain. It runs on Hedera's EVM. It
accepts a C-Chain block when an Avalanche Warp `BitSetSignature` from validators holding at least 67%
of the Primary Network stake signs the block hash. It then proves the ClprService queue storage
against that header's state root with the shared `ClprEvmBundleVerifier` MPT code.

Files:
- `src/libraries/proof/avalanche/ClprAvalancheWarp.sol`: the Warp `UnsignedMessage` for a block
  hash, the canonical validator set, and signer aggregation with the weighted quorum.
- `src/verifiers/evm/avalanche/AvalancheWarpVerifier.sol`: trust anchor, bundle, rotation and config.
- `src/libraries/proof/beacon/ClprBeaconBls.sol`: gained `hashToG2Message` and `verifyMessage`, which
  hash raw bytes rather than a 32-byte root. The existing functions behave exactly as before.
- Tests: `test/verifiers/evm/avalanche/` (synthetic, live vectors, gas),
  `test/verifiers/compliance/AvalancheWarpComplianceTest.t.sol`, and
  `test/e2e/tests/verifiers/avalanche-live-fuji.spec.ts` (anvil).
- Live data: `test/e2e/fixtures/avalanche-live/`, built by `test/e2e/relay/buildAvalancheLiveProof.ts`.

`MockAvalancheVerifier` is unchanged and still backs the docker e2e harness (`CLPR_BACKEND=avalanche`).

## Protocol rules the verifier mirrors

Checked against `ava-labs/avalanchego` master (commit `3b99241`, 2026-10-01; coreth and subnet-evm
are grafted into it) and against the v1.15.0 nodes that serve Fuji.

| Rule | Source | Verifier |
|---|---|---|
| `UnsignedMessage = u16(0) ‖ u32(networkID) ‖ sourceChainID ‖ u32(len) ‖ payload` (linear codec v0) | `vms/platformvm/warp/unsigned_message.go`, `codec.go` | `blockHashMessage` |
| Block-hash payload `payload.Hash` = `u16(0) ‖ u32(typeID 0) ‖ hash32` | `warp/payload/{codec,hash}.go` | same |
| Validators sign `payload.Hash(h)` only if `h` is an **accepted** block's EVM hash. Snowman acceptance is final. | `graft/coreth/warp/verifier_backend.go`, `plugin/evm/vm.go#GetAcceptedBlock` | `blockHash = keccak256(header RLP)` |
| Canonical set: keyless validators dropped (their weight still counts in `TotalWeight`), equal keys merged with weights summed, sorted by the 96-byte uncompressed key | `snow/validators/warp.go#FlattenValidatorSet` | `validate` rejects anything else |
| `Signers` is a big-endian big.Int whose bit i is canonical validator i. It must be minimal (no leading zero byte) and must not name an index ≥ n. | `warp/signature.go`, `utils/set/bits.go` | `aggregateSigners` |
| Quorum `67·TotalWeight ≤ 100·signedWeight` | `warp/signature.go#VerifyWeight`, coreth `WarpDefaultQuorumNumerator = 67` | `requireQuorum` |
| BLS: G1 keys, G2 signatures, DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, signed message = raw UnsignedMessage bytes | `utils/crypto/bls` | `ClprBeaconBls.verifyMessage` |
| A coreth state account is `[nonce, balance, root, codeHash, isMultiCoin]`. Live Fuji leaves carry the 5th field. | `customtypes/state_account_ext.go`, live `eth_getProof` | `_serviceStorageRoot` accepts 4 or 5 fields |
| **ACP-194 (SAE, live on Fuji):** a header's `stateRoot` is the post-execution root of the last *settled* block (`settledHeight`, a few blocks back), not of the block itself | `vms/saevm/sae/blocks.go`, `blocks/export.go#SettledStateRoot` | The verifier is unaffected. The relayer calls `eth_getProof` at `settledHeight`. |

The whole chain was confirmed on live data before any Solidity was written. A Fuji block-hash
message was aggregated by the public ACP-118 signature aggregator. It verified off-chain against the
canonical set rebuilt from `platform.getValidatorsAt` (71 keys from 72 nodes, because one key is
shared; 12 signers holding 67.03% of the stake).

## Trust anchor (220 bytes, flat)

`networkId(4) ‖ sourceChainId(32) ‖ channelId(32) ‖ codeHash(32) ‖ setHash(32) ‖ totalWeight(32) ‖
pChainHeight(8) ‖ pChainTimestamp(8) ‖ maxSetAge(8) ‖ attestorsHash(32)`

- `setHash` is keccak256 of the packed set `n × (x48 ‖ y48 ‖ weight8)` in canonical order. `x ‖ y` is
  avalanchego's uncompressed key, so canonical order is plain byte order. The EIP-2537 limb padding is
  re-added in memory, which keeps 24 bytes per key out of calldata.
- `totalWeight` is uint256. Flare's total stake (2.2·10¹⁹) already exceeds uint64, and go-flare
  switched its Warp weights to big.Int.
- The trust-anchor id is `pChainHeight` (uint64, big-endian).

## Bundle (RLP, 7 items, or 9 with a manifest update)

```
[ header          RLP-encoded C-Chain header (bytes); blockHash = keccak256(header)
  warpSignature   [signers bit set, signature (256-byte uncompressed G2)]
  validatorSet    the packed set the signature is checked against
  rotation        0x80, or [pChainHeight, pChainTimestamp, totalWeight, threshold, attestors[], sigs[]]
  accountProof, storageProof (5|6 slots), bundleContent, [manifestStorageProof, manifestPreimage] ]
```

Steps:
1. Without a rotation, `keccak(validatorSet)` must equal `setHash`. With a rotation, the attested
   new set replaces it first.
2. Freshness: `pChainTimestamp ≤ header.time ≤ pChainTimestamp + maxSetAge`.
3. Aggregate the signers' keys with `BLS12_G1ADD` (375 gas per signer), check the quorum, rebuild the
   80-byte UnsignedMessage, hash it to G2, and run one pairing.
4. Run the account proof (code hash pinned), the channel-slot storage proof, and the bundle content.

The relayer decompresses the 96-byte Warp signature. The on-chain pairing proves that the point is a
valid signature, so the compressed form is not needed.

## What is proven, and what is trusted

**Proven from the chain:** finality and integrity of the C-Chain block (Warp quorum certificate over
its hash), the state root (from the hashed header), and the ClprService account and queue slots
(MPT).

**Trusted:** the validator set and its weights. Neither chain offers a proof of the Primary Network
set:
- the P-Chain has no state commitment and no finality signatures. Its blocks carry only the
  proposer's staking-key signature (proposervm).
- the P-Chain's ACP-118 handler signs only the ACP-77 L1-validator messages
  (`vms/platformvm/network/warp.go`). It never signs a block hash or the Primary Network set.
- C-Chain state does not contain the set. A contract that "publishes" the set would be signed only
  as an accepted log, not as a true statement.

So, as in every light client, the verifier works as follows:
- **Bootstrap (`verifyConfig`)** takes the set at a P-Chain height as a trusted input. This is weak
  subjectivity. The input is `[ledgerConfiguration, evmChainId, networkId, sourceChainId, pChainHeight,
  pChainTimestamp, validatorSet, totalWeight, maxSetAge, attestorThreshold, attestors[], codeHash]`.
- **Rotation** is accepted when `threshold` distinct attestors from the anchor's policy EIP-191-sign
  `keccak256(abi.encode(TYPEHASH, networkId, sourceChainId, pChainHeight, pChainTimestamp, setHash,
  totalWeight))`. Signatures must be in ascending signer order. Each attestor is expected to
  recompute the set from `platform.getValidatorsAt` on its own node. `threshold = 0` disables
  rotation, so a re-config is then needed.
- **What the chain still checks:**
  - every set (config and rotation) is in canonical order, which also rules out duplicates;
  - every set has non-zero weights, keyed weight ≤ `totalWeight`, and every key on the curve;
  - rotation is strictly forward: P-Chain height increases and the timestamp does not decrease, so an
    old rotation cannot be replayed;
  - after a rotation, the bundle must be signed by ≥ 67% of the *new* set;
  - a set is only usable inside its `maxSetAge` window.
- **Considered and rejected:** a "the old set must also sign" continuity rule. One aggregate signature
  binds only the sum of the signers' keys. Without a per-key proof of possession, an attestor could
  add cancelling rogue keys, and the weights stay unauthenticated in any case. The rule would add
  cost without reducing what must be trusted.

Further assumptions:
- Fewer than 1/3 of any tracked set's stake is malicious. This is Avalanche's own Warp assumption.
  Validators who left the set keep their keys, and `maxSetAge` bounds how long their signatures
  count. Keep `maxSetAge` at or below the network's minimum stake duration: 12 h on Fuji and 48 h on
  mainnet after Helicon, and 24 h / 14 days before it. The live fixture uses 12 h.
- BLS keys are valid subgroup points. The P-Chain enforces a proof of possession at registration.
  `G1ADD` checks that every signer key is on the curve, and the pairing precompile subgroup-checks
  the aggregate.
- The ClprService code hash is pinned by config, and the storage proof is bound to `channelId`.
- For the known C-Chains, `verifyConfig` binds the CAIP-2 id `eip155:<evmChainId>` to the
  (networkId, blockchainId) pair that the Warp message commits to: mainnet 43114, Fuji 43113, Flare
  14, Coston2 114. For other chains it checks only that the config is self-consistent.

## Gas and calldata

`eth_estimateGas` on anvil includes 21k base and calldata. Foundry figures are execution gas plus
21k plus calldata gas. Hedera limits are 15M gas and 128 KB calldata.

| Case | Execution | Total | Calldata |
|---|---|---|---|
| **Fuji live** (71 keys, 12 signers, WAVAX MPT), no rotation | 1.36M | 1.74M (`eth_estimateGas`) | 23.2 KB |
| **Fuji live**, real rotation P-Chain @298945 (70 keys) → @298993 (71 keys) | 1.48M | 1.86M (`eth_estimateGas`) | 23.4 KB |
| Synthetic Fuji scale (71 keys, 12 signers) | 0.62M | 0.78M | 9.4 KB |
| Synthetic mainnet scale (588 keys, 170 signers) | 1.05M | 2.04M | 63.2 KB |
| Synthetic mainnet, worst case (588 equal keys, 394 signers) | 1.15M | 2.13M | 63.2 KB |
| Synthetic mainnet rotation (588 → 588 keys, 2-of-3 attestors) | 1.74M | 2.72M | 63.5 KB |

The mainnet figures were measured on 2026-10-01: 588 unique Primary Network keys, and 170 signers
returned by the public aggregator for a real C-Chain block.

- The synthetic rows use a one-leaf MPT. A real ClprService proof adds the MPT cost on top. On Fuji,
  WAVAX's large trie costs about 0.6M gas and about 12 KB. A mainnet bundle should therefore stay
  under about 3M gas and about 80 KB.
- The packed set costs 104 bytes per key: about 7.4 KB on Fuji and 61 KB on mainnet. It is sent with
  every bundle, because the anchor stores only its hash.
- Runtime size is 19,473 B, leaving 5,103 B of EIP-170 headroom.

## Limits

- The validator set is trusted input (see above). This is the main limit.
- **Mainnet calldata.** The full set rides along with every bundle. That is fine at 588 keys
  (61 KB), but it would pass 128 KB at about 1,100 keys together with the proofs. A Merkle-committed
  set with signer proofs would then be needed. Today's mainnet would need about 170 × 456 B ≈ 77 KB
  for that, so it is not smaller yet.
- **The relayer must aggregate against the anchor's P-Chain height.** The public aggregator accepts
  `pChainHeight`. If validators who left can no longer reach 67% of the anchor's set, rotate first.
- **Rotation is not chained.** One rotation per bundle, but any newer height may be the target, so
  catching up is a single step.
- **ACP-194 (SAE).** The proven state lags the signed block by a few blocks (`settledHeight`).
  Public RPCs keep only a few recent states, so the relayer must call `eth_getProof` right after
  choosing the block.
- **Firewood.** If a chain's state moves to a non-MPT commitment, the storage proof format changes.
  This is not the case on Fuji today: live proofs are MPT.
- Fork-awareness (`feat/fork-aware-verifiers`) is not integrated.

## Live data

`npm run avalanche-live:refresh` captures from Fuji:
- the latest accepted C-Chain header (re-encoded in coreth's `HeaderSerializable` order and checked
  against its hash);
- the P-Chain height whose timestamp does not exceed the block's, with
  `platform.getValidatorsAt(height)` from the publicnode P-Chain API (the Ava Labs endpoint rejects
  numeric heights);
- the most recent earlier height whose set differs, found by binary search, for a real rotation;
- the validators' Warp signature from `glacier-api…/signatureAggregator/fuji/aggregateSignatures`,
  pinned to that height;
- `eth_getProof` for WAVAX at `settledHeight`, with the channel slots giving MPT exclusion proofs (no
  ClprService exists on Fuji).

It then writes `capture.json` and `vectors.json`. Rotation attestations come from test keys (anvil
accounts 0–2, 2-of-3), the one input the verifier trusts by design.

To verify:
- `forge test --match-path 'test/verifiers/evm/avalanche/*'`
- `npm run test:e2e:avalanche-live` (anvil, 13 cases)

## Avalanche-family chains

| Chain | Covered | Notes |
|---|---|---|
| Avalanche C-Chain mainnet / Fuji | yes | Fuji tested live, mainnet measured live (set, signer count) |
| Avalanche L1s on subnet-evm (ACP-77) | yes, same contract | subnet-evm signs block hashes with the same backend (`graft/subnet-evm/warp/verifier_backend.go`). Use the L1's `subnetID` set, `networkId` and blockchain id. 4-field accounts are accepted. |
| Flare / Songbird / Coston2 | likely, not tested live | See below |

**Flare has Warp.** The plan said it does not, but that is no longer true:
- go-flare v1.14.x (`flare-foundation/go-flare`, Jul 2026) carries avalanchego's full Warp stack.
  The coreth `acp118` handler is registered (`plugin/evm/vm.go`), and `verifier_backend.go` matches
  upstream.
- On live Flare and Coston2 RPCs, the Warp precompile `0x02…05` answers `getBlockchainID()`, so it is
  active.
- All 180 Flare and 8 Coston2 validators have BLS keys.
- Flare's one change is big.Int weights, which this verifier already handles.
- No live Flare signature was produced, because no public signature aggregator serves Flare and
  aggregating needs a node.
