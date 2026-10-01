# Ethereum-derived beacon chains: Gnosis Chain and PulseChain

`EthBeaconTwinVerifier` is `EthMainnetVerifier` with the chain parameters fixed per deployment. It
verifies Gnosis Chain, Gnosis Chiado, PulseChain and PulseChain testnet v4 toward Hiero. The light
client, the BLS checks (EIP-2537), the SSZ and MPT proofs, and the trust-anchor and bundle formats are
unchanged. No logic is forked. `EthMainnetVerifier` gained four `internal virtual` hooks (Ethereum
defaults, bytecode 19,216 B, down from 19,338 B), and the twin overrides them from immutables.

| Parameter | Hook | Gnosis / Chiado | PulseChain / testnet v4 | Ethereum |
|---|---|---|---|---|
| genesis validators root | `_checkChainIdentity` (verifyConfig) | `0xf5dc…9d47` / `0x9d64…4c1e` | `0x3357…0c90` / `0xd816…4e64` | any (not pinned) |
| fork version (signing domain) | `_checkChainIdentity` | `0x06000064` / `0x0600006f` (Fulu) | `0x0000036c` / `0x00000946` (Capella) | any |
| SLOTS_PER_EPOCH × EPOCHS_PER_SYNC_COMMITTEE_PERIOD | `_slotsPerSyncCommitteePeriod` | 16 × 512 = 8192 | 32 × 256 = 8192 | 32 × 256 |
| `execution_payload.state_root` in `BeaconBlockBody` | `_executionStateRootGindex` | 802 (depth 9) | **402 (depth 8)** | 802 |
| `next_sync_committee` in `BeaconState` | `_nextSyncCommitteeGindex` | 87 (depth 6) | **55 (depth 5)** | 87 |

Presets: `EthTwinPresets.{gnosis,chiado,pulsechain,pulsechainTestnetV4}()`. Every value was read from
the chains' public beacon APIs on 2026-10-01 (`/eth/v1/beacon/genesis`, `/eth/v1/config/spec`,
`/eth/v1/config/fork_schedule`). The gindices were checked against live data:

- **Gnosis and Chiado (Fulu)**: the public Lighthouse v8.2.2 nodes serve the light-client API. The
  `execution_branch` (gindex 25) composed with the 17-field ExecutionPayloadHeader folds to `body_root`
  at 802. `next_sync_committee_branch` folds to the attested `state_root` at 87.
- **PulseChain (Capella, no Deneb scheduled: `DENEB_FORK_EPOCH` = 2^64−1)**: the 18 MB SSZ
  `BeaconState` was re-merkleized with a vanilla Capella schema (28 fields) and hashes to the header's
  `state_root`. `next_sync_committee` is field 23 of 32 leaves, so gindex 55. The SSZ `BeaconBlockBody`
  (11 fields) hashes to `body_root`. `execution_payload` (gindex 25) × the 15-field payload
  (`state_root` gindex 18) gives 402.

Slot timing affects only the anchor id (the period) and how often a rotation is due. Gnosis has 5 s
slots, so a period lasts about 11.4 h. PulseChain has 10 s slots, so a period lasts about 22.8 h.
Ethereum's period is about 27.3 h. The verifier itself reads no timestamps.

## Do the chains have sync committees and light-client APIs?

| | Sync committee | Light-client API (public nodes) | EVM (for the reverse leg, Hiero → chain) |
|---|---|---|---|
| Gnosis / Chiado | yes: 512 members, Altair at epochs 512 / 90 | yes (`gnosis-beacon-api.publicnode.com`, `rpc-gbc.gnosischain.com`, `rpc-gbc.chiadochain.net`; publicnode's Teku for Chiado has none) | Osaka level: EIP-2537 present (G1ADD on two infinity points returns 128 zero bytes), and MCOPY, TSTORE and CLZ work |
| PulseChain / testnet v4 | yes: 512 members, Altair at epoch 1, about 98% participation in the captures (502/512, 500/512) | **no**: Lighthouse-Pulse v2.5.1 answers 404 on every `/eth/v1/beacon/light_client/*` route. `debug/beacon/states` and `beacon/blocks` are served as SSZ | **Shanghai level, see below** |

### What PulseChain lacks

Toward Hiero, nothing is missing. The verifier runs on Hedera, and the sync-committee data exists on
PulseChain.

The relayer has more work. With no light-client server, each bundle needs the full state at the
attested slot (about 18 MB, roughly 1.4 s to merkleize). `test/e2e/relay/buildEthTwinsLiveProof.ts`
does this. A self-hosted node with a light-client server would avoid it, but whether Lighthouse-Pulse
can enable one was not checked.

The reverse leg (Hiero → PulseChain) would need contracts deployed on PulseChain. Its EVM is erigon
2.4.1 at Shanghai level. These checks were run with `eth_call` against `rpc.pulsechain.com` and
`rpc.v4.testnet.pulsechain.com`:
- **No EIP-2537.** A call to `0x0b` with 256 zero bytes returns empty output, and
  `eth_getCode(0x0d)` is empty. `TSSVerifier` needs `0x0c`, `0x0d`, `0x0e`, `0x0f` and `0x11`.
- **No Cancun opcodes.** MCOPY, TSTORE and BLOBHASH each fail with "invalid opcode". The repo compiles
  for `evm_version = "osaka"`. `TSSVerifier` and `EthMainnetVerifier` use `mcopy`, and `ClprService`
  uses transient-storage reentrancy guards.
- **No Osaka.** CLZ (0x1e) fails with "opcode not defined". The KZG precompile 0x0a is absent.
- **Present:** PUSH0 (Shanghai), the BN254 precompiles 0x06–0x08 (which WRAPS uses) and `eth_getProof`.

So a Hiero → PulseChain verifier would need a BLS12-381 implementation in plain EVM code, which is
gas-prohibitive, or a SNARK wrapper over BN254. It would also need the contracts rebuilt for Shanghai.

## Trust assumptions and limits

These are the same as `EthMainnetVerifier`; see `../ethereum/README.md`.

- **Finality.** A bundle is trusted when 2/3 of the 512-member sync committee signs the attested
  header. The verifier does not prove finality. On PulseChain the committee is drawn from a smaller,
  PLS-staked validator set, which gives a lower economic security bound than Ethereum's.
- **Genesis anchor.** The first committee comes from `verifyConfig` (trust on first use). The twin
  only pins the GVR and fork version, so a channel cannot be set up with another chain's identity.
- **Hard forks.** The anchor carries one fork version through every rotation. A fork that changes the
  fork version needs a new deployment and a reconfigured channel. A fork that changes either gindex
  needs the same, for example Gnosis Electra → Fulu kept 802/87, but PulseChain moving to Deneb would
  give 802/55 and Electra 802/87. Gloas (ePBS) moves the execution payload out of the body, which
  breaks the execution branch for every member of this family. The fork-aware standard
  (`feat/fork-aware-verifiers`) is the general fix.
- **Rotations.** One rotation bundle is needed per period. On Gnosis the light-client update for a
  period is usually older than the public RPCs' `eth_getProof` window (about 128 blocks on publicnode,
  under 40 on Tenderly and gateway.fm). Unless the relayer has an archive RPC, the rotation must be
  proven from a recent attested header. On PulseChain the capture takes `next_sync_committee` from the
  same recent state, so every bundle can rotate.
- **Replay.** The verifier is stateless. An old bundle verifies again against the same anchor, and
  ClprService's message ids and running hashes reject it. After a rotation the old committee's bundles
  fail (test: `test_rejectsStaleCommitteeAfterRotation`).
- **Malformed points.** A corrupted G2 signature makes the EIP-2537 precompile fail. A failing
  precompile consumes the gas forwarded to it (`BlsPrecompileCallFailed`). This is inherited
  behaviour, and the relayer pays for it.

## Gas and calldata (live data, anvil `eth_estimateGas`; Hedera: 15M gas, 128 KB calldata)

| Bundle | Participation | proofBytes | Calldata | Gas (total) |
|---|---|---|---|---|
| Gnosis, typical | 494/512 | 22.5 KB | 23.1 KB | 1,934,671 |
| Chiado, typical | 452/512 | 43.6 KB | 44.2 KB | 2,926,126 |
| PulseChain, typical | 502/512 | 11.9 KB | 12.5 KB | 1,320,015 |
| PulseChain testnet, typical | 500/512 | 12.5 KB | 13.1 KB | 1,326,191 |
| PulseChain, **rotation bundle** (typical + 512 next keys) | 502/512 | 78.7 KB | 79.3 KB | 6,195,813 |
| PulseChain testnet, rotation bundle | 500/512 | 79.4 KB | 80.0 KB | 6,202,941 |
| Gnosis / Chiado `_verifyRotation` alone (harness) | n/a | 66.9 KB rotation items | n/a | 4,836,051 |

A Gnosis rotation bundle is therefore about 1.93M + 4.8M, roughly 6.8M gas and 90 KB. Every case is
inside both Hedera limits. Calldata grows with non-signers: 416 B per non-signer key plus its proof.
The worst case at the 2/3 threshold has 170 non-signers, about 71 KB extra, which a rotation bundle
cannot also carry within 128 KB. The relayer should rotate with a well-signed header. The Ethereum
bundle measured on Hedera testnet used 1,645,052 gas, in line with these anvil numbers.

## Files and commands

- `EthBeaconTwinVerifier.sol`, `EthTwinPresets.sol`: the verifier and the per-chain parameters.
- `test/verifiers/evm/ethtwins/EthBeaconTwinVerifier.t.sol`: 23 Foundry tests on the real Gnosis
  and PulseChain fixtures (`fixtures/*.json`):
  - happy paths: bundle, rotation bundle, Gnosis rotation, and a `verifyConfig` with the live
    committee that reproduces the anchor;
  - negative cases: bad signature, wrong fork version, below threshold (341/512), wrong validator set,
    stale committee after rotation, cross-chain replay, wrong chain identity in config, Capella and
    Electra layouts swapped, wrong execution root, wrong account and storage proofs, another channel,
    and a wrong code hash.
- `test/e2e/fixtures/ethtwins-live/{gnosis,chiado,pulsechain,pulsechain-testnet}.json`: the raw
  captures.
- `test/e2e/relay/buildEthTwinsLiveProof.ts`: the capture and refresh script. It runs either through
  the light-client API or from SSZ state via `test/e2e/relay/ssz.ts`.
- `test/e2e/tests/verifiers/ethtwins-live.spec.ts`: the vitest spec. It deploys one verifier per
  network on anvil and replays all four captures.

```
npm run ethtwins-live:refresh                  # re-capture all four networks (+ Foundry fixtures)
forge build && npm run test:e2e:ethtwins-live  # vitest on anvil (CLPR_ANVIL_PORT_A, default 8611)
forge test --match-path 'test/verifiers/evm/ethtwins/*'
```

The bundles prove each chain's beacon deposit contract (real code and storage). The channel slots are
empty there, so the storage step runs on genuine MPT exclusion proofs. No ClprService is deployed on
these chains yet.
