# dYdX verifier (native `x/clpr` module on CometBFT)

> **Source**: [CosmosModuleVerifier.sol](./CosmosModuleVerifier.sol) (extends
> [CosmWasmVerifier](../provenance/CosmWasmVerifier.sol)) ·
> [CometBftCommitAccumulator](../cometbft/CometBftCommitAccumulator.sol) ·
> Ed25519: [Ed25519Verifier](../sei/Ed25519Verifier.sol) ·
> peer module: [modules/x-clpr](../../../../modules/x-clpr/README.md)
> **Interface**: [IClprVerifier.sol](../../../interfaces/IClprVerifier.sol)

A "dYdX → Hiero" verifier. dYdX v4 has no contract runtime (no `wasm` store, no EVM), so its CLPR
Service has to be a **native Cosmos SDK module**. This directory is the Hiero half of that
prototype; `modules/x-clpr` is the Go half. The verifier checks (1) CometBFT finality of a header
(more than 2/3 of the validator set's power signed it) and (2) the module's queue record in its own
IAVL store `clpr`, under that header's `app_hash`.

It is `CosmWasmVerifier` with a different key layout. The light client, accumulator, multistore and
IAVL checks, queue-record codec and manifest binding are the same code. Any CometBFT + Cosmos SDK
chain that adds `x/clpr` uses the same contract with its own profile.

## 1. Results

`npm run test:e2e:dydx-xclpr` replays `test/e2e/fixtures/dydx-xclpr/`. Gas is `eth_estimateGas` of
the whole transaction.

| What | Data | Sigs | Gas | Calldata | ≤ 15M |
|---|---|---|---|---|---|
| `verifyBundle`: commit + `clpr` multistore + queue record + service item + manifest, 3 messages | **real x/clpr localnet** | 1 | **1,051,913** | 2.0 KB | yes |
| `verifyQueueMessage`: one queued entry `0x02‖channel‖id` | real x/clpr localnet | 1 | 970,308 | 1.5 KB | yes |
| `verifyModuleEntry`: bank supply `0x00‖"adydx"` in store `bank` | **live dydx-mainnet-1** (21 validators) | 10 | **7,033,228** | 3.8 KB | yes |

The localnet is a one-validator chain built on dYdX v9.7.1's own cosmos-sdk, store, IAVL and
CometBFT forks (`modules/x-clpr/go.mod`). It recorded a channel, three Data Messages and a manifest
update sent by real transactions. The spec checks the proven record against the running hash
`ClprService` (BundleLib Step 5) recomputes from the delivered payloads.

The mainnet row uses the same contract with storeKey `bank`, because dYdX has no `clpr` store
yet. It shows that dYdX's live multistore and IAVL proofs (its forked IAVL v1.1.1) and its 10-of-21
Ed25519 commit go through the pipeline the module relies on. **Estimated dYdX mainnet bundle once
`x/clpr` exists:** 7.03M (commit + one entry, measured) + ~0.1M for the service item and payloads
(the localnet difference) ≈ **7.1–7.2M gas**, within 15M with ~7.8M to spare. A rotation bundle
costs the same (CometBFT README §6.3). A catch-up across a rotation (two 10-signature commits,
≈14M) is near the limit, so the relay should use the accumulator split for that case
(Provenance README §3). No rotation appeared in 1,000 sampled mainnet blocks (~10 min); dYdX now
runs 21 validators (gov proposal 396).

Contract sizes: `CosmosModuleVerifier` 16,163 B, `CometBftCommitAccumulator` 13,104 B (EIP-170:
24,576 B).

## 2. Store layout (fixed by this verifier)

Source: `modules/x-clpr/x/clpr/types/keys.go`. Store key `clpr` (profile).

| Key | Value | Proven by |
|---|---|---|
| `0x01 ‖ channel_id(32)` | Queue record, 90 B: `0x01 ‖ status u8 ‖ next_message_id u64 ‖ received_message_id u64 ‖ endpoint_manifest_version u64 ‖ sent_running_hash ‖ received_running_hash` (big-endian). Byte-identical to the CosmWasm record | `verifyBundle` (existence → metadata, absence → zeros) |
| `0x02 ‖ channel_id(32) ‖ message_id u64 BE` | `ClprMessageValue{1 payload, 2 running_hash_after_processing}`. `payload` is the exact serialized `ClprMessagePayload` that entered the running hash | `verifyQueueMessage` |
| `0x03` | Service item: module address(20) ‖ `keccak256(ClprEndpointManifest)` (zero if unset) | `verifyBundle` (manifest), `verifyConfig` |
| `0x04 ‖ channel_id`, `0x05` | Local channel bookkeeping and params (not proven) | — |

- **Service address** = the module account, `sha256("clpr")[:20]` =
  `a88f550db4433c59b3322bca3a2c233cfdd69adc` (`authtypes.NewModuleAddress`). The native store has
  only one service, so the address is not in the record key. The service item binds it instead,
  and the configured address must equal its first 20 bytes. Other lengths revert
  `InvalidServiceAddressLength`.
- Every key is fixed-length within its prefix, so ICS-23 non-existence proofs (two neighbours) work
  for any absent channel or message id.
- **Running hash** is BundleLib's `h' = sha256(h ‖ sha256(payload))`. The spec text (§4.1) says
  `sha256(h ‖ payload)`; the module follows the Solidity reference because the Hiero-side
  ClprService recomputes that form. Flag for the spec.
- **Payload encoding**: gogoproto's canonical encoding of the spec messages equals
  `ClprProtobuf.encodeDataMessage`. A golden vector from the localnet is checked in both Go
  (`keeper_test.go`) and Solidity (`test_golden_payloadEncodingAndRunningHash`).

## 3. Verification chain

As `CosmWasmVerifier` (Provenance README §2), with three changes: the queue key is
`0x01 ‖ ctx.channelId`, the service key is `0x03`, and addresses are 20 bytes. Two entry points
are added:

- `verifyQueueMessage(proof, anchor, channelId, messageId) → (payload, runningHashAfter, height)`
  requires existence.
- `verifyModuleEntry(proof, anchor, key) → (exists, value, height)` proves any raw key of the
  profile's store. The inherited `verifyContractEntry` assumes wasmd's `0x03 ‖ contract ‖ key`
  prefix and does not apply to this layout.

## 4. Trust assumptions and limits

- Honest supermajority, unbonding period (dYdX: 21 days, `1814400s`, live staking params),
  bootstrap checkpoint, replay handling: as in [CometBFT README §5](../cometbft/README.md).
- **Module upgrades.** A native module changes only through a chain software upgrade (x/gov on
  dYdX), so there is no admin key to migrate it. Its storage layout is consensus code, and a layout
  change needs a store migration plus a verifier redeploy (ClprService pins verifiers per channel).
- **Prototype scope on the Go side** (modules/x-clpr README §5): channels open ACTIVE without the
  commit-reveal and `verifyConfig` steps. There are no connectors, fees or slashing yet, and no inbound
  `submit_bundle`, so `received_message_id` and `received_running_hash` stay 0. The verifier
  already decodes them.
- Ed25519 dominates gas: ~640k per signature (CometBFT README §6.1).

## 5. Tests

- `test/verifiers/evm/dydx/CosmosModuleVerifier.t.sol`: 16 tests on a synthetic chain with a real
  IAVL-shaped `clpr` store and real secp256k1 signatures. They cover the layout and golden vectors
  from the Go module (key bytes, payload encoding, running hash, a real record), absent records,
  rotation with a manifest, queue-entry existence and absence, and `verifyConfig`. Negatives: bad
  signature, below threshold, wrong set, stale header, CosmWasm-layout keys, another channel,
  32-byte address, another service address, malformed or absent message, wrong message id, wrong
  store key.
- `test/verifiers/compliance/CosmosModuleComplianceTest.t.sol`: the shared `IClprVerifier` suite
  (21 cases).
- `test/e2e/tests/verifiers/dydx-xclpr.spec.ts`: 7 tests on the recorded data (table in §1), with
  negatives for another channel, a tampered record, a tampered IAVL proof, a wrong manifest, a
  32-byte address, a bad signature, a wrong set, a stale header and a wrong store key.

```bash
forge test --match-path 'test/verifiers/evm/dydx/*'
forge build && npm run test:e2e:dydx-xclpr            # CLPR_ANVIL_PORT_A, default 8601
# re-record: start modules/x-clpr localnet + scripts/send-demo.sh, then
npm run dydx-xclpr:refresh [localnet|mainnet]
```
