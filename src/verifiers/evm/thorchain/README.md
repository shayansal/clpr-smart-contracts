# THORChain verifier (CosmWasm App Layer on CometBFT)

> **Contracts**: no THORChain-specific code. THORChain is a deploy-time profile of
> [CosmWasmVerifier](../provenance/CosmWasmVerifier.sol) +
> [CometBftCommitAccumulator](../cometbft/CometBftCommitAccumulator.sol) (shared base
> [CometBftStoreProofBase](../cometbft/CometBftStoreProofBase.sol)) ·
> Ed25519: [Ed25519Verifier](../sei/Ed25519Verifier.sol)
> **Design of the shared contracts**: [../provenance/README.md](../provenance/README.md)

A "THORChain → Hiero" verifier: CometBFT finality of a `thorchain-1` header (more than 2/3 of
the validators' power signed it) and an ICS-23 proof of the peer CLPR Service's storage in that
header's `app_hash`, read from THORChain's CosmWasm `wasm` store.

Everything below was checked against live `thorchain-1` (thornode 3.20.3, CometBFT 0.38.19) on
2026-10-01 and against the sources in §7.

## 1. Results on live mainnet

`npm run test:e2e:thorchain-live` replays `test/e2e/fixtures/thorchain-live/thorchain.json`:
the last churn `R = 27,914,371` (95 validators, signed by the old set, `next_validators_hash`
changes) and a current header `B = 28,052,921` (99 validators, signed by the new set), plus ABCI
proofs from a live App Layer contract, Rujira's swap router
`thor1n5a08r0z…cccnat2ska5t4g` (code 198, cw2 `rujira-thorchain-swap` 1.3.0). Gas is
`eth_estimateGas` (or `gasUsed` for `accumulate`) of the whole transaction.

| Transaction | Sigs | Gas | Calldata | ≤ 15M |
|---|---|---|---|---|
| Bundle at B with the commit inline (one tx) | 67 | 44,401,841 | 12.9 KB | **no** |
| `accumulate` R, batch 1 / 2 / 3 / 4 | 16 each | 11.26M / 11.10M / 11.11M / 11.11M | 5.7 KB | yes |
| **Bundle at R by header hash** (rotation: returns the new anchor) | 0 | **583,609** | 3.0 KB | yes |
| `accumulate` B, batch 1 / 2 / 3 / 4 | 17/17/17/16 | 11.91M / 11.77M / 11.78M / 11.14M | 6.0 KB | yes |
| **Bundle at B by header hash** (typical) | 0 | **583,234** | 3.0 KB | yes |
| Catch-up bundle at B, hop R, both by hash | 0 | 599,882 | 3.0 KB | yes |
| `verifyContractEntry` cw2 `contract_info` (existence) | 0 | 297,296 | 1.8 KB | yes |
| `verifyContractEntry` Map `vaults["avax-avax"]` (existence) | 0 | 304,337 | 1.8 KB | yes |

So a full THORChain bundle is **5 transactions**: 4 `accumulate` (~11-12M gas each, ~46.6M total)
and one ~0.58M-gas `verifyBundle` carrying the state proof. A validator-set rotation (churn) costs
exactly the same: it is an ordinary bundle at the churn header R, which returns the new anchor.

The bundle proves a **non-existence** of the CLPR queue record (no CLPR Service is deployed on
THORChain), so the IAVL proof has two neighbours; an existing record needs one path and is cheaper.

## 2. Why the commit must be split

All THORChain validators have voting power 100 (checked live at R and B), so power ordering does
not shrink the signer set: >2/3 needs 64 of 95 or 67 of 99 Ed25519 signatures. Hedera has no
Ed25519 precompile, and the pure-Solidity verifier costs ~640k gas per signature, so one commit is
~41-44M gas. `CometBftCommitAccumulator` verifies any subset per transaction and records signed
power per header hash; the verifier then reads the record (`HeaderRef{3 header_hash}`). Each
batch of ≤ 17 signatures fits 15M with ~3M to spare. Safety of the permissionless record is in
[../provenance/README.md §3](../provenance/README.md).

A SNARK of the commit (Groth16 over BN254, ~0.3-0.4M gas on Hedera) would collapse this to one
transaction; it is documented in [../cometbft/README.md §6.4](../cometbft/README.md), not built.

## 3. Which store a CLPR Service on THORChain would use

THORChain has two candidate homes for a CLPR Service:

| Option | Store / key | Who can deploy | Verdict |
|---|---|---|---|
| **CosmWasm App Layer** | IAVL store `wasm`, key `0x03 ‖ contract(32 B) ‖ contract key` (standard wasmd) | `MsgStoreCode` and `MsgInstantiateContract` only from the addresses compiled into thornode (`common/wasmpermissions/wasm_permissions_mainnet.go` at v3.20.3: 3 addresses may store code, all Rujira; 11 may instantiate, e.g. DAODAO, Levana, Nami) unless the mimir `MimirKeyWasmPermissionless` is set (it is **not** set live). A contract can instantiate further contracts without permission (`checkInstantiateAuthorization`), but code upload still needs a whitelisted sender | **Chosen.** Layout is plain wasmd, so `CosmWasmVerifier` works unchanged. Needs whitelisting (a thornode release, or a whitelisted deployer such as Rujira uploading the code) |
| Native thornode module | a new IAVL store or a key range in `thorchain` | a thornode release and node-operator upgrade | Same governance cost as the whitelist plus Go code in consensus; no benefit for the verifier |

**Live status (2026-10-01): the App Layer is globally halted.** Mimir `HALTWASMGLOBAL = 1`, and
`WasmMgr.checkGlobalHalt` blocks `StoreCode`, `Instantiate(2)`, `Execute`, `Migrate`, `Sudo` and
admin changes once the block height exceeds the mimir value. Contract **state** is still in the
`wasm` store and provable (this fixture), but no CLPR Service could be deployed or run on THORChain
until node operators lift the halt.

Store layout (thornode v3.20.3 → wasmd v0.54.0, cosmwasm-std / cw-storage-plus as in
[../provenance/README.md §4](../provenance/README.md)):

| What | Key in store `wasm` | Live proof in the fixture |
|---|---|---|
| Contract storage | `0x03 ‖ canonical address (32 B, BuildContractAddressClassic) ‖ key` | all three keys below |
| cw2 `Item("contract_info")` | `… ‖ "contract_info"` | `{"contract":"rujira-thorchain-swap","version":"1.3.0"}` |
| cw-storage-plus `Map("vaults")["avax-avax"]` | `… ‖ 0x0006 "vaults" ‖ "avax-avax"` | `"thor13etu2zrd…"` |
| CLPR queue record (README §4 of provenance) | `… ‖ 0x000a "clpr_queue" ‖ channelId` | absent (non-existence) |

The CLPR Service contract sketched in [../provenance/README.md §8](../provenance/README.md)
applies unchanged; it must write the 90-byte queue record and the `clpr_service` item.

## 4. Profile

```
CometBftCommitAccumulator("thorchain-1", KeyScheme.ED25519, Ed25519Verifier)
CosmWasmVerifier.Profile{accumulator, storeKey: "wasm",
                         bootstrapValidatorsHash: <set hash at a recent churn>, bootstrapHeight}
```

## 5. Trust assumptions and limits

- **Honest supermajority** of the THORChain validator set, as in every CometBFT verifier here.
- **Rotation = churn.** `validators_hash` changes only at churns (equal power, so no
  delegation-driven rotations), every `CHURNINTERVAL = 43200` blocks (~3 days) plus
  ad-hoc churn-outs. Relays must bundle at every churn header R (5 transactions, §1). A churned-out
  node can withdraw its bond, so an old set may have nothing at stake: a relay that misses a churn should
  catch up promptly with hops (the by-hash catch-up above, 0.6M gas plus the accumulations).
- **No Ed25519 precompile on Hedera**: 4 extra transactions per bundle, ~46.6M gas total.
- **App Layer halt and whitelist** (§3) gate deployment, not verification.
- **History**: the public node (`gateway.liquify.com`) serves ABCI proofs at the June 2026 churn,
  so it keeps full history. Other public endpoints (ninerealms, publicnode) did not answer on
  2026-10-01.

## 6. Tests

- `test/e2e/tests/verifiers/thorchain-live.spec.ts` (7 tests, live fixture): inline commit too
  big, rotation over 4 accumulate transactions, typical bundle and catch-up by hash, two real
  contract entries; negatives for a replayed batch (`NoNewSignatures`), a flipped signature byte
  (`InvalidSignature`), not-yet-finalized header (`NotFinalized`), wrong set, stale anchor,
  another channel, tampered IAVL proof.
- Contract-level tests are the CosmWasmVerifier suites (`test/verifiers/evm/provenance/`,
  `test/verifiers/compliance/CosmWasmComplianceTest.t.sol`).

```bash
forge build && npm run test:e2e:thorchain-live   # CLPR_ANVIL_PORT_A, default 8601
npm run thorchain-live:refresh                    # re-record (last churn + current header)
```

## 7. Sources checked

- thornode **v3.20.3** (the live version): `go.mod` (wasmd v0.54.0, cosmos-sdk v0.53.0, cometbft
  v0.38.21, iavl v1.2.8), `x/thorchain/manager_wasm_current.go` (`checkGlobalHalt`,
  `checkCanStore`, `checkInstantiateAuthorization`), `common/wasmpermissions/`, `app/app.go`
  (`wasmtypes.StoreKey` mounted).
- CosmWasm/wasmd **v0.54.0** `x/wasm/types/keys.go` (`ContractStorePrefix = 0x03`),
  `x/wasm/keeper/addresses.go` (`BuildContractAddressClassic`, 32 B).
- Live: `https://gateway.liquify.com/chain/thorchain_rpc` (status, commit, validators, blockchain,
  `abci_query /store/wasm/key?prove=true`) and `…/thorchain_api` (mimir, asgard vaults, wasm codes,
  contracts and state).
