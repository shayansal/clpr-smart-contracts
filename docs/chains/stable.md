# Stable → Hiero

Status: in progress. Stable is assigned to the CometBFT family (`CometBftVerifier`, EVM store) in
the ranks 51–100 sweep. Its profile, fixture and source checks are not recorded yet, so this page
has no measured numbers.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | not recorded yet |
| Chain type | L1 on CometBFT with an EVM (to be confirmed against the chain's source) |
| Finality source | CometBFT commit: > 2/3 of voting power (to be confirmed) |
| Verifier | `CometBftVerifier` ([family README](../../src/verifiers/evm/cometbft/README.md)) |
| Trust tier | Family baseline: honest 2/3 of each validator set the anchor reaches; bootstrap checkpoint; anchor kept inside the unbonding period |
| Typical bundle | not measured |
| Rotation | not measured |

## Deployment profile

Every value below must be read from Stable's source and live RPC before deployment.

| Parameter | Value | Where to read it |
|---|---|---|
| `chainId` | not recorded | `/status`, header `chain_id` |
| `storeKey` | not recorded | the EVM module's `StoreKey` |
| `evmStateKeyPrefix` | not recorded | the EVM module's storage key prefix; confirm by comparing an IAVL value with `eth_getStorageAt` at the same height |
| `keyScheme` | not recorded | `/validators` key type |
| `ed25519Verifier` | required if the key scheme is Ed25519 | `src/verifiers/evm/sei/Ed25519Verifier.sol` |
| `bootstrapValidatorsHash`, `bootstrapHeight` | chosen at deployment | `/commit?height=…` |

## Relayer requirements

- RPC methods (family baseline): `/status`, `/commit`, `/validators`,
  `abci_query /store/<evm store>/key?prove=true` at `H-1`, `/blockchain` to find rotations.
- To confirm: how far back public nodes serve ABCI proofs, and how often the validator set changes.

## Chain-specific trust and caveats

Not assessed yet. The two questions that decide fit are the number of signatures needed for > 2/3
by power (about 18 Ed25519 signatures fit one bundle, family README §7) and how often the set hash
changes (family README §6).

## Live verification

None yet. Once the profile is known: add an entry to `test/e2e/relay/buildCometBftLiveFixture.ts`,
run `npm run cometbft-live:refresh stable`, and replay with `npm run test:e2e:cometbft-live`.

## Hiero → Stable

Not built. It waits on the Hiero proof source, like every Hiero → chain direction.
