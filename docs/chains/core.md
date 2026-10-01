# Core → Hiero

Status: family-covered. Headers and a vote attestation were checked live; no full bundle was run.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `1116` / `eip155:1116` |
| Chain type | L1, Satoshi Plus consensus (`consensus/satoshi`), which keeps Parlia's header and vote formats |
| Finality source | BLS vote attestation of at least 2/3 of the validator set |
| Verifier | `BscParliaVerifier` ([family README](../../src/verifiers/evm/bsc/README.md)), no code change |
| Trust tier | Fewer than 1/3 of each validator set malicious; bootstrap epoch block trusted |
| Typical bundle | Not measured on Core |
| Rotation | Not measured on Core |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | 1116 | Live headers, checked by the capture code (family README, "Parlia-family chains") |
| `epochLength` | 200 | Live epoch blocks |
| Validators | 20 | Live epoch block |
| `turnLength` | 1 | Live epoch block |
| Bootstrap epoch block | Not chosen yet | Pick a recent epoch block at deployment |
| ClprService code hash | Not deployed yet | `eth_getProof` at deployment |

## Relayer requirements

- Same RPC methods as BNB Smart Chain: `eth_chainId`, `eth_getBlockByNumber`, `eth_getProof`.
- `eth_getProof` support on Core RPCs was not checked.
- One rotation per 200-block epoch of absence (BSC uses 1000-block epochs).

## Chain-specific trust and caveats

- `consensus/satoshi` uses Parlia's `extraData` layout, `minerHistoryCheckLen` and `updateAttestation` unchanged
  (coredao-org/core-chain commit `06a3e0a`).
- The verifier does not check how Core elects its validators, only that each epoch block is finalized by the
  previous set.
- The check verified header hashes, the chain-id seal, the epoch layout and an 18 of 20 BLS attestation.

## Live verification

No fixture is committed for Core. A full live run needs a capture with `eth_getProof` from a Core RPC.

## Hiero → Core

Not built. It would use the reference Hiero verifier on Core's EVM and is blocked on the same Hiero proof source as
Hiero → Ethereum.
