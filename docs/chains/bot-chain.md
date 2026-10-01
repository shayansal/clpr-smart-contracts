# BOT Chain → Hiero

Status: family-covered. Headers and a vote attestation were checked live; no full bundle was run.

## Quick facts

| Item | Value |
|---|---|
| Chain id / CAIP-2 | `677` / `eip155:677` |
| Chain type | L1, BSC-derived client (Geth v1.5.13 fork) running Parlia with fast finality |
| Finality source | BLS vote attestation of at least 2/3 of the validator set |
| Verifier | `BscParliaVerifier` ([family README](../../src/verifiers/evm/bsc/README.md)), no code change |
| Trust tier | Fewer than 1/3 of each validator set malicious; bootstrap epoch block trusted. With 7 validators, 3 colluding validators are enough to block finality and 5 to forge it |
| Typical bundle | Not measured on BOT Chain |
| Rotation | Not measured on BOT Chain |

## Deployment profile

| Parameter | Value | Source |
|---|---|---|
| `chainId` | 677 | Live headers, checked by the capture code (family README, "Parlia-family chains") |
| `epochLength` | 1000 | Live epoch blocks |
| Validators | 7 | Live epoch block |
| `turnLength` | 16 | Live epoch block |
| Bootstrap epoch block | Not chosen yet | Pick a recent epoch block at deployment |
| ClprService code hash | Not deployed yet | `eth_getProof` at deployment |

## Relayer requirements

- Same RPC methods as BNB Smart Chain: `eth_chainId`, `eth_getBlockByNumber`, `eth_getProof`.
- `eth_getProof` support on BOT Chain RPCs was not checked.
- One rotation per 1000-block epoch of absence.

## Chain-specific trust and caveats

- The set is small (7 validators). The quorum is `ceil(2 x 7 / 3) = 5` votes.
- The check verified header hashes, the chain-id seal, the epoch layout and a 7 of 7 BLS attestation.

## Live verification

No fixture is committed for BOT Chain. A full live run needs a capture with `eth_getProof` from a BOT Chain RPC.

## Hiero → BOT Chain

Not built. It would use the reference Hiero verifier on BOT Chain's EVM and is blocked on the same Hiero proof
source as Hiero → Ethereum.
