# Chain pages

One page per source chain covered on this branch. Each page lists the chain's deployment profile, relayer needs,
chain-specific trust notes and how its live data was verified. The shared design, trust model, proof format and
upgrade notes are in the family README:
[Substrate verifiers: GRANDPA and BEEFY](../../src/verifiers/evm/grandpa/README.md).

| Chain | Status | Page |
|---|---|---|
| Bittensor | live-verified on Bittensor mainnet (finney) (2026-10-01) | [bittensor.md](./bittensor.md) |
| Hydration | live-verified on Polkadot + Hydration mainnet (2026-10-01) | [hydration.md](./hydration.md) |

Dates are fixture capture timestamps. "Live-verified" means live mainnet data replayed through the unmodified
verifier on anvil; no ClprService is deployed on these chains yet.
