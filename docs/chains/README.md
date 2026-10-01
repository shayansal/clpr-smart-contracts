# Chain pages

One page per chain added on this branch to the CometBFT-family verifiers. Family design, trust
model and gas are in [src/verifiers/evm/cometbft/README.md](../../src/verifiers/evm/cometbft/README.md)
and, for CosmWasm chains, [src/verifiers/evm/provenance/README.md](../../src/verifiers/evm/provenance/README.md).

| Chain | Verifier | Status | Page |
|---|---|---|---|
| Kava | `CometBftVerifier` | live-verified on mainnet (2026-10-01) | [kava.md](kava.md) |
| ZIGChain | `CosmWasmVerifier` | live-verified on mainnet (2026-10-01) | [zigchain.md](zigchain.md) |
| Stable | `CometBftVerifier` | in progress: profile and state layout confirmed live; no public CometBFT RPC for the commit | [stable.md](stable.md) |
| 0G | none yet (needs a new adapter) | in progress (blocked): EVM state in Reth's MPT; no public CometBFT RPC or node source | [0g.md](0g.md) |

The other chains of the family (Cronos, Mezo, MANTRA, Injective, Sei, Provenance, THORChain,
Polygon PoS, dYdX, Arc) are documented in the family README §1.
