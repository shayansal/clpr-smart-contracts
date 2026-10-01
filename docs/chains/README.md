# Chain pages

One page per chain served by the CometBFT-family verifiers on this branch. Family design, trust
model and gas are in the verifier READMEs under `src/verifiers/evm/`.

| Chain | Verifier | Status | Page |
|---|---|---|---|
| Cronos | `CometBftVerifier` | live-verified on mainnet (2026-10-01) | [cronos.md](cronos.md) |
| Mezo | `CometBftVerifier` | live-verified on mainnet (2026-10-01) | [mezo.md](mezo.md) |
| MANTRA | `CometBftVerifier` | live-verified on mainnet (2026-10-01); fixture on `feat/rwaprofiles-verifier` | [mantra.md](mantra.md) |
| Injective | `CometBftVerifier` | live-verified on mainnet (2026-10-01); fixture on `feat/rwaprofiles-verifier` | [injective.md](injective.md) |
| Sei | `SeiCometBftVerifier`; `CometBftVerifier` by profile | family-covered | [sei.md](sei.md) |
| Stable | `CometBftVerifier` | in progress | [stable.md](stable.md) |
| Kava | `CometBftVerifier` | in progress | [kava.md](kava.md) |
| 0G | `CometBftVerifier` | in progress | [0g.md](0g.md) |
| Provenance | `CosmWasmVerifier` | live-verified on mainnet (2026-10-01) | [provenance.md](provenance.md) |
| THORChain | `CosmWasmVerifier` | live-verified on mainnet (2026-10-01) | [thorchain.md](thorchain.md) |
| Polygon PoS | `PolygonPosVerifier` | live-verified on mainnet (2026-10-01) | [polygon-pos.md](polygon-pos.md) |

dYdX (`CosmosModuleVerifier` with the native `x/clpr` module) has its page on branch
`feat/dydx-xclpr` (`docs/chains/dydx.md`).
