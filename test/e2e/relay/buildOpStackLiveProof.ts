import {existsSync, mkdirSync, readdirSync, readFileSync, unlinkSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {decodeAbiParameters, encodeFunctionData, keccak256, toHex, type Hex} from "viem";
import {deriveChannelSlots, encodeEthTrustAnchor, type EthGetProofResult} from "./buildEthMainnetProof.js";
import {
    buildLiveLightClient,
    captureBeaconLive,
    DEFAULT_BEACON_APIS,
    DEFAULT_EXECUTION_RPC,
    getJson,
    rpc as rpcOnce,
    type BeaconCapture,
    type LiveLightClient
} from "./buildEthLiveProof.js";
import {
    accountNodes,
    asrSlots,
    BASE_SEPOLIA_LAYOUT,
    dgfGameSlot,
    encodeOpStackBundle,
    encodeOpStackL2StateRootProof,
    GAME_STATUS,
    gameUuid,
    MODE,
    OP_SUCCINCT_LITE_LAYOUT,
    outputRootPreimage,
    ROOT_FORMAT,
    slotHex,
    storageEntries,
    type DisputeProofParts,
    type OpStackLayout,
    type OpStackProfile
} from "./opstack.js";
import {stageLatestL2Proof} from "./stageLatestL2Proof.js";

/// Live-data proof builder for the OP Stack verifiers. One code path, one chain config per network:
///   - `base-sepolia`: Base Sepolia settling on Ethereum Sepolia (AggregateVerifier, game type 621);
///   - `xlayer`: X Layer (chain 196) settling on Ethereum mainnet (OP Succinct Lite, game type 42).
///
/// Chain of real data:
///   L1 sync committee (finality_update, bootstrap) → attested execution block B
///   → eth_getProof at B of the chain's AnchorStateRegistry (+ its implementation), the
///     DisputeGameFactory `_disputeGames[uuid]` entries and each dispute game's state slots (+ code)
///   → the game's root claim == keccak(0 ‖ L2 stateRoot ‖ withdrawalsRoot ‖ L2 blockHash) of the L2
///     block it claims (since Isthmus the header's withdrawalsRoot is the L2ToL1MessagePasser storage
///     root, so the preimage comes straight from the L2 header)
///   → eth_getProof on the L2 at that block (ClprService stand-in: the L2ToL1MessagePasser predeploy,
///     whose real code hash is pinned; the channel slots are absent → exclusion proofs).
///
/// Which games the fixture carries:
///   - `anchor`   ASR.anchorGame: ANCHOR mode and GAME mode (it is a resolved DEFENDER_WINS game).
///                Its L2 block is ≥ the chain's proof-maturity age (days), outside every public RPC's
///                eth_getProof window, so its L2 account proof is usually absent and the FINALIZED path
///                is checked on-chain up to the L2 state root (`verifyL2StateRoot`).
///   - `newest`   the newest DGF game of the respected type at B (IN_PROGRESS): full `verifyBundle`
///                through the PROPOSED tier when its L2 proof is available; FINALIZED rejects it.
///   - `resolved` (optional) the newest resolved DEFENDER_WINS game still inside the finality delay:
///                FINALIZED rejects it with GameNotFinalized.
///   - `pending`  games whose L2 proofs an EARLIER run staged while they were recent: full FINALIZED
///                `verifyBundle` once they have finalized.
///
/// L2 proof sources. Base Sepolia's public RPC serves eth_getProof ~5,000 blocks back, so a refresh
/// stages its newest game. X Layer's only public eth_getProof endpoint (dRPC → reth with a proof window
/// of 0) answers for "latest" only; `--stage-next` waits for the block the proposer's next game will
/// claim (its proposals are every `interval` L2 blocks) and keeps the "latest" proof whose root is that
/// block's state root (stageLatestL2Proof.ts). The game itself appears on L1 ~30 min later.
///
/// CLI:
///   npx tsx test/e2e/relay/buildOpStackLiveProof.ts [--chain xlayer]            build from the fixture
///   npx tsx test/e2e/relay/buildOpStackLiveProof.ts [--chain xlayer] --refresh [--wait-nonsigners SECS]
///   npx tsx test/e2e/relay/buildOpStackLiveProof.ts --chain xlayer --stage-next [COUNT]
///   npx tsx test/e2e/relay/buildOpStackLiveProof.ts --chain xlayer --export-forge   rewrite the Foundry fixture

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface OpStackLiveChain {
    name: string;
    l2ChainId: number;
    optimismPortal: Hex;
    anchorStateRegistry: Hex;
    /// Headers, and eth_getProof at a block number.
    l2Rpcs: string[];
    /// eth_getProof at "latest" only (staged ahead of the game, see `--stage-next`).
    l2LatestProofRpcs: string[];
    layout: OpStackLayout;
    fixtureDir: string;
    channelId: Hex;
    beaconApis?: string[];
    l1Rpc?: string;
    /// Compact replay inputs for a Foundry test, written on every refresh (and by `--export-forge`).
    forgeFixture?: string;
}

export const BASE_SEPOLIA_FIXTURE_DIR = path.resolve(__dirname, "../fixtures/base-sepolia-live");
export const BASE_SEPOLIA_LIVE_FIXTURE = path.join(BASE_SEPOLIA_FIXTURE_DIR, "capture.json");
export const OPSTACK_LIVE_CHANNEL_ID: Hex = keccak256(toHex("clpr/opstack-live/base-sepolia"));

/// Base Sepolia (Superchain registry, chain 84532) on Ethereum Sepolia.
export const BASE_SEPOLIA: OpStackLiveChain = {
    name: "base-sepolia",
    l2ChainId: 84532,
    optimismPortal: "0x49f53e41452C74589E85cA1677426Ba426459e85",
    anchorStateRegistry: "0x2fF5cC82dBf333Ea30D8ee462178ab1707315355",
    l2Rpcs: ["https://sepolia.base.org", "https://base-sepolia-rpc.publicnode.com"],
    l2LatestProofRpcs: [],
    layout: BASE_SEPOLIA_LAYOUT,
    fixtureDir: BASE_SEPOLIA_FIXTURE_DIR,
    channelId: OPSTACK_LIVE_CHANNEL_ID
};

/// X Layer (chain 196) on Ethereum mainnet: OptimismPortal 0x6405…9993 → ASR 0x0005…149d.
/// rpc.xlayer.tech serves headers but not eth_getProof ("rpc method is not whitelisted").
export const XLAYER_FIXTURE_DIR = path.resolve(__dirname, "../fixtures/xlayer-live");
export const XLAYER: OpStackLiveChain = {
    name: "xlayer",
    l2ChainId: 196,
    optimismPortal: "0x64057ad1DdAc804d0D26A7275b193D9DACa19993",
    anchorStateRegistry: "0x000590BB65ab1864a7AD46d6B957cC9a4F2C149d",
    l2Rpcs: ["https://rpc.xlayer.tech", "https://xlayer.drpc.org"],
    l2LatestProofRpcs: ["https://xlayer.drpc.org"],
    layout: OP_SUCCINCT_LITE_LAYOUT,
    fixtureDir: XLAYER_FIXTURE_DIR,
    channelId: keccak256(toHex("clpr/opstack-live/xlayer")),
    beaconApis: ["https://ethereum-beacon-api.publicnode.com", "https://lodestar-mainnet.chainsafe.io"],
    l1Rpc: "https://ethereum-rpc.publicnode.com",
    forgeFixture: path.resolve(__dirname, "../../verifiers/evm/opstack/fixtures/xlayer-live.json")
};

export const OPSTACK_LIVE_CHAINS: Record<string, OpStackLiveChain> = {[BASE_SEPOLIA.name]: BASE_SEPOLIA, [XLAYER.name]: XLAYER};

/// L2ToL1MessagePasser predeploy: a real contract with real code and storage on every OP Stack chain.
export const L2_ACCOUNT: Hex = "0x4200000000000000000000000000000000000016";
export const L1_SECONDS_PER_SLOT = 12n;

const fixtureFile = (chain: OpStackLiveChain) => path.join(chain.fixtureDir, "capture.json");
const pendingDir = (chain: OpStackLiveChain) => path.join(chain.fixtureDir, "pending");

/// Public RPCs are load-balanced over nodes with different state windows ("distance to target block
/// exceeds maximum proof window", "Temporary internal error"): retry a few times.
async function rpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
    for (let attempt = 0; ; attempt++) {
        try {
            return await rpcOnce<T>(url, method, params);
        } catch (err) {
            if (attempt >= 4 || !/window|Temporary|rate limit|fetch failed|timeout|503|502/i.test(String(err))) throw err;
            await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
        }
    }
}

// ── ABI fragments ──────────────────────────────────────────────────────────
const ABI = [
    {type: "function", name: "gameCount", inputs: [], outputs: [{type: "uint256"}], stateMutability: "view"},
    {type: "function", name: "gameAtIndex", inputs: [{type: "uint256"}],
        outputs: [{type: "uint32"}, {type: "uint64"}, {type: "address"}], stateMutability: "view"},
    {type: "function", name: "gameImpls", inputs: [{type: "uint32"}], outputs: [{type: "address"}], stateMutability: "view"},
    {type: "function", name: "disputeGameFinalityDelaySeconds", inputs: [], outputs: [{type: "uint256"}], stateMutability: "view"},
    {type: "function", name: "anchorStateRegistry", inputs: [], outputs: [{type: "address"}], stateMutability: "view"},
    {type: "function", name: "gameType", inputs: [], outputs: [{type: "uint32"}], stateMutability: "view"},
    {type: "function", name: "rootClaim", inputs: [], outputs: [{type: "bytes32"}], stateMutability: "view"},
    {type: "function", name: "extraData", inputs: [], outputs: [{type: "bytes"}], stateMutability: "view"},
    {type: "function", name: "l2SequenceNumber", inputs: [], outputs: [{type: "uint256"}], stateMutability: "view"}
] as const;

async function call<T>(url: string, to: Hex, fn: string, args: unknown[], blockTag: Hex | "latest"): Promise<T> {
    const item = ABI.find((a) => a.name === fn)!;
    const data = encodeFunctionData({abi: [item], functionName: fn as never, args: args as never});
    const out = await rpc<Hex>(url, "eth_call", [{to, data}, blockTag]);
    const decoded = decodeAbiParameters(item.outputs, out);
    return (decoded.length === 1 ? decoded[0] : decoded) as T;
}

async function l2rpc<T>(chain: OpStackLiveChain, method: string, params: unknown[]): Promise<T> {
    let lastErr: unknown;
    for (const url of chain.l2Rpcs) {
        try {
            return await rpc<T>(url, method, params);
        } catch (err) {
            lastErr = err;
        }
    }
    throw lastErr;
}

// ── Capture shapes ─────────────────────────────────────────────────────────
export interface L2Output {
    blockNumber: string;
    header: {hash: Hex; stateRoot: Hex; withdrawalsRoot: Hex};
    /// eth_getProof of L2_ACCOUNT with the channel slots at `blockNumber`; null when out of the RPC's window.
    proof: (EthGetProofResult & {storageHash: Hex}) | null;
}

export interface CapturedGame {
    address: Hex;
    gameType: number;
    rootClaim: Hex;
    extraData: Hex;
    l2BlockNumber: string;
    code: Hex;
    proof: EthGetProofResult; // the game's state slots at B (slot 0, plus the wasRespected slot)
    l2: L2Output;
}

export interface OpStackLiveCapture {
    /// `OPSTACK_LIVE_CHAINS` key; absent in older Base Sepolia captures.
    chain?: string;
    network: string;
    capturedAt: string;
    sources: {beaconApi: string; l1Rpc: string; l2Rpcs: string[]};
    beacon: BeaconCapture;
    l1: {
        genesisTime: string;
        block: {number: string; hash: Hex; stateRoot: Hex; timestamp: string};
        anchorStateRegistry: Hex;
        asrImplementation: Hex;
        disputeGameFinalityDelaySeconds: string;
        disputeGameFactory: Hex;
        respectedGameType: number;
        gameImplementation: Hex;
        asrProof: EthGetProofResult;
        asrImplProof: EthGetProofResult;
        dgfProof: EthGetProofResult;
    };
    games: {anchor: CapturedGame; newest: CapturedGame; resolved?: CapturedGame; pending: CapturedGame[]};
    /// keccak256 of L2_ACCOUNT's code at the L2 head, for captures that carry no L2 account proof.
    l2AccountCodeHash?: Hex;
}

/// L2 proofs captured while recent. `address` etc. are absent while the game claiming the block has
/// not been proposed yet (`--stage-next`); a refresh fills them in once it finds the game.
interface PendingStage {
    address?: Hex;
    gameType?: number;
    rootClaim?: Hex;
    extraData?: Hex;
    l2BlockNumber: string;
    l2: L2Output;
}

async function captureL2Output(chain: OpStackLiveChain, blockNumber: bigint, withProof: boolean): Promise<L2Output> {
    const tag = "0x" + blockNumber.toString(16);
    const h = await l2rpc<{hash: Hex; stateRoot: Hex; withdrawalsRoot: Hex}>(chain, "eth_getBlockByNumber", [tag, false]);
    let proof: L2Output["proof"] = null;
    if (withProof) {
        try {
            proof = await l2rpc<NonNullable<L2Output["proof"]>>(chain, "eth_getProof", [L2_ACCOUNT, deriveChannelSlots(chain.channelId), tag]);
        } catch (err) {
            console.error(`L2 eth_getProof at ${blockNumber} unavailable: ${String(err).slice(0, 120)}`);
        }
    }
    return {blockNumber: blockNumber.toString(), header: {hash: h.hash, stateRoot: h.stateRoot, withdrawalsRoot: h.withdrawalsRoot}, proof};
}

function loadPending(chain: OpStackLiveChain): (PendingStage & {file: string})[] {
    const dir = pendingDir(chain);
    if (!existsSync(dir)) return [];
    return readdirSync(dir).filter((f) => f.endsWith(".json"))
        .map((f) => ({...(JSON.parse(readFileSync(path.join(dir, f), "utf8")) as PendingStage), file: f}));
}

/// Slots of a game's own storage the verifier reads (slot 0, and the wasRespected slot when separate).
function gameSlots(L: OpStackLayout): Hex[] {
    return L.gameWasRespectedSlot === L.gameStateSlot ? [slotHex(L.gameStateSlot)]
        : [slotHex(L.gameStateSlot), slotHex(L.gameWasRespectedSlot)];
}

/// Capture everything at one attested L1 block. L1 reads happen inside the beacon hook (non-archive
/// window); L2 reads follow.
export async function captureOpStackLive(chain: OpStackLiveChain, opts: {
    beaconApis?: string[];
    l1Rpc?: string;
    waitForNonSignersMs?: number;
} = {}): Promise<OpStackLiveCapture> {
    const l1Rpc = opts.l1Rpc ?? chain.l1Rpc ?? DEFAULT_EXECUTION_RPC;
    const beaconApis = opts.beaconApis ?? chain.beaconApis ?? DEFAULT_BEACON_APIS;
    const L = chain.layout;
    const asr = chain.anchorStateRegistry;
    const pending = loadPending(chain);

    const {beacon, extra} = await captureBeaconLive({...opts, beaconApis}, async (_execution, B) => {
        const portalAsr = await call<Hex>(l1Rpc, chain.optimismPortal, "anchorStateRegistry", [], B);
        if (portalAsr.toLowerCase() !== asr.toLowerCase()) throw new Error(`portal ASR moved to ${portalAsr}`);
        const head = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [asr, asrSlots(L), B]);
        const v = new Map(head.storageProof.map((sp) => [BigInt(sp.key), BigInt(sp.value)]));
        const dgf = slotHex(v.get(L.asrDisputeGameFactorySlot)!).replace(/^0x0{24}/, "0x") as Hex;
        const respectedGameType = Number(v.get(L.asrRespectedGameTypeSlot)! & 0xffffffffn);
        const impl = ("0x" + v.get(BigInt(asrSlots(L)[2]))!.toString(16).padStart(40, "0")) as Hex;
        const anchorGame = ("0x" + v.get(L.asrAnchorGameSlot)!.toString(16).padStart(40, "0")) as Hex;
        const count = await call<bigint>(l1Rpc, dgf, "gameCount", [], B);

        const readGame = async (address: Hex) => {
            const [gameType, rootClaim, extraData, l2BlockNumber] = await Promise.all([
                call<number>(l1Rpc, address, "gameType", [], B),
                call<Hex>(l1Rpc, address, "rootClaim", [], B),
                call<Hex>(l1Rpc, address, "extraData", [], B),
                call<bigint>(l1Rpc, address, "l2SequenceNumber", [], B)
            ]);
            const proof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [address, gameSlots(L), B]);
            const code = await rpc<Hex>(l1Rpc, "eth_getCode", [address, B]);
            return {address, gameType, rootClaim, extraData, l2BlockNumber: l2BlockNumber.toString(), code, proof};
        };
        // The newest games of the respected type (a DGF may also host other chains' game types: X Layer's
        // hosts type 1961 too). Scanned back far enough to find a resolved one and the staged blocks.
        const recent: Awaited<ReturnType<typeof readGame>>[] = [];
        const wanted = new Set(pending.filter((p) => !p.address).map((p) => p.l2BlockNumber));
        for (let i = count - 1n; i >= 0n && i >= count - 64n; i--) {
            const [type, , addr] = await call<[number, bigint, Hex]>(l1Rpc, dgf, "gameAtIndex", [i], B);
            if (type !== respectedGameType) continue;
            const g = await readGame(addr);
            recent.push(g);
            // Scanning backwards, L2 blocks decrease: a staged block above the newest game or above
            // this one is not proposed yet (or never will be at this index), so stop looking for it.
            for (const w of [...wanted]) if (BigInt(w) >= BigInt(g.l2BlockNumber)) wanted.delete(w);
            if (wanted.size === 0 && recent.some((r) => statusOf(L, r.proof) === GAME_STATUS.DEFENDER_WINS)) break;
        }
        const newest = recent[0];
        if (!newest) throw new Error("no game of the respected type");
        const resolved = recent.find((g) => statusOf(L, g.proof) === GAME_STATUS.DEFENDER_WINS);
        const anchor = await readGame(anchorGame);
        // Pending stages: those with an address, plus address-less ones whose game has appeared since.
        const pend: Awaited<ReturnType<typeof readGame>>[] = [];
        for (const p of pending) {
            const g = p.address ? recent.find((r) => r.address.toLowerCase() === p.address!.toLowerCase()) ?? await readGame(p.address)
                : recent.find((r) => r.l2BlockNumber === p.l2BlockNumber);
            if (g && !pend.some((x) => x.address === g.address)) pend.push(g);
        }
        const all = [anchor, newest, ...(resolved ? [resolved] : []), ...pend];

        const asrProof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [asr, asrSlots(L, all.map((g) => g.address)), B]);
        const asrImplProof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [impl, [], B]);
        const dgfProof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof",
            [dgf, all.map((g) => dgfGameSlot(gameUuid(g.gameType, g.rootClaim, g.extraData), L)), B]);
        const block = await rpc<{number: string; hash: Hex; stateRoot: Hex; timestamp: string}>(
            l1Rpc, "eth_getBlockByNumber", [B, false]);
        const delay = await call<bigint>(l1Rpc, asr, "disputeGameFinalityDelaySeconds", [], B);
        const gameImplementation = await call<Hex>(l1Rpc, dgf, "gameImpls", [respectedGameType], B);
        return {
            anchor, newest, resolved, pend,
            l1: {
                block: {number: block.number, hash: block.hash, stateRoot: block.stateRoot, timestamp: block.timestamp},
                anchorStateRegistry: asr,
                asrImplementation: impl,
                disputeGameFinalityDelaySeconds: delay.toString(),
                disputeGameFactory: dgf,
                respectedGameType,
                gameImplementation,
                asrProof, asrImplProof, dgfProof
            }
        };
    });

    const {json: genesis} = await getJson<{data: {genesis_time: string}}>(
        [beacon.sources.beaconApi, ...beaconApis], "/eth/v1/beacon/genesis");
    // A staged L2 output for the game's block wins; otherwise ask the L2 RPCs (null outside their window).
    const l2Of = async (g: {l2BlockNumber: string}) =>
        pending.find((p) => p.l2BlockNumber === g.l2BlockNumber)?.l2 ?? captureL2Output(chain, BigInt(g.l2BlockNumber), true);
    const anchor = {...extra.anchor, l2: await l2Of(extra.anchor)};
    const newest = {...extra.newest, l2: await l2Of(extra.newest)};
    const resolved = extra.resolved ? {...extra.resolved, l2: await l2Of(extra.resolved)} : undefined;
    const pend = await Promise.all(extra.pend.map(async (g) => ({...g, l2: await l2Of(g)})));
    const l2AccountCodeHash = keccak256(await l2rpc<Hex>(chain, "eth_getCode", [L2_ACCOUNT, "latest"]));

    return {
        chain: chain.name,
        network: chain.name + " on " + beacon.network,
        capturedAt: new Date().toISOString(),
        sources: {beaconApi: beacon.sources.beaconApi, l1Rpc, l2Rpcs: [...chain.l2Rpcs, ...chain.l2LatestProofRpcs]},
        beacon: {...beacon, sources: {beaconApi: beacon.sources.beaconApi, executionRpc: l1Rpc}},
        l1: {genesisTime: genesis.data.genesis_time, ...extra.l1},
        games: {anchor, newest, ...(resolved ? {resolved} : {}), pending: pend},
        l2AccountCodeHash
    };
}

/// Back-compat entry point.
export const captureBaseSepoliaLive = (opts: Parameters<typeof captureOpStackLive>[1] = {}) => captureOpStackLive(BASE_SEPOLIA, opts);

// ── Pure builder ───────────────────────────────────────────────────────────
export interface OpStackLiveGameCase {
    game: Hex;
    gameType: number;
    status: number;
    createdAt: bigint;
    resolvedAt: bigint;
    l2BlockNumber: bigint;
    outputRoot: Hex;
    l2StateRoot: Hex;
    dispute: DisputeProofParts;
    /// `verifyL2StateRoot` input (items 0–2).
    l2StateRootProof: Hex;
    /// Full `verifyBundle` proof, when the L2 account proof is available.
    bundle: Hex | null;
}

export interface OpStackLiveProof {
    lightClient: LiveLightClient;
    l1Time: bigint;
    l1GenesisTime: bigint;
    profile: OpStackProfile;
    trustAnchor: Hex;
    channelContext: Hex;
    channelId: Hex;
    l2Account: Hex;
    l2CodeHash: Hex;
    respectedGameType: number;
    anchorMode: OpStackLiveGameCase;
    anchorGame: OpStackLiveGameCase;
    newest: OpStackLiveGameCase;
    /// Resolved DEFENDER_WINS but (on chains with a delay) not yet finalized, when captured.
    resolved: OpStackLiveGameCase | null;
    pendingFinalized: OpStackLiveGameCase[];
}

function slotValue(proof: EthGetProofResult, slot: bigint): bigint {
    const sp = proof.storageProof.find((x) => BigInt(x.key) === slot);
    if (!sp) throw new Error(`game slot ${slot} not in proof`);
    return BigInt(sp.value);
}

function unpackGameState(L: OpStackLayout, proof: EthGetProofResult) {
    const word = slotValue(proof, L.gameStateSlot);
    const f = (w: bigint, off: bigint, bits: bigint) => (w >> (off * 8n)) & ((1n << bits) - 1n);
    return {
        createdAt: f(word, L.gameCreatedAtOffset, 64n),
        resolvedAt: f(word, L.gameResolvedAtOffset, 64n),
        status: Number(f(word, L.gameStatusOffset, 8n)),
        wasRespected: f(slotValue(proof, L.gameWasRespectedSlot), L.gameWasRespectedOffset, 8n) !== 0n
    };
}

const statusOf = (L: OpStackLayout, proof: EthGetProofResult) => unpackGameState(L, proof).status;

export function chainOf(c: OpStackLiveCapture): OpStackLiveChain {
    const chain = OPSTACK_LIVE_CHAINS[c.chain ?? BASE_SEPOLIA.name];
    if (!chain) throw new Error(`unknown chain ${c.chain}`);
    return chain;
}

/// Pure/offline: turn a capture into verifier inputs, cross-checking every link off-chain.
export function buildOpStackLiveProof(c: OpStackLiveCapture): OpStackLiveProof {
    const chain = chainOf(c);
    const L = chain.layout;
    const lightClient = buildLiveLightClient(c.beacon);
    const attested = c.beacon.finalityUpdate.data.attested_header;

    // L1 binding: the proofs were taken at the attested execution block, whose time is the slot's.
    if (BigInt(c.l1.block.number) !== BigInt(attested.execution.block_number)) throw new Error("L1 block != attested block");
    if (c.l1.block.stateRoot.toLowerCase() !== attested.execution.state_root.toLowerCase()) throw new Error("L1 stateRoot mismatch");
    const l1GenesisTime = BigInt(c.l1.genesisTime);
    const l1Time = l1GenesisTime + BigInt(attested.beacon.slot) * L1_SECONDS_PER_SLOT;
    if (l1Time !== BigInt(attested.execution.timestamp) || l1Time !== BigInt(c.l1.block.timestamp)) {
        throw new Error("genesis_time + slot × 12 != execution timestamp");
    }

    const profile: OpStackProfile = {
        rootFormat: ROOT_FORMAT.OUTPUT_ROOT,
        l2ChainId: BigInt(chain.l2ChainId),
        anchorStateRegistry: c.l1.anchorStateRegistry,
        anchorStateRegistryImplCodeHash: c.l1.asrImplProof.codeHash as Hex,
        disputeGameFinalityDelaySeconds: BigInt(c.l1.disputeGameFinalityDelaySeconds),
        gameImplementation: c.l1.gameImplementation,
        layout: L
    };

    const all = [c.games.anchor, c.games.newest, ...(c.games.resolved ? [c.games.resolved] : []), ...c.games.pending];
    const asrKeys = asrSlots(L, all.map((g) => g.address));
    const dgfKeys = all.map((g) => dgfGameSlot(gameUuid(g.gameType, g.rootClaim, g.extraData), L));
    const base = {
        asrAccountProof: accountNodes(c.l1.asrProof),
        asrStorageProof: storageEntries(c.l1.asrProof, asrKeys),
        asrImplAccountProof: accountNodes(c.l1.asrImplProof),
        dgfAccountProof: accountNodes(c.l1.dgfProof),
        dgfStorageProof: storageEntries(c.l1.dgfProof, dgfKeys)
    };

    // The L2 account whose code hash the anchor pins: taken from any available L2 proof.
    const withProof = all.find((g) => g.l2.proof)?.l2.proof;
    const l2CodeHash = (withProof?.codeHash ?? c.l2AccountCodeHash) as Hex;
    if (!l2CodeHash) throw new Error("capture has no L2 account proof");
    if (withProof && c.l2AccountCodeHash && withProof.codeHash !== c.l2AccountCodeHash) throw new Error("L2 code hash mismatch");
    const channelId = chain.channelId;
    const trustAnchor = encodeEthTrustAnchor(channelId, l2CodeHash, lightClient.committee, {
        gvr: c.beacon.genesisValidatorsRoot as Hex, forkVersion: lightClient.signed.forkVersion
    });
    const channelContext = (channelId + L2_ACCOUNT.slice(2).toLowerCase()) as Hex;
    const chSlots = deriveChannelSlots(channelId);

    const gameCase = (g: CapturedGame, mode: number): OpStackLiveGameCase => {
        const {preimage, outputRoot} = outputRootPreimage(g.l2.header.stateRoot, g.l2.header.withdrawalsRoot, g.l2.header.hash);
        if (outputRoot !== g.rootClaim.toLowerCase() && outputRoot !== g.rootClaim) {
            throw new Error(`game ${g.address}: output root ${outputRoot} != rootClaim ${g.rootClaim}`);
        }
        const st = unpackGameState(L, g.proof);
        if (!st.wasRespected) throw new Error(`game ${g.address}: wasRespectedGameTypeWhenCreated is false`);
        if (g.l2.proof && g.l2.proof.storageHash.toLowerCase() !== g.l2.header.withdrawalsRoot.toLowerCase()) {
            throw new Error("L2ToL1MessagePasser storage root != header withdrawalsRoot");
        }
        const dispute: DisputeProofParts = {
            ...base,
            mode,
            gameType: g.gameType,
            extraData: g.extraData,
            gameAccountProof: mode === MODE.GAME ? accountNodes(g.proof) : [],
            gameCode: mode === MODE.GAME ? g.code : "0x",
            gameStorageProof: mode === MODE.GAME ? storageEntries(g.proof, gameSlots(L)) : []
        };
        const common = {lightClientProof: lightClient.lightClientProof, dispute, outputRootPreimage: preimage};
        return {
            game: g.address,
            gameType: g.gameType,
            status: st.status,
            createdAt: st.createdAt,
            resolvedAt: st.resolvedAt,
            l2BlockNumber: BigInt(g.l2BlockNumber),
            outputRoot,
            l2StateRoot: g.l2.header.stateRoot,
            dispute,
            l2StateRootProof: encodeOpStackL2StateRootProof(common),
            bundle: g.l2.proof ? encodeOpStackBundle({
                ...common,
                l2AccountProof: accountNodes(g.l2.proof),
                l2StorageProof: storageEntries(g.l2.proof, chSlots),
                bundleContent: "0x"
            }) : null
        };
    };

    const finalizedAt = (x: OpStackLiveGameCase) => x.status === GAME_STATUS.DEFENDER_WINS && x.resolvedAt !== 0n
        && l1Time - x.resolvedAt > profile.disputeGameFinalityDelaySeconds;
    return {
        lightClient,
        l1Time,
        l1GenesisTime,
        profile,
        trustAnchor,
        channelContext,
        channelId,
        l2Account: L2_ACCOUNT,
        l2CodeHash,
        respectedGameType: c.l1.respectedGameType,
        anchorMode: gameCase(c.games.anchor, MODE.ANCHOR),
        anchorGame: gameCase(c.games.anchor, MODE.GAME),
        newest: gameCase(c.games.newest, MODE.GAME),
        resolved: c.games.resolved ? gameCase(c.games.resolved, MODE.GAME) : null,
        pendingFinalized: c.games.pending.map((g) => gameCase(g, MODE.GAME)).filter(finalizedAt)
    };
}

export function loadOpStackLiveCapture(file = BASE_SEPOLIA_LIVE_FIXTURE): OpStackLiveCapture {
    if (OPSTACK_LIVE_CHAINS[file]) file = fixtureFile(OPSTACK_LIVE_CHAINS[file]);
    return JSON.parse(readFileSync(file, "utf8")) as OpStackLiveCapture;
}

/// The inputs `test/verifiers/evm/opstack/OpStackXLayerLive.t.sol` replays (no beacon/MPT rebuilding in
/// Solidity: these are the exact calldata arguments the vitest spec sends).
export function forgeFixtureOf(p: OpStackLiveProof): unknown {
    const c = (x: OpStackLiveGameCase | null) => x ? {proof: x.l2StateRootProof, l2StateRoot: x.l2StateRoot, game: x.game,
        status: x.status, resolvedAt: Number(x.resolvedAt)} : null;
    const proposed = [p.newest, ...(p.resolved ? [p.resolved] : [])].find((x) => x.bundle);
    const final = p.pendingFinalized.find((x) => x.bundle) ?? (p.anchorGame.bundle ? p.anchorGame : undefined);
    return {
        l1GenesisTime: Number(p.l1GenesisTime),
        l1Time: Number(p.l1Time),
        trustAnchor: p.trustAnchor,
        channelContext: p.channelContext,
        profile: {
            l2ChainId: Number(p.profile.l2ChainId),
            anchorStateRegistry: p.profile.anchorStateRegistry,
            anchorStateRegistryImplCodeHash: p.profile.anchorStateRegistryImplCodeHash,
            disputeGameFinalityDelaySeconds: Number(p.profile.disputeGameFinalityDelaySeconds),
            gameImplementation: p.profile.gameImplementation,
            respectedGameType: p.respectedGameType
        },
        anchorMode: c(p.anchorMode),
        anchorGame: c(p.anchorGame),
        resolved: c(p.resolved),
        newest: c(p.newest),
        proposedBundle: proposed?.bundle ?? "0x",
        finalizedBundle: final?.bundle ?? "0x"
    };
}

function summarize(p: OpStackLiveProof): string {
    const g = (x: OpStackLiveGameCase) =>
        `${x.game} type ${x.gameType} status ${x.status} L2 #${x.l2BlockNumber} root ${x.outputRoot.slice(0, 18)}… ` +
        `${x.bundle ? "full bundle" : "to L2 state root"}`;
    return [
        `L1 slot ${(p.l1Time - p.l1GenesisTime) / L1_SECONDS_PER_SLOT} (time ${p.l1Time}), ` +
            `participation ${p.lightClient.signed.participants}/512`,
        `ASR ${p.profile.anchorStateRegistry} impl codeHash ${p.profile.anchorStateRegistryImplCodeHash}`,
        `respected game type ${p.respectedGameType}, finality delay ${p.profile.disputeGameFinalityDelaySeconds}s, ` +
            `game impl ${p.profile.gameImplementation}`,
        `anchor  ${g(p.anchorGame)}`,
        `newest  ${g(p.newest)}`,
        ...(p.resolved ? [`resolved ${g(p.resolved)}`] : []),
        `pending finalized: ${p.pendingFinalized.length}`
    ].join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const chainIdx = args.indexOf("--chain");
    const chain = OPSTACK_LIVE_CHAINS[chainIdx >= 0 ? args[chainIdx + 1] : BASE_SEPOLIA.name];
    if (!chain) throw new Error(`--chain: one of ${Object.keys(OPSTACK_LIVE_CHAINS).join(", ")}`);
    const file = fixtureFile(chain);
    const pdir = pendingDir(chain);

    if (args.includes("--stage-next")) {
        await stageNext(chain, Number(args[args.indexOf("--stage-next") + 1]) || 1);
        return;
    }
    let capture: OpStackLiveCapture;
    if (args.includes("--refresh")) {
        const waitIdx = args.indexOf("--wait-nonsigners");
        capture = await captureOpStackLive(chain, {
            waitForNonSignersMs: waitIdx >= 0 ? Number(args[waitIdx + 1]) * 1000 : 0
        });
        const built = buildOpStackLiveProof(capture); // validate before writing
        mkdirSync(pdir, {recursive: true});
        writeFileSync(file, JSON.stringify(capture, null, 1) + "\n");
        // Stage the newest game when its L2 proofs were fetchable now, for a later FINALIZED capture.
        const n = capture.games.newest;
        const keep = new Set<string>();
        const stageOf = (g: CapturedGame): PendingStage => ({address: g.address, gameType: g.gameType, rootClaim: g.rootClaim,
            extraData: g.extraData, l2BlockNumber: g.l2BlockNumber, l2: g.l2});
        if (n.l2.proof) {
            writeFileSync(path.join(pdir, `${n.address.toLowerCase()}.json`), JSON.stringify(stageOf(n), null, 1) + "\n");
            keep.add(`${n.address.toLowerCase()}.json`);
        }
        // Address-less stages whose game has appeared: rewrite them under the game's address.
        for (const g of capture.games.pending) {
            const name = `${g.address.toLowerCase()}.json`;
            writeFileSync(path.join(pdir, name), JSON.stringify(stageOf(g), null, 1) + "\n");
        }
        // Prune: keep games still in progress or resolved-not-final, the most recent finalized one, and
        // address-less stages for blocks no game claims yet.
        const lastFinal = built.pendingFinalized.at(-1);
        if (lastFinal) keep.add(`${lastFinal.game.toLowerCase()}.json`);
        for (const g of capture.games.pending) {
            const st = unpackGameState(chain.layout, g.proof);
            if (!built.pendingFinalized.some((x) => x.game === g.address) && st.status !== GAME_STATUS.CHALLENGER_WINS) {
                keep.add(`${g.address.toLowerCase()}.json`);
            }
        }
        const claimed = new Set(capture.games.pending.map((g) => g.l2BlockNumber));
        for (const f of readdirSync(pdir)) {
            if (!f.endsWith(".json") || keep.has(f)) continue;
            const stage = JSON.parse(readFileSync(path.join(pdir, f), "utf8")) as PendingStage;
            if (!stage.address && !claimed.has(stage.l2BlockNumber)) continue;
            unlinkSync(path.join(pdir, f));
        }
        console.log(`captured → ${path.relative(process.cwd(), file)}`);
    } else {
        capture = loadOpStackLiveCapture(file);
    }
    const built = buildOpStackLiveProof(capture);
    if (chain.forgeFixture && (args.includes("--refresh") || args.includes("--export-forge"))) {
        writeFileSync(chain.forgeFixture, JSON.stringify(forgeFixtureOf(built), null, 1) + "\n");
        console.log(`forge fixture → ${path.relative(process.cwd(), chain.forgeFixture)}`);
    }
    console.log(summarize(built));
}

/// For chains whose public eth_getProof serves "latest" only: stage the L2 proofs of the blocks the
/// proposer's next `count` games will claim. The cadence is read from the two newest games of the
/// respected type on L1.
async function stageNext(chain: OpStackLiveChain, count: number): Promise<void> {
    if (!chain.l2LatestProofRpcs.length) throw new Error(`${chain.name}: no latest-only proof RPC configured`);
    const l1Rpc = chain.l1Rpc ?? DEFAULT_EXECUTION_RPC;
    const dgf = (await rpc<Hex>(l1Rpc, "eth_getStorageAt",
        [chain.anchorStateRegistry, slotHex(chain.layout.asrDisputeGameFactorySlot), "latest"])).replace(/^0x0{24}/, "0x") as Hex;
    const respected = Number(BigInt(await rpc<Hex>(l1Rpc, "eth_getStorageAt",
        [chain.anchorStateRegistry, slotHex(chain.layout.asrRespectedGameTypeSlot), "latest"])) & 0xffffffffn);
    const n = await call<bigint>(l1Rpc, dgf, "gameCount", [], "latest");
    const blocks: bigint[] = [];
    for (let i = n - 1n; i >= 0n && blocks.length < 2; i--) {
        const [type, , addr] = await call<[number, bigint, Hex]>(l1Rpc, dgf, "gameAtIndex", [i], "latest");
        if (type === respected) blocks.push(await call<bigint>(l1Rpc, addr, "l2SequenceNumber", [], "latest"));
    }
    const interval = blocks[0] - blocks[1];
    const head = BigInt(await rpc<Hex>(chain.l2LatestProofRpcs[0], "eth_blockNumber", []));
    let target = blocks[0] + interval;
    while (target <= head + 5n) target += interval;
    mkdirSync(pendingDir(chain), {recursive: true});
    for (let k = 0; k < count; k++, target += interval) {
        console.error(`staging L2 block ${target} (game interval ${interval}, head ${head})`);
        const staged = await stageLatestL2Proof(chain.l2LatestProofRpcs[0], L2_ACCOUNT, deriveChannelSlots(chain.channelId), target);
        if (!staged) {
            console.error(`missed block ${target}`);
            continue;
        }
        if (staged.proof.storageHash.toLowerCase() !== staged.header.withdrawalsRoot.toLowerCase()) {
            throw new Error("L2ToL1MessagePasser storage root != header withdrawalsRoot");
        }
        const stage: PendingStage = {l2BlockNumber: staged.blockNumber, l2: staged};
        writeFileSync(path.join(pendingDir(chain), `l2-${target}.json`), JSON.stringify(stage, null, 1) + "\n");
        console.log(`staged L2 block ${target} → ${path.relative(process.cwd(), pendingDir(chain))}/l2-${target}.json`);
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
