import {keccak256, type Hex} from "viem";
import {rpc} from "./buildEthLiveProof.js";
import type {EthGetProofResult} from "./buildEthMainnetProof.js";

/// For L2 RPCs that serve `eth_getProof` only at "latest" (reth with `--rpc.eth-proof-window 0`, e.g.
/// X Layer's public dRPC endpoint): wait until block `target` is the head, then poll
/// `eth_getProof(…, "latest")` until a response's account-proof root equals `target`'s state root.
/// Returns null if the head moves past `target` first.
export interface StagedL2Proof {
    blockNumber: string;
    header: {hash: Hex; stateRoot: Hex; withdrawalsRoot: Hex};
    proof: EthGetProofResult & {storageHash: Hex};
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function stageLatestL2Proof(url: string, account: Hex, keys: Hex[], target: bigint, opts: {
    pollMs?: number; slackBlocks?: bigint; log?: (s: string) => void;
} = {}): Promise<StagedL2Proof | null> {
    const log = opts.log ?? ((s: string) => console.error(s));
    const slack = opts.slackBlocks ?? 4n;
    // Coarse wait: sleep until a few blocks before the target.
    for (;;) {
        const head = BigInt(await rpc<Hex>(url, "eth_blockNumber", []).catch(() => "0x0"));
        if (head > target + slack) return null;
        if (head >= target - 3n) break;
        const gap = target - 3n - head;
        log(`head ${head}, target ${target}: ${gap} blocks to go`);
        await sleep(Math.min(Number(gap) * 800, 60_000));
    }
    // Tight loop: collect "latest" proofs until the target header is known and one matches it.
    const seen: (EthGetProofResult & {storageHash: Hex})[] = [];
    let header: StagedL2Proof["header"] | null = null;
    for (let i = 0; i < 200; i++) {
        try {
            seen.push(await rpc<EthGetProofResult & {storageHash: Hex}>(url, "eth_getProof", [account, keys, "latest"]));
        } catch (err) {
            log(`eth_getProof: ${String(err).slice(0, 100)}`);
        }
        if (!header) {
            try {
                const h = await rpc<{hash: Hex; stateRoot: Hex; withdrawalsRoot: Hex} | null>(
                    url, "eth_getBlockByNumber", ["0x" + target.toString(16), false]);
                if (h) header = {hash: h.hash, stateRoot: h.stateRoot, withdrawalsRoot: h.withdrawalsRoot};
            } catch {
                /* not yet */
            }
        }
        if (header) {
            const hit = seen.find((p) => keccak256(p.accountProof[0] as Hex) === header!.stateRoot.toLowerCase());
            if (hit) return {blockNumber: target.toString(), header, proof: hit};
            const head = BigInt(await rpc<Hex>(url, "eth_blockNumber", []).catch(() => "0x0"));
            if (head > target + slack) return null;
        }
        await sleep(opts.pollMs ?? 250);
    }
    return null;
}
