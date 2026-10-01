import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {
    createPublicClient,
    createWalletClient,
    encodeFunctionData,
    http,
    keccak256,
    toHex,
    type Hex,
    type PublicClient,
    type WalletClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {
    attest,
    buildAvalancheLiveProof,
    loadLiveCapture,
    reencodeBundle,
    validatorSetDigest,
    type AvalancheLiveProof,
    type LiveCapture
} from "../../relay/buildAvalancheLiveProof.js";
import {hexToBuf} from "../../lib/rlp.js";

/// AvalancheWarpVerifier against REAL Fuji data, replayed offline from
/// test/e2e/fixtures/avalanche-live/capture.json (re-capture: `npm run avalanche-live:refresh`).
///
/// Real inputs: the C-Chain header (hash re-derived from coreth's RLP layout), the Primary Network
/// validator set at two P-Chain heights (a real set change between them), the validators' Warp
/// BitSetSignature over the block hash (ACP-118, aggregated at the newer height) and eth_getProof for
/// WAVAX at the same block. No ClprService exists on Fuji, so the channel slots are MPT exclusion
/// proofs (zeroed metadata). The only synthetic input is the rotation attestation, which the verifier
/// trusts by design (test attestor keys, 2-of-3).
///
/// Run: forge build && npm run test:e2e:avalanche-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8611);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const VERIFIER = "AvalancheWarpVerifier";

function byteLen(h: Hex): number {
    return (h.length - 2) / 2;
}

/// Overwrite `anchor[off..off+bytes.length)`.
function patchAnchor(anchor: Hex, off: number, bytes: Buffer): Hex {
    const a = hexToBuf(anchor);
    bytes.copy(a, off);
    return ("0x" + a.toString("hex")) as Hex;
}

describe("AvalancheWarpVerifier on live Fuji data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let verifier: Hex;
    let capture: LiveCapture;
    let live: AvalancheLiveProof;
    const art = loadArtifact(VERIFIER);

    function verifyBundle(proofBytes: Hex, trustAnchor: Hex, channelContext: Hex = live.channelContext) {
        return pub.readContract({
            address: verifier,
            abi: art.abi as never,
            functionName: "verifyBundle",
            args: [proofBytes, trustAnchor, channelContext]
        }) as Promise<[{state: number; nextMessageId: bigint; receivedMessageId: bigint;
            sentRunningHash: Hex; receivedRunningHash: Hex}, Hex[], Hex, Hex, unknown]>;
    }

    async function measure(proofBytes: Hex, trustAnchor: Hex): Promise<{gas: bigint; calldata: number; calldataGas: number}> {
        const args = [proofBytes, trustAnchor, live.channelContext];
        const gas = await pub.estimateContractGas({
            address: verifier, abi: art.abi as never, functionName: "verifyBundle", args, account: wallet.account!
        });
        const cd = hexToBuf(encodeFunctionData({abi: art.abi, functionName: "verifyBundle", args} as never));
        return {gas, calldata: cd.length, calldataGas: cd.reduce((acc, b) => acc + (b === 0 ? 4 : 16), 0)};
    }

    beforeAll(async () => {
        capture = loadLiveCapture();
        live = await buildAvalancheLiveProof(capture);

        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--hardfork", "prague"], {stdio: "ignore"});
        const rpc = `http://127.0.0.1:${ANVIL_PORT}`;
        pub = createPublicClient({transport: http(rpc), pollingInterval: 100}) as PublicClient;
        const deadline = Date.now() + 15_000;
        for (;;) {
            try {
                await pub.getChainId();
                break;
            } catch (err) {
                if (Date.now() > deadline) throw err;
                await new Promise((r) => setTimeout(r, 200));
            }
        }
        wallet = createWalletClient({account: privateKeyToAccount(ANVIL_KEY), transport: http(rpc)});
        const hash = await wallet.deployContract({
            abi: art.abi as never, bytecode: art.bytecode, args: [], account: wallet.account!, chain: null
        });
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        verifier = r.contractAddress;
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    it("builder: live inputs are consistent (Fuji C-Chain, canonical set, ≥67% signed)", () => {
        expect(capture.networkId).toBe(5);
        expect(live.sourceChainId).toBe("0x7fc93d85c6d62c5b2ac0b519c87010ea5294012d1e407030d6acd0021cac10d5");
        expect(byteLen(live.trustAnchor)).toBe(220);
        expect(live.meta.signedWeightBps).toBeGreaterThanOrEqual(6700);
        expect(live.set.height).toBeGreaterThan(live.previousSet.height);
        expect(live.set.setHash).not.toBe(live.previousSet.setHash);
    });

    it("verifyBundle succeeds on the real header, Warp signature and account proof", async () => {
        const [metadata, payloads, newAnchor, newAnchorId] = await verifyBundle(live.proofBytes, live.trustAnchor);
        expect(metadata.nextMessageId).toBe(0n);
        expect(metadata.receivedMessageId).toBe(0n);
        expect(metadata.sentRunningHash).toBe(toHex(0n, {size: 32}));
        expect(payloads).toEqual([]);
        expect(newAnchor).toBe("0x");
        expect(newAnchorId).toBe("0x");
        const m = await measure(live.proofBytes, live.trustAnchor);
        console.log(
            `[avalanche-live] ${live.meta.network} block ${live.meta.blockNumber}: ${live.meta.signers}/${live.meta.validators} ` +
            `signers (${live.meta.signedWeightBps / 100}% stake) | verifyBundle eth_estimateGas ${m.gas} = 21000 base + ` +
            `${m.calldataGas} calldata + ~${m.gas - 21000n - BigInt(m.calldataGas)} execution | proofBytes ` +
            `${byteLen(live.proofBytes)} B, calldata ${m.calldata} B`
        );
    });

    it("real validator-set rotation: P-Chain @previous → @current, then the bundle verifies under the new set", async () => {
        const [, , newAnchor, newAnchorId] = await verifyBundle(live.rotationProofBytes, live.previousTrustAnchor);
        expect(newAnchor).toBe(live.trustAnchor);
        expect(BigInt(newAnchorId)).toBe(live.set.height);
        const m = await measure(live.rotationProofBytes, live.previousTrustAnchor);
        console.log(
            `[avalanche-live] rotation @${live.previousSet.height} (${live.meta.previousValidators} keys) → ` +
            `@${live.set.height} (${live.meta.validators} keys): eth_estimateGas ${m.gas}, calldata ${m.calldata} B`
        );
    });

    it("rejects a replayed rotation (P-Chain height not newer than the anchor)", async () => {
        await expect(verifyBundle(live.rotationProofBytes, live.trustAnchor)).rejects.toThrow(/RotationNotNewer/);
    });

    it("rejects a rotation with fewer attestations than the threshold", async () => {
        const digest = validatorSetDigest(live.networkId, hexToBuf(live.sourceChainId), live.set.height,
            live.set.timestamp, live.set.setHash, live.set.totalWeight);
        const rot = [...live.parts.rotation];
        rot[5] = await attest(digest, 1);
        const proof = reencodeBundle(live.parts, {rotationItem: rot});
        await expect(verifyBundle(proof, live.previousTrustAnchor)).rejects.toThrow(/InsufficientAttestations/);
    });

    it("rejects the real signature checked against the wrong (previous) validator set", async () => {
        // Previous set with a window wide enough that only the signature check can fail.
        const anchor = patchAnchor(live.previousTrustAnchor, 180, Buffer.from("00000000ffffffff", "hex"));
        const proof = reencodeBundle(live.parts, {validatorSet: live.parts.previousValidatorSet});
        await expect(verifyBundle(proof, anchor))
            .rejects.toThrow(/BlsSignatureInvalid|InsufficientSignedWeight|InvalidSignerBitSet/);
    });

    it("rejects a validator set the anchor does not commit to", async () => {
        const proof = reencodeBundle(live.parts, {validatorSet: live.parts.previousValidatorSet});
        await expect(verifyBundle(proof, live.trustAnchor)).rejects.toThrow(/ValidatorSetMismatch/);
    });

    it("rejects a tampered signature", async () => {
        const sig = Buffer.from(live.parts.warpSignature[1]);
        sig[255] ^= 1;
        const proof = reencodeBundle(live.parts, {warpSignature: [live.parts.warpSignature[0], sig]});
        await expect(verifyBundle(proof, live.trustAnchor)).rejects.toThrow(/BlsSignatureInvalid|BlsPrecompileCallFailed/);
    });

    it("rejects a dropped signer (stake falls below 67% or the aggregate no longer matches)", async () => {
        const bits = Buffer.from(live.parts.warpSignature[0]);
        const last = bits.length - 1;
        const firstSet = [...Array(8 * bits.length).keys()].find((i) => (bits[last - (i >> 3)] >> (i & 7)) & 1)!;
        bits[last - (firstSet >> 3)] &= ~(1 << (firstSet & 7));
        const proof = reencodeBundle(live.parts, {warpSignature: [bits, live.parts.warpSignature[1]]});
        await expect(verifyBundle(proof, live.trustAnchor)).rejects.toThrow(/InsufficientSignedWeight|BlsSignatureInvalid/);
    });

    it("rejects a header whose state root was swapped (block hash no longer signed)", async () => {
        const h = Buffer.from(live.parts.header);
        const sr = h.indexOf(hexToBuf(capture.block.stateRoot));
        h[sr] ^= 1;
        const proof = reencodeBundle(live.parts, {header: h});
        await expect(verifyBundle(proof, live.trustAnchor)).rejects.toThrow(/BlsSignatureInvalid/);
    });

    it("rejects the block once the validator set is older than maxSetAge (stale set)", async () => {
        const anchor = patchAnchor(live.trustAnchor, 180, Buffer.from("0000000000000001", "hex"));
        await expect(verifyBundle(live.proofBytes, anchor)).rejects.toThrow(/ValidatorSetExpired/);
    });

    it("fails only at the codeHash binding when another (e.g. ClprService) code hash is pinned", async () => {
        const anchor = patchAnchor(live.trustAnchor, 68, hexToBuf(keccak256(toHex("other-runtime-code"))));
        await expect(verifyBundle(live.proofBytes, anchor)).rejects.toThrow(/CodeHashMismatch/);
    });

    it("rejects a Warp signature from another network id", async () => {
        const anchor = patchAnchor(live.trustAnchor, 0, Buffer.from("00000001", "hex"));
        await expect(verifyBundle(live.proofBytes, anchor)).rejects.toThrow(/BlsSignatureInvalid/);
    });
});
