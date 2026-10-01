// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprSha512
/// @notice SHA-512 (FIPS 180-4) for chains that hash with it, without a precompile. The XRP Ledger
///         hashes ledger headers, SHAMap nodes, validations and manifests with SHA-512Half (the first
///         32 bytes of SHA-512), so its verifier runs dozens of compressions per bundle.
/// @dev The eight working variables stay on the stack; rounds are unrolled by eight so the a..h
///      roles rotate by renaming instead of moving values, and K[t] + W[t] is precomputed per block. Checked against NIST and Node `crypto` vectors in ClprSha512.t.sol.
library ClprSha512 {
    /// @dev 80 round constants, 8 bytes each, big-endian.
    bytes internal constant K =
        hex"428a2f98d728ae227137449123ef65cdb5c0fbcfec4d3b2fe9b5dba58189dbbc3956c25bf348b53859f111f1b605d019923f82a4af194f9bab1c5ed5da6d8118d807aa98a303024212835b0145706fbe243185be4ee4b28c550c7dc3d5ffb4e272be5d74f27b896f80deb1fe3b1696b19bdc06a725c71235c19bf174cf692694e49b69c19ef14ad2efbe4786384f25e30fc19dc68b8cd5b5240ca1cc77ac9c652de92c6f592b02754a7484aa6ea6e4835cb0a9dcbd41fbd476f988da831153b5983e5152ee66dfaba831c66d2db43210b00327c898fb213fbf597fc7beef0ee4c6e00bf33da88fc2d5a79147930aa72506ca6351e003826f142929670a0e6e7027b70a8546d22ffc2e1b21385c26c9264d2c6dfc5ac42aed53380d139d95b3df650a73548baf63de766a0abb3c77b2a881c2c92e47edaee692722c851482353ba2bfe8a14cf10364a81a664bbc423001c24b8b70d0f89791c76c51a30654be30d192e819d6ef5218d69906245565a910f40e35855771202a106aa07032bbd1b819a4c116b8d2d0c81e376c085141ab532748774cdf8eeb9934b0bcb5e19b48a8391c0cb3c5c95a634ed8aa4ae3418acb5b9cca4f7763e373682e6ff3d6b2b8a3748f82ee5defb2fc78a5636f43172f6084c87814a1f0ab728cc702081a6439ec90befffa23631e28a4506cebde82bde9bef9a3f7b2c67915c67178f2e372532bca273eceea26619cd186b8c721c0c207eada7dd6cde0eb1ef57d4f7fee6ed17806f067aa72176fba0a637dc5a2c898a6113f9804bef90dae1b710b35131c471b28db77f523047d8432caab7b40c724933c9ebe0a15c9bebc431d67c49c100d4c4cc5d4becb3e42b6597f299cfc657e2a5fcb6fab3ad6faec6c44198c4a475817";

    /// @notice SHA-512 of `data` as two big-endian words (bytes 0..31 and 32..63 of the digest).
    function hash(bytes memory data) internal pure returns (bytes32 hi, bytes32 lo) {
        uint256 st = _init();
        uint256 nblocks = (data.length + 144) / 128; // ceil((len + 1 + 16) / 128)
        for (uint256 bi = 0; bi < nblocks; ++bi) {
            _schedule(data, bi, nblocks, st);
            _rounds(st);
        }
        return _digest(st);
    }

    /// @dev Work area: 8 state words, then 80 words of K[t] + W[t], then a 128-byte block buffer.
    function _init() private pure returns (uint256 st) {
        uint256[] memory area = new uint256[](8 + 80 + 4);
        assembly ("memory-safe") {
            st := add(area, 0x20)
            mstore(st, 0x6a09e667f3bcc908)
            mstore(add(st, 0x20), 0xbb67ae8584caa73b)
            mstore(add(st, 0x40), 0x3c6ef372fe94f82b)
            mstore(add(st, 0x60), 0xa54ff53a5f1d36f1)
            mstore(add(st, 0x80), 0x510e527fade682d1)
            mstore(add(st, 0xa0), 0x9b05688c2b3e6c1f)
            mstore(add(st, 0xc0), 0x1f83d9abfb41bd6b)
            mstore(add(st, 0xe0), 0x5be0cd19137e2179)
        }
    }

    function _digest(uint256 st) private pure returns (bytes32 hi, bytes32 lo) {
        assembly ("memory-safe") {
            hi :=
                or(
                    or(shl(192, mload(st)), shl(128, mload(add(st, 0x20)))),
                    or(shl(64, mload(add(st, 0x40))), mload(add(st, 0x60)))
                )
            lo :=
                or(
                    or(shl(192, mload(add(st, 0x80))), shl(128, mload(add(st, 0xa0)))),
                    or(shl(64, mload(add(st, 0xc0))), mload(add(st, 0xe0)))
                )
        }
    }

    /// @dev Pad block `bi` into the buffer and expand K[t] + W[t] for t = 0..79.
    function _schedule(bytes memory data, uint256 bi, uint256 nblocks, uint256 st) private pure {
        bytes memory k = K;
        assembly ("memory-safe") {
            let M := 0xffffffffffffffff
            let kw := add(st, 0x100)
            let blk := add(kw, 0xa00)
            let len := mload(data)
            let off := mul(bi, 128)
            mstore(blk, 0)
            mstore(add(blk, 0x20), 0)
            mstore(add(blk, 0x40), 0)
            mstore(add(blk, 0x60), 0)
            if lt(off, len) {
                let n := sub(len, off)
                if gt(n, 128) { n := 128 }
                mcopy(blk, add(add(data, 0x20), off), n)
                if lt(n, 128) { mstore8(add(blk, n), 0x80) }
            }
            if eq(off, len) { mstore8(blk, 0x80) }
            if eq(bi, sub(nblocks, 1)) {
                // 128-bit big-endian bit length (high half zero). OR it in: bytes 96..111 of the
                // last block may still hold message data.
                mstore(add(blk, 96), or(mload(add(blk, 96)), mul(len, 8)))
            }
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                mstore(add(kw, shl(5, i)), shr(192, mload(add(blk, shl(3, i)))))
            }
            for { let t := 16 } lt(t, 80) { t := add(t, 1) } {
                let w15 := mload(add(kw, shl(5, sub(t, 15))))
                let w2 := mload(add(kw, shl(5, sub(t, 2))))
                let y15 := or(w15, shl(64, w15))
                let y2 := or(w2, shl(64, w2))
                let s0 := xor(and(xor(shr(1, y15), shr(8, y15)), M), shr(7, w15))
                let s1 := xor(and(xor(shr(19, y2), shr(61, y2)), M), shr(6, w2))
                mstore(
                    add(kw, shl(5, t)),
                    and(add(add(mload(add(kw, shl(5, sub(t, 16)))), s0), add(mload(add(kw, shl(5, sub(t, 7)))), s1)), M)
                )
            }
            let kp := add(k, 0x20)
            for { let t := 0 } lt(t, 80) { t := add(t, 1) } {
                let q := add(kw, shl(5, t))
                mstore(q, add(mload(q), shr(192, mload(add(kp, shl(3, t))))))
            }
        }
    }

    /// @dev 80 rounds over the prepared K[t] + W[t], unrolled by eight so the a..h roles rotate by
    ///      renaming; then add into the state.
    function _rounds(uint256 st) private pure {
        assembly ("memory-safe") {
            // A round only changes d and h: t1 = h + Σ1(e) + Ch(e,f,g) + K + W, d += t1,
            // h = t1 + Σ0(a) + Maj(a,b,c). Σ widens once (x | x << 64) and uses right shifts.
            function t1of(e, f, g, h, kw) -> t1 {
                let y := or(e, shl(64, e))
                t1 :=
                    add(
                        add(h, and(xor(xor(shr(14, y), shr(18, y)), shr(41, y)), 0xffffffffffffffff)),
                        add(xor(g, and(e, xor(f, g))), kw)
                    )
            }
            function hof(a, b, c, t1) -> h2 {
                let y := or(a, shl(64, a))
                h2 :=
                    and(
                        add(
                            add(t1, and(xor(xor(shr(28, y), shr(34, y)), shr(39, y)), 0xffffffffffffffff)),
                            or(and(a, b), and(c, or(a, b)))
                        ),
                        0xffffffffffffffff
                    )
            }
            let a := mload(st)
            let b := mload(add(st, 0x20))
            let c := mload(add(st, 0x40))
            let d := mload(add(st, 0x60))
            let e := mload(add(st, 0x80))
            let f := mload(add(st, 0xa0))
            let g := mload(add(st, 0xc0))
            let h := mload(add(st, 0xe0))
            let t
            let qEnd := add(st, 0xb00)
            for { let q := add(st, 0x100) } lt(q, qEnd) { q := add(q, 0x100) } {
                t := t1of(e, f, g, h, mload(q))
                d := and(add(d, t), 0xffffffffffffffff)
                h := hof(a, b, c, t)
                t := t1of(d, e, f, g, mload(add(q, 0x20)))
                c := and(add(c, t), 0xffffffffffffffff)
                g := hof(h, a, b, t)
                t := t1of(c, d, e, f, mload(add(q, 0x40)))
                b := and(add(b, t), 0xffffffffffffffff)
                f := hof(g, h, a, t)
                t := t1of(b, c, d, e, mload(add(q, 0x60)))
                a := and(add(a, t), 0xffffffffffffffff)
                e := hof(f, g, h, t)
                t := t1of(a, b, c, d, mload(add(q, 0x80)))
                h := and(add(h, t), 0xffffffffffffffff)
                d := hof(e, f, g, t)
                t := t1of(h, a, b, c, mload(add(q, 0xa0)))
                g := and(add(g, t), 0xffffffffffffffff)
                c := hof(d, e, f, t)
                t := t1of(g, h, a, b, mload(add(q, 0xc0)))
                f := and(add(f, t), 0xffffffffffffffff)
                b := hof(c, d, e, t)
                t := t1of(f, g, h, a, mload(add(q, 0xe0)))
                e := and(add(e, t), 0xffffffffffffffff)
                a := hof(b, c, d, t)
            }
            let M := 0xffffffffffffffff
            mstore(st, and(add(mload(st), a), M))
            mstore(add(st, 0x20), and(add(mload(add(st, 0x20)), b), M))
            mstore(add(st, 0x40), and(add(mload(add(st, 0x40)), c), M))
            mstore(add(st, 0x60), and(add(mload(add(st, 0x60)), d), M))
            mstore(add(st, 0x80), and(add(mload(add(st, 0x80)), e), M))
            mstore(add(st, 0xa0), and(add(mload(add(st, 0xa0)), f), M))
            mstore(add(st, 0xc0), and(add(mload(add(st, 0xc0)), g), M))
            mstore(add(st, 0xe0), and(add(mload(add(st, 0xe0)), h), M))
        }
    }

    /// @notice SHA-512Half: the first 256 bits of SHA-512 (XRPL `sha512Half`).
    function half(bytes memory data) internal pure returns (bytes32 h) {
        (h,) = hash(data);
    }
}
