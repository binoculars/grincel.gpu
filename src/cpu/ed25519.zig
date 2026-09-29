const std = @import("std");
const crypto = std.crypto;

const Curve = crypto.ecc.Edwards25519;
const Fe = Curve.Fe;
const Sha512 = crypto.hash.sha2.Sha512;
const precomp_limbs = @import("../base_precomp.zig").limbs;

pub const Ed25519 = struct {
    pub const KeyPair = struct {
        public: [32]u8,
        /// Solana keypair: raw 32-byte Ed25519 seed, then the public key.
        private: [64]u8,
    };

    /// Derive a Solana-compatible keypair from a 32-byte seed.
    ///
    /// `solana-keygen` stores the seed itself and re-derives the public key
    /// with SHA-512 + clamping. The seed must not be pre-hashed.
    pub fn generateKeypair(seed: []const u8) KeyPair {
        std.debug.assert(seed.len == 32);
        var seed_bytes: [32]u8 = undefined;
        @memcpy(&seed_bytes, seed[0..32]);

        var pubs: [1][32]u8 = undefined;
        const seeds = [_][32]u8{seed_bytes};
        publicKeys(&seeds, &pubs);
        const public_key = pubs[0];
        var private: [64]u8 = undefined;
        private[0..32].* = seed_bytes;
        private[32..].* = public_key;
        return .{
            .public = public_key,
            .private = private,
        };
    }

    /// Derive public keys for many seeds, inverting all Z coordinates together.
    pub fn publicKeys(seeds: []const [32]u8, out: [][32]u8) void {
        std.debug.assert(seeds.len == out.len);
        std.debug.assert(seeds.len <= 32);
        if (seeds.len == 0) return;

        var points: [32]Curve = undefined;
        var zinv: [32]Fe = undefined;
        for (seeds, 0..) |seed, i| {
            var az: [Sha512.digest_length]u8 = undefined;
            Sha512.hash(&seed, &az, .{});
            var scalar = az[0..32].*;
            Curve.scalar.clamp(&scalar);
            points[i] = scalarmultBase(scalar);
            zinv[i] = points[i].z;
        }
        batchInvert(zinv[0..seeds.len]);
        for (seeds, 0..) |_, i| {
            const y = points[i].y.mul(zinv[i]);
            const x = points[i].x.mul(zinv[i]);
            var encoded = y.toBytes();
            encoded[31] ^= @as(u8, @intFromBool(x.isNegative())) << 7;
            out[i] = encoded;
        }
    }

    pub fn generateKeypairBatch(allocator: std.mem.Allocator, seeds: []const u8, count: usize) ![]KeyPair {
        var pairs = try allocator.alloc(KeyPair, count);
        errdefer allocator.free(pairs);

        var i: usize = 0;
        while (i < count) : (i += 1) {
            pairs[i] = generateKeypair(seeds[i * 32 ..][0..32]);
        }

        return pairs;
    }

    /// True when `private_key` is a Solana keypair for `public_key`.
    /// Checked against Zig's standard implementation, not the grind path.
    pub fn matchesSolanaKeypair(public_key: [32]u8, private_key: [64]u8) bool {
        const seed: [32]u8 = private_key[0..32].*;
        const key_pair = crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return false;
        const derived = key_pair.public_key.toBytes();
        return std.mem.eql(u8, &derived, &public_key) and std.mem.eql(u8, &derived, private_key[32..64]);
    }
};

const Precomp = struct {
    yplusx: Fe,
    yminusx: Fe,
    xy2d: Fe,
};

fn feAt(comptime at: usize) Fe {
    return .{ .limbs = .{
        @as(u64, @intCast(precomp_limbs[at])),
        @as(u64, @intCast(precomp_limbs[at + 1])),
        @as(u64, @intCast(precomp_limbs[at + 2])),
        @as(u64, @intCast(precomp_limbs[at + 3])),
        @as(u64, @intCast(precomp_limbs[at + 4])),
    } };
}

/// base[i][j] = (j + 1) * 256^i * B, as (y+x, y-x, 2*d*x*y).
const base_table: [32][8]Precomp = blk: {
    @setEvalBranchQuota(10000);
    var table: [32][8]Precomp = undefined;
    for (0..32) |pos| {
        for (0..8) |j| {
            const at = (pos * 8 + j) * 15;
            table[pos][j] = .{
                .yplusx = feAt(at),
                .yminusx = feAt(at + 5),
                .xy2d = feAt(at + 10),
            };
        }
    }
    break :blk table;
};

const identity_precomp = Precomp{
    .yplusx = Fe.one,
    .yminusx = Fe.one,
    .xy2d = Fe.zero,
};

fn batchInvert(zs: []Fe) void {
    var prefix: [32]Fe = undefined;
    prefix[0] = zs[0];
    for (1..zs.len) |i| prefix[i] = prefix[i - 1].mul(zs[i]);
    var inv = prefix[zs.len - 1].invert();
    var i = zs.len - 1;
    while (i > 0) : (i -= 1) {
        const current = zs[i];
        zs[i] = inv.mul(prefix[i - 1]);
        inv = inv.mul(current);
    }
    zs[0] = inv;
}

/// Signed radix-16 fixed-base multiply. `s[31] <= 127`, which clamping guarantees.
fn scalarmultBase(s: [32]u8) Curve {
    var e: [64]i32 = undefined;
    for (0..32) |i| {
        e[2 * i] = s[i] & 15;
        e[2 * i + 1] = s[i] >> 4;
    }
    var carry: i32 = 0;
    for (0..63) |i| {
        e[i] += carry;
        carry = (e[i] + 8) >> 4;
        e[i] -= carry << 4;
    }
    e[63] += carry;

    var h = Curve.identityElement;
    var i: usize = 1;
    while (i < 64) : (i += 2) {
        h = madd(h, select(i / 2, e[i]));
    }
    h = h.dbl().dbl().dbl().dbl();
    i = 0;
    while (i < 64) : (i += 2) {
        h = madd(h, select(i / 2, e[i]));
    }
    return h;
}

fn select(pos: usize, b: i32) Precomp {
    if (b == 0) return identity_precomp;
    const neg = b < 0;
    const absb: usize = @intCast(if (neg) -b else b);
    var t = base_table[pos][absb - 1];
    if (neg) {
        const ypx = t.yplusx;
        t.yplusx = t.yminusx;
        t.yminusx = ypx;
        t.xy2d = t.xy2d.neg();
    }
    return t;
}

fn madd(p: Curve, q: Precomp) Curve {
    const ypx = p.y.add(p.x).mul(q.yplusx);
    const ymx = p.y.sub(p.x).mul(q.yminusx);
    const xy2 = q.xy2d.mul(p.t);
    const z2 = p.z.add(p.z);
    const x = ypx.sub(ymx);
    const y = ypx.add(ymx);
    const z = z2.add(xy2);
    const t = z2.sub(xy2);
    return .{
        .x = x.mul(t),
        .y = y.mul(z),
        .z = z.mul(t),
        .t = x.mul(y),
    };
}

test "keypair is a Solana seed followed by the public key" {
    var seed: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");

    const kp = Ed25519.generateKeypair(&seed);
    const expected = try crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);

    try std.testing.expectEqualSlices(u8, &seed, kp.private[0..32]);
    try std.testing.expectEqualSlices(u8, &expected.public_key.toBytes(), &kp.public);
    try std.testing.expectEqualSlices(u8, &expected.secret_key.toBytes(), &kp.private);
    try std.testing.expect(Ed25519.matchesSolanaKeypair(kp.public, kp.private));
}

test "fixed-base public keys match the standard derivation" {
    var seeds: [16][32]u8 = undefined;
    var pubs: [16][32]u8 = undefined;
    for (&seeds, 0..) |*seed, n| {
        seed.* = .{0} ** 32;
        seed[0] = @intCast(n);
        seed[15] = @intCast(n *% 17);
        seed[31] = @intCast(n *% 9);
    }
    Ed25519.publicKeys(&seeds, &pubs);
    for (seeds, pubs) |seed, public_key| {
        const expected = try crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        try std.testing.expectEqualSlices(u8, &expected.public_key.toBytes(), &public_key);
    }
}
