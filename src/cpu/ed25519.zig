const std = @import("std");
const crypto = std.crypto;

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

        const key_pair = crypto.sign.Ed25519.KeyPair.generateDeterministic(seed_bytes) catch unreachable;
        return .{
            .public = key_pair.public_key.toBytes(),
            .private = key_pair.secret_key.toBytes(),
        };
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
    pub fn matchesSolanaKeypair(public_key: [32]u8, private_key: [64]u8) bool {
        const seed: [32]u8 = private_key[0..32].*;
        const key_pair = crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return false;
        const derived = key_pair.public_key.toBytes();
        return std.mem.eql(u8, &derived, &public_key) and std.mem.eql(u8, &derived, private_key[32..64]);
    }
};

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
