const std = @import("std");

pub const Base58 = struct {
    const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /// Encode bytes to Base58 string
    /// Returns the length of the encoded string
    pub fn encode(out: []u8, input: []const u8) !usize {
        if (input.len == 32) return encode32(out, input[0..32]);
        if (input.len == 0) return 0;

        // Count leading zeros - they become '1' in base58
        var zeros: usize = 0;
        while (zeros < input.len and input[zeros] == 0) : (zeros += 1) {}

        // Allocate enough space for base58 output
        // Base58 encoded size is roughly input.len * 138 / 100 + 1
        var b58: [128]u8 = undefined;
        var b58_len: usize = 0;

        // Process each byte
        for (input[zeros..]) |byte| {
            var carry: u32 = byte;

            // Apply carry to existing digits
            var i: usize = 0;
            while (i < b58_len or carry != 0) : (i += 1) {
                if (i < b58_len) {
                    carry += @as(u32, b58[i]) * 256;
                }
                b58[i] = @intCast(carry % 58);
                carry /= 58;
            }
            b58_len = i;
        }

        // Check output buffer size
        const output_len = zeros + b58_len;
        if (output_len > out.len) return error.NoSpace;

        // Write leading '1's for zeros
        for (0..zeros) |i| {
            out[i] = '1';
        }

        // Write base58 digits in reverse order
        for (0..b58_len) |i| {
            out[zeros + i] = ALPHABET[b58[b58_len - 1 - i]];
        }

        return output_len;
    }

    /// 32-byte encoding used for Solana public keys. Four input bytes are
    /// absorbed per step instead of one.
    fn encode32(out: []u8, input: *const [32]u8) !usize {
        var zeros: usize = 0;
        while (zeros < 32 and input[zeros] == 0) : (zeros += 1) {}

        var b58: [64]u8 = undefined;
        var b58_len: usize = 0;
        var offset = zeros;

        while (offset < 32 and (offset & 3) != 0) : (offset += 1) {
            absorb(&b58, &b58_len, input[offset], 256);
        }
        while (offset < 32) : (offset += 4) {
            const word = std.mem.readInt(u32, input[offset..][0..4], .big);
            absorb(&b58, &b58_len, word, 0x100000000);
        }

        const output_len = zeros + b58_len;
        if (output_len > out.len) return error.NoSpace;

        for (0..zeros) |i| out[i] = '1';
        for (0..b58_len) |i| {
            out[zeros + i] = ALPHABET[b58[b58_len - 1 - i]];
        }
        return output_len;
    }

    fn absorb(b58: *[64]u8, b58_len: *usize, value: u64, place: u64) void {
        var carry: u64 = value;
        var i: usize = 0;
        const len = b58_len.*;
        while (i < len) : (i += 1) {
            carry += @as(u64, b58[i]) * place;
            b58[i] = @intCast(carry % 58);
            carry /= 58;
        }
        while (carry != 0) : (i += 1) {
            b58[i] = @intCast(carry % 58);
            carry /= 58;
        }
        b58_len.* = i;
    }

    /// Decode Base58 string to bytes
    pub fn decode(out: []u8, input: []const u8) !usize {
        if (input.len == 0) return 0;

        // Count leading '1's - they become 0x00 bytes
        var zeros: usize = 0;
        while (zeros < input.len and input[zeros] == '1') : (zeros += 1) {}

        // Decode base58 to bytes
        var bytes: [64]u8 = undefined;
        var bytes_len: usize = 0;

        for (input[zeros..]) |c| {
            // Find character in alphabet
            const val: u8 = for (ALPHABET, 0..) |a, i| {
                if (a == c) break @intCast(i);
            } else return error.InvalidCharacter;

            var carry: u32 = val;
            var i: usize = 0;
            while (i < bytes_len or carry != 0) : (i += 1) {
                if (i < bytes_len) {
                    carry += @as(u32, bytes[i]) * 58;
                }
                bytes[i] = @intCast(carry & 0xFF);
                carry >>= 8;
            }
            bytes_len = i;
        }

        // Check output buffer size
        const output_len = zeros + bytes_len;
        if (output_len > out.len) return error.NoSpace;

        // Write leading zeros
        @memset(out[0..zeros], 0);

        // Write decoded bytes in reverse order
        for (0..bytes_len) |i| {
            out[zeros + i] = bytes[bytes_len - 1 - i];
        }

        return output_len;
    }
};

test "32-byte base58 roundtrips and keeps leading ones" {
    const zeros = [_]u8{0} ** 32;
    var out: [64]u8 = undefined;
    const n = try Base58.encode(&out, &zeros);
    try std.testing.expectEqualStrings("1" ** 32, out[0..n]);

    var raw: [32]u8 = undefined;
    var back: [32]u8 = undefined;
    for (0..8) |k| {
        for (&raw, 0..) |*b, i| b.* = @intCast((i *% 17 +% k *% 9) & 0xff);
        if (k == 3) raw[0] = 0;
        const len = try Base58.encode(&out, &raw);
        const decoded = try Base58.decode(&back, out[0..len]);
        try std.testing.expectEqualSlices(u8, &raw, back[0..decoded]);
    }
}

