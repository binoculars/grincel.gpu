const std = @import("std");

pub const Base58 = struct {
    const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /// Encode bytes to Base58 string
    /// Returns the length of the encoded string
    pub fn encode(out: []u8, input: []const u8) !usize {
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

