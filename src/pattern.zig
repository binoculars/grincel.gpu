const std = @import("std");

pub const MatchMode = enum {
    prefix, // Match at start of address
    suffix, // Match at end of address
    anywhere, // Match anywhere in address
};

pub const PatternOptions = struct {
    ignore_case: bool = true, // Case-insensitive by default (matches solana-keygen behavior)
    match_mode: MatchMode = .prefix,
};

pub const Pattern = struct {
    raw: []const u8,
    mask: []const bool, // true for fixed chars, false for wildcards
    options: PatternOptions,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, pattern: []const u8, options: PatternOptions) !Pattern {
        var mask = try allocator.alloc(bool, pattern.len);

        for (pattern, 0..) |c, i| {
            mask[i] = (c != '?');
        }

        return Pattern{
            .raw = try allocator.dupe(u8, pattern),
            .mask = mask,
            .options = options,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Pattern) void {
        self.allocator.free(self.raw);
        self.allocator.free(self.mask);
    }

    pub fn matches(self: Pattern, address: []const u8) bool {
        return switch (self.options.match_mode) {
            .prefix => self.matchesAt(address, 0),
            .suffix => if (address.len >= self.raw.len)
                self.matchesAt(address, address.len - self.raw.len)
            else
                false,
            .anywhere => self.matchesAnywhere(address),
        };
    }

    fn matchesAt(self: Pattern, address: []const u8, start: usize) bool {
        if (start + self.raw.len > address.len) return false;

        for (self.raw, 0..) |c, i| {
            if (self.mask[i]) {
                const addr_char = if (self.options.ignore_case)
                    std.ascii.toLower(address[start + i])
                else
                    address[start + i];

                const pattern_char = if (self.options.ignore_case)
                    std.ascii.toLower(c)
                else
                    c;

                if (addr_char != pattern_char) {
                    return false;
                }
            }
        }
        return true;
    }

    fn matchesAnywhere(self: Pattern, address: []const u8) bool {
        if (address.len < self.raw.len) return false;

        const max_start = address.len - self.raw.len;
        var start: usize = 0;
        while (start <= max_start) : (start += 1) {
            if (self.matchesAt(address, start)) return true;
        }
        return false;
    }

    /// Get a description of the match mode
    pub fn matchModeStr(self: Pattern) []const u8 {
        return switch (self.options.match_mode) {
            .prefix => "starts with",
            .suffix => "ends with",
            .anywhere => "contains",
        };
    }
};

// Legacy extern struct for GPU compatibility (if needed)
pub const PatternGpu = extern struct {
    pattern_length: u32,
    _padding1: [3]u32,
    fixed_chars: [8]u32,
    _padding2: [4]u32,
    mask: [8]u32,
    _padding3: [4]u32,
    case_sensitive: u32,
    _padding4: [3]u32,

    comptime {
        std.debug.assert(@sizeOf(@This()) == 128);
        std.debug.assert(@alignOf(@This()) == 4);
    }

    pub fn fromPattern(pattern: Pattern) PatternGpu {
        var result = std.mem.zeroes(PatternGpu);
        result.pattern_length = @intCast(pattern.raw.len);
        result.case_sensitive = @intFromBool(!pattern.options.ignore_case);

        var fixed_chars = [_]u32{0} ** 8;
        var mask_bits = [_]u32{0} ** 8;

        for (pattern.raw, 0..) |c, i| {
            const byte_pos: u32 = @intCast(i >> 2);
            const bit_shift: u5 = @intCast((i & 3) * 8);

            if (pattern.mask[i]) {
                fixed_chars[byte_pos] |= @as(u32, c) << bit_shift;
                mask_bits[byte_pos] |= @as(u32, 0xFF) << bit_shift;
            }
        }

        @memcpy(result.fixed_chars[0..], &fixed_chars);
        @memcpy(result.mask[0..], &mask_bits);

        return result;
    }
};

test "Pattern prefix matching" {
    const allocator = std.testing.allocator;
    var pattern = try Pattern.init(allocator, "ABC", .{ .match_mode = .prefix });
    defer pattern.deinit();

    try std.testing.expect(pattern.matches("ABCdef123"));
    try std.testing.expect(!pattern.matches("xyzABC123"));
    try std.testing.expect(!pattern.matches("AB"));
}

test "Pattern suffix matching" {
    const allocator = std.testing.allocator;
    var pattern = try Pattern.init(allocator, "XYZ", .{ .match_mode = .suffix });
    defer pattern.deinit();

    try std.testing.expect(pattern.matches("123abcXYZ"));
    try std.testing.expect(!pattern.matches("XYZabc123"));
    try std.testing.expect(!pattern.matches("YZ"));
}

test "Pattern anywhere matching" {
    const allocator = std.testing.allocator;
    var pattern = try Pattern.init(allocator, "TEST", .{ .match_mode = .anywhere });
    defer pattern.deinit();

    try std.testing.expect(pattern.matches("TESTabc"));
    try std.testing.expect(pattern.matches("abcTEST"));
    try std.testing.expect(pattern.matches("abTESTcd"));
    try std.testing.expect(!pattern.matches("TES"));
}

test "Pattern case insensitive" {
    const allocator = std.testing.allocator;
    var pattern = try Pattern.init(allocator, "AbC", .{ .ignore_case = true, .match_mode = .prefix });
    defer pattern.deinit();

    try std.testing.expect(pattern.matches("ABCdef"));
    try std.testing.expect(pattern.matches("abcdef"));
    try std.testing.expect(pattern.matches("AbCdef"));
}

test "Pattern wildcards" {
    const allocator = std.testing.allocator;
    var pattern = try Pattern.init(allocator, "A?C", .{ .match_mode = .prefix });
    defer pattern.deinit();

    try std.testing.expect(pattern.matches("ABCdef"));
    try std.testing.expect(pattern.matches("AXCdef"));
    try std.testing.expect(pattern.matches("A1Cdef"));
    try std.testing.expect(!pattern.matches("ABDdef"));
}
