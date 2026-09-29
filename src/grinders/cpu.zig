const std = @import("std");
const Ed25519 = @import("../cpu/ed25519.zig").Ed25519;
const Base58 = @import("../cpu/base58.zig").Base58;
const mod = @import("mod.zig");
const Pattern = mod.Pattern;
const FoundKey = mod.FoundKey;
const PROGRESS_INTERVAL = mod.PROGRESS_INTERVAL;

/// Vanity address grinder using CPU only
pub const CpuGrinder = struct {
    prng: std.Random.Xoshiro256,
    pattern: Pattern,
    attempts: u64,
    start_time: i64,
    allocator: std.mem.Allocator,
    p50_attempts: f64,
    /// When set, the search returns once this flag is true.
    stop: ?*std.atomic.Value(bool) = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pattern: Pattern) Self {
        const seed = @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));
        return .{
            .prng = std.Random.Xoshiro256.init(seed),
            .pattern = pattern,
            .attempts = 0,
            .start_time = std.time.milliTimestamp(),
            .allocator = allocator,
            .p50_attempts = 0,
        };
    }

    /// Set the P50 attempts for progress display
    pub fn setP50(self: *Self, p50: f64) void {
        self.p50_attempts = p50;
    }

    const key_batch = 16;

    /// Search indefinitely for a matching vanity address
    pub fn search(self: *Self) !?FoundKey {
        while (true) {
            if (self.shouldStop()) return null;
            if (try self.searchChunk(key_batch, true)) |found| return found;
        }
    }

    /// Search with a maximum number of attempts
    pub fn searchBatch(self: *Self, max_attempts: u64) !?FoundKey {
        const end_attempts = self.attempts + max_attempts;
        while (self.attempts < end_attempts) {
            if (self.shouldStop()) return null;
            const room: usize = @intCast(@min(end_attempts - self.attempts, key_batch));
            if (try self.searchChunk(room, false)) |found| return found;
        }
        return null;
    }

    fn searchChunk(self: *Self, n: usize, report: bool) !?FoundKey {
        var seeds: [key_batch][32]u8 = undefined;
        var pubs: [key_batch][32]u8 = undefined;
        for (0..n) |i| self.prng.fill(&seeds[i]);
        Ed25519.publicKeys(seeds[0..n], pubs[0..n]);

        for (0..n) |i| {
            var address_buf: [64]u8 = undefined;
            const addr_len = try Base58.encode(&address_buf, &pubs[i]);
            const address = address_buf[0..addr_len];
            self.attempts += 1;

            if (self.pattern.matches(address)) {
                var private: [64]u8 = undefined;
                private[0..32].* = seeds[i];
                private[32..].* = pubs[i];
                return FoundKey{
                    .public_key = pubs[i],
                    .private_key = private,
                    .address = try self.allocator.dupe(u8, address),
                    .attempts = self.attempts,
                    .source = .cpu,
                };
            }

            if (report and self.attempts % PROGRESS_INTERVAL == 0) {
                self.reportProgress();
            }
        }
        return null;
    }

    fn shouldStop(self: *Self) bool {
        if (self.stop) |flag| return flag.load(.monotonic);
        return false;
    }

    fn reportProgress(self: *Self) void {
        const elapsed_ms = std.time.milliTimestamp() - self.start_time;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
        const rate = if (elapsed_secs > 0)
            @as(f64, @floatFromInt(self.attempts)) / elapsed_secs
        else
            0;

        std.debug.print("\r[CPU] {d} keys, {d:.2} k/s, ", .{
            self.attempts,
            rate / 1000.0,
        });
        mod.formatTimeToP50(self.attempts, self.p50_attempts, rate);
        std.debug.print("        ", .{}); // Clear trailing chars
    }

    pub fn getRate(self: *Self) f64 {
        const elapsed_ms = std.time.milliTimestamp() - self.start_time;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
        return if (elapsed_secs > 0)
            @as(f64, @floatFromInt(self.attempts)) / elapsed_secs
        else
            0;
    }
};
