const std = @import("std");
const pattern_mod = @import("../pattern.zig");
pub const Pattern = pattern_mod.Pattern;

// Re-export grinder implementations
pub const CpuGrinder = @import("cpu.zig").CpuGrinder;
pub const HybridGrinder = @import("hybrid.zig").HybridGrinder;
pub const FullGpuGrinder = @import("full_gpu.zig").FullGpuGrinder;

// ============================================================================
// Configuration
// ============================================================================

pub const BATCH_SIZE: usize = 65536; // Keys per batch - large batch for GPU efficiency
pub const NUM_BUFFERS: usize = 3; // Triple buffering for continuous GPU utilization
pub const PROGRESS_INTERVAL: u64 = 100000; // Report every N attempts
pub const NUM_CPU_THREADS: usize = 8; // CPU threads for parallel key derivation

// Shader is embedded at compile time - no external file needed at runtime
pub const EMBEDDED_SHADER = @embedFile("../shaders/vanity.metal");

// ============================================================================
// Shared Types
// ============================================================================

pub const FoundKey = struct {
    public_key: [32]u8,
    private_key: [64]u8,
    address: []const u8,
    attempts: u64,
};

/// Statistics for difficulty estimation
pub const DifficultyStats = struct {
    effective_length: usize,
    alphabet_size: u32,
    expected_attempts: f64,
    p50_attempts: f64,
};

/// Format time to P50 for display
pub fn formatTimeToP50(current_attempts: u64, p50_attempts: f64, rate: f64) void {
    if (rate <= 0) {
        std.debug.print("P50: --:--", .{});
        return;
    }

    const attempts_f = @as(f64, @floatFromInt(current_attempts));
    const remaining = p50_attempts - attempts_f;

    if (remaining > 0) {
        // Time until P50
        const seconds = remaining / rate;
        printTimeValue(seconds, "P50: ");
    } else {
        // Time since P50 (negative)
        const seconds = -remaining / rate;
        printTimeValue(seconds, "P50: +");
    }
}

fn printTimeValue(seconds: f64, prefix: []const u8) void {
    if (seconds < 60) {
        std.debug.print("{s}{d:.0}s", .{ prefix, seconds });
    } else if (seconds < 3600) {
        const mins = @as(u32, @intFromFloat(seconds / 60));
        const secs = @as(u32, @intFromFloat(@mod(seconds, 60)));
        std.debug.print("{s}{d}m{d:0>2}s", .{ prefix, mins, secs });
    } else if (seconds < 86400) {
        const hours = @as(u32, @intFromFloat(seconds / 3600));
        const mins = @as(u32, @intFromFloat(@mod(seconds, 3600) / 60));
        std.debug.print("{s}{d}h{d:0>2}m", .{ prefix, hours, mins });
    } else {
        const days = seconds / 86400;
        std.debug.print("{s}{d:.1}d", .{ prefix, days });
    }
}

/// Pattern configuration for GPU kernel (must match Metal shader)
pub const GpuPatternConfig = extern struct {
    length: u32,
    match_mode: u32, // 0=prefix, 1=suffix, 2=anywhere
    ignore_case: u32,
    pattern: [32]u8,

    pub fn fromPattern(pattern: Pattern) GpuPatternConfig {
        var config = GpuPatternConfig{
            .length = @intCast(pattern.raw.len),
            .match_mode = switch (pattern.options.match_mode) {
                .prefix => 0,
                .suffix => 1,
                .anywhere => 2,
            },
            .ignore_case = if (pattern.options.ignore_case) 1 else 0,
            .pattern = undefined,
        };
        @memset(&config.pattern, 0);
        const copy_len = @min(pattern.raw.len, 32);
        @memcpy(config.pattern[0..copy_len], pattern.raw[0..copy_len]);
        return config;
    }
};

/// Result buffer for GPU kernel (must match Metal shader)
pub const GpuResultBuffer = extern struct {
    found: u32, // 1 if match found
    thread_id: u32, // Thread that found match
    public_key: [32]u8, // Public key bytes
    private_key: [64]u8, // Private key (hash + public)
    address: [48]u8, // Base58 address
    address_len: u32, // Address length
};
