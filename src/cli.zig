const std = @import("std");
const Base58 = @import("cpu/base58.zig").Base58;
const pattern_mod = @import("pattern.zig");
const Pattern = pattern_mod.Pattern;
const PatternOptions = pattern_mod.PatternOptions;
const MatchMode = pattern_mod.MatchMode;
const grinders = @import("grinders/mod.zig");
const FoundKey = grinders.FoundKey;
const CpuGrinder = grinders.CpuGrinder;
const HybridGrinder = grinders.HybridGrinder;
const FullGpuGrinder = grinders.FullGpuGrinder;
const BATCH_SIZE = grinders.BATCH_SIZE;

// ============================================================================
// CLI Entry Point
// ============================================================================

pub fn run() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Check for help or benchmark mode first
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        }
        if (std.mem.eql(u8, arg, "--benchmark")) {
            try runBenchmark(allocator);
            return;
        }
    }

    // Get pattern from CLI args or VANITY_PATTERN env var
    var raw_pattern: []const u8 = undefined;
    var pattern_owned: ?[]u8 = null;
    defer if (pattern_owned) |p| allocator.free(p);

    if (args.len >= 2 and !std.mem.startsWith(u8, args[1], "--")) {
        raw_pattern = args[1];
    } else {
        pattern_owned = std.process.getEnvVarOwned(allocator, "VANITY_PATTERN") catch {
            printUsage();
            return;
        };
        raw_pattern = pattern_owned.?;
    }

    // Parse pattern:count syntax (e.g., "SOL:5" means find 5 matches)
    const parsed = parsePatternWithCount(raw_pattern);
    const pattern_str = parsed.pattern;
    const match_count = parsed.count;

    // Validate pattern contains only valid Base58 characters
    validatePattern(pattern_str) catch {
        return;
    };

    // Parse options from CLI args
    var use_gpu = true;
    // Default is case-insensitive (matches solana-keygen behavior)
    var ignore_case = !envIsTruthy(allocator, "CASE_SENSITIVE");
    var match_mode = getMatchMode(allocator);

    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--cpu")) {
            use_gpu = false;
        } else if (std.mem.eql(u8, arg, "--ignore-case") or std.mem.eql(u8, arg, "-i")) {
            ignore_case = true;
        } else if (std.mem.eql(u8, arg, "--case-sensitive") or std.mem.eql(u8, arg, "-s")) {
            ignore_case = false;
        } else if (std.mem.eql(u8, arg, "--suffix") or std.mem.eql(u8, arg, "--end")) {
            match_mode = .suffix;
        } else if (std.mem.eql(u8, arg, "--anywhere") or std.mem.eql(u8, arg, "--contains")) {
            match_mode = .anywhere;
        } else if (std.mem.eql(u8, arg, "--prefix") or std.mem.eql(u8, arg, "--start")) {
            match_mode = .prefix;
        }
    }

    const options = PatternOptions{
        .ignore_case = ignore_case,
        .match_mode = match_mode,
    };

    try searchVanity(allocator, pattern_str, options, use_gpu, match_count);
}

// ============================================================================
// Search Functions
// ============================================================================

fn searchVanity(allocator: std.mem.Allocator, pattern_str: []const u8, options: PatternOptions, use_gpu: bool, match_count: u32) !void {
    std.debug.print("\n=== Solana Vanity Address Search ===\n", .{});
    std.debug.print("Pattern: {s}\n", .{pattern_str});
    std.debug.print("Match mode: {s}\n", .{@tagName(options.match_mode)});
    std.debug.print("Case sensitive: {}\n", .{!options.ignore_case});
    if (match_count > 1) {
        std.debug.print("Finding: {d} matches\n", .{match_count});
    }
    std.debug.print("Using: {s}\n", .{if (use_gpu) "Full GPU (Metal)" else "CPU"});

    // Show difficulty estimate
    const stats = calculateDifficulty(pattern_str, options);
    std.debug.print("\nDifficulty estimate:\n", .{});
    std.debug.print("  Effective pattern length: {d} chars\n", .{stats.effective_length});
    std.debug.print("  Alphabet size: {d} ({s})\n", .{ stats.alphabet_size, if (options.ignore_case) "case-insensitive" else "case-sensitive" });
    std.debug.print("  Probability per attempt: 1 in {d:.0}\n", .{stats.expected_attempts});
    std.debug.print("  Expected attempts (mean): {d:.0}\n", .{stats.expected_attempts});
    std.debug.print("  P50 attempts (median): {d:.0}\n", .{stats.p50_attempts});

    // P50 time shown during search based on actual measured rate
    std.debug.print("\n", .{});

    var pattern = try Pattern.init(allocator, pattern_str, options);
    defer pattern.deinit();

    var found_count: u32 = 0;

    if (use_gpu) {
        var grinder = try FullGpuGrinder.init(allocator, pattern);
        defer grinder.deinit();
        grinder.setP50(stats.p50_attempts);

        std.debug.print("Searching...\n", .{});
        while (found_count < match_count) {
            if (try grinder.searchBatch(BATCH_SIZE * 100)) |found| {
                found_count += 1;
                std.debug.print("\n\n*** FOUND MATCH {d}/{d}! ***\n", .{ found_count, match_count });
                printFoundKey(found, pattern, allocator);
                allocator.free(found.address);

                if (found_count < match_count) {
                    std.debug.print("\nContinuing search...\n", .{});
                }
            }
        }
    } else {
        var grinder = CpuGrinder.init(allocator, pattern);
        grinder.setP50(stats.p50_attempts);

        std.debug.print("Searching...\n", .{});
        while (found_count < match_count) {
            if (try grinder.searchBatch(BATCH_SIZE * 100)) |found| {
                found_count += 1;
                std.debug.print("\n\n*** FOUND MATCH {d}/{d}! ***\n", .{ found_count, match_count });
                printFoundKey(found, pattern, allocator);
                allocator.free(found.address);

                if (found_count < match_count) {
                    std.debug.print("\nContinuing search...\n", .{});
                }
            }
        }
    }

    std.debug.print("\nDone! Found {d} matching address(es).\n", .{found_count});
}

// ============================================================================
// Output Functions
// ============================================================================

fn printFoundKey(found: FoundKey, pattern: Pattern, allocator: std.mem.Allocator) void {
    std.debug.print("Address: {s}\n", .{found.address});
    std.debug.print("Attempts: {d}\n", .{found.attempts});

    // Public key hex
    std.debug.print("Public Key (hex): ", .{});
    for (found.public_key) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});

    // Verify: re-encode public key and compare
    var verify_buf: [64]u8 = undefined;
    const verify_len = Base58.encode(&verify_buf, &found.public_key) catch {
        std.debug.print("VERIFICATION FAILED: Could not encode public key\n", .{});
        return;
    };
    const verified_address = verify_buf[0..verify_len];

    std.debug.print("Public Key (Base58): {s}\n", .{verified_address});

    if (std.mem.eql(u8, verified_address, found.address)) {
        std.debug.print("VERIFIED: Address matches Base58(PublicKey)\n", .{});
    } else {
        std.debug.print("VERIFICATION FAILED!\n", .{});
        std.debug.print("  Expected: {s}\n", .{found.address});
        std.debug.print("  Got:      {s}\n", .{verified_address});
        return;
    }

    // Private key (64 bytes = 32 byte secret + 32 byte public for Solana)
    var privkey_b58_buf: [128]u8 = undefined;
    const privkey_b58_len = Base58.encode(&privkey_b58_buf, &found.private_key) catch {
        std.debug.print("Could not encode private key to Base58\n", .{});
        return;
    };
    std.debug.print("Private Key (Base58): {s}\n", .{privkey_b58_buf[0..privkey_b58_len]});

    // Show pattern match details
    const match_desc = pattern.matchModeStr();
    if (pattern.matches(found.address)) {
        std.debug.print("Pattern '{s}' {s} address\n", .{ pattern.raw, match_desc });
    } else {
        std.debug.print("WARNING: Pattern '{s}' does not match address!\n", .{pattern.raw});
    }

    // Save to JSON file
    saveKeyAsJson(allocator, found) catch |err| {
        std.debug.print("Warning: Could not save JSON file: {}\n", .{err});
    };
}

// ============================================================================
// Benchmark
// ============================================================================

const BENCHMARK_DURATION_MS: i64 = 10_000; // 10 seconds per benchmark

fn runBenchmark(allocator: std.mem.Allocator) !void {
    std.debug.print("\n=== Vanity Address Grinder Benchmark ===\n", .{});
    std.debug.print("Running each mode for {d} seconds...\n\n", .{BENCHMARK_DURATION_MS / 1000});

    var pattern = try Pattern.init(allocator, "ZZZZ", .{});
    defer pattern.deinit();

    // CPU Benchmark
    std.debug.print("CPU benchmark...\n", .{});
    var cpu_grinder = CpuGrinder.init(allocator, pattern);
    const cpu_start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - cpu_start < BENCHMARK_DURATION_MS) {
        if (try cpu_grinder.searchBatch(BATCH_SIZE)) |found| {
            allocator.free(found.address);
        }
    }
    const cpu_elapsed = @as(f64, @floatFromInt(std.time.milliTimestamp() - cpu_start)) / 1000.0;
    const cpu_rate = @as(f64, @floatFromInt(cpu_grinder.attempts)) / cpu_elapsed;
    std.debug.print("  CPU: {d:.2} k/s\n", .{cpu_rate / 1000.0});

    // Hybrid GPU+CPU Benchmark
    std.debug.print("Hybrid (GPU seeds + CPU derive) benchmark...\n", .{});
    var hybrid_grinder = try HybridGrinder.init(allocator, pattern);
    defer hybrid_grinder.deinit();

    const hybrid_start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - hybrid_start < BENCHMARK_DURATION_MS) {
        if (try hybrid_grinder.searchBatch(BATCH_SIZE)) |found| {
            allocator.free(found.address);
        }
    }
    const hybrid_elapsed = @as(f64, @floatFromInt(std.time.milliTimestamp() - hybrid_start)) / 1000.0;
    const hybrid_attempts = hybrid_grinder.attempts.load(.acquire);
    const hybrid_rate = @as(f64, @floatFromInt(hybrid_attempts)) / hybrid_elapsed;
    std.debug.print("  Hybrid: {d:.2} k/s\n", .{hybrid_rate / 1000.0});

    // Full GPU Benchmark
    std.debug.print("Full GPU (all on GPU) benchmark...\n", .{});
    var fullgpu_grinder = try FullGpuGrinder.init(allocator, pattern);
    defer fullgpu_grinder.deinit();

    const fullgpu_start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - fullgpu_start < BENCHMARK_DURATION_MS) {
        if (try fullgpu_grinder.searchBatch(BATCH_SIZE)) |found| {
            allocator.free(found.address);
        }
    }
    const fullgpu_elapsed = @as(f64, @floatFromInt(std.time.milliTimestamp() - fullgpu_start)) / 1000.0;
    const fullgpu_attempts = fullgpu_grinder.attempts.load(.acquire);
    const fullgpu_rate = @as(f64, @floatFromInt(fullgpu_attempts)) / fullgpu_elapsed;
    std.debug.print("  Full GPU: {d:.2} k/s\n", .{fullgpu_rate / 1000.0});

    // Results
    std.debug.print("\n=== Results ===\n", .{});
    std.debug.print("CPU:      {d:.2} k/s (baseline)\n", .{cpu_rate / 1000.0});
    std.debug.print("Hybrid:   {d:.2} k/s ({d:.0}x faster)\n", .{ hybrid_rate / 1000.0, hybrid_rate / cpu_rate });
    std.debug.print("Full GPU: {d:.2} k/s ({d:.0}x faster)\n", .{ fullgpu_rate / 1000.0, fullgpu_rate / cpu_rate });

    // Determine fastest
    const best_rate = @max(cpu_rate, @max(hybrid_rate, fullgpu_rate));
    if (best_rate == fullgpu_rate) {
        std.debug.print("\nFull GPU mode is fastest!\n", .{});
    } else if (best_rate == hybrid_rate) {
        std.debug.print("\nHybrid mode is fastest!\n", .{});
    } else {
        std.debug.print("\nCPU mode is fastest!\n", .{});
    }
}

// ============================================================================
// Difficulty Estimation
// ============================================================================

const DifficultyStats = struct {
    effective_length: usize,
    alphabet_size: u32,
    expected_attempts: f64,
    p50_attempts: f64,
};

fn calculateDifficulty(pattern_str: []const u8, options: PatternOptions) DifficultyStats {
    // Count non-wildcard characters
    var effective_length: usize = 0;
    for (pattern_str) |c| {
        if (c != '?') effective_length += 1;
    }

    // Base58 alphabet considerations:
    // - Full Base58: 58 chars (123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz)
    // - Case-insensitive: effectively ~34 unique values
    //   (9 digits + 25 letters, since I/O/l are excluded and case folds)
    const alphabet_size: u32 = if (options.ignore_case) 34 else 58;

    // For prefix/suffix match: probability = 1 / (alphabet_size ^ effective_length)
    // For anywhere match: slightly higher probability (depends on address length ~44 chars)
    var combinations: f64 = 1.0;
    for (0..effective_length) |_| {
        combinations *= @as(f64, @floatFromInt(alphabet_size));
    }

    // Anywhere match: can match at ~(44 - pattern_len) positions
    if (options.match_mode == .anywhere and pattern_str.len < 44) {
        const positions = 44 - pattern_str.len + 1;
        combinations /= @as(f64, @floatFromInt(positions));
    }

    // P50 (median) = expected * ln(2) for geometric distribution
    const p50_attempts = combinations * 0.693;

    return DifficultyStats{
        .effective_length = effective_length,
        .alphabet_size = alphabet_size,
        .expected_attempts = combinations,
        .p50_attempts = p50_attempts,
    };
}

fn printDuration(seconds: f64) void {
    std.debug.print("  Estimated P50 time: ", .{});
    if (seconds < 1) {
        std.debug.print("<1 second", .{});
    } else if (seconds < 60) {
        std.debug.print("{d:.1} seconds", .{seconds});
    } else if (seconds < 3600) {
        std.debug.print("{d:.1} minutes", .{seconds / 60});
    } else if (seconds < 86400) {
        std.debug.print("{d:.1} hours", .{seconds / 3600});
    } else if (seconds < 86400 * 365) {
        std.debug.print("{d:.1} days", .{seconds / 86400});
    } else {
        std.debug.print("{d:.1} years", .{seconds / (86400 * 365)});
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn printUsage() void {
    std.debug.print("grincel - Solana vanity address grinder with Metal GPU acceleration\n\n", .{});
    std.debug.print("Usage: grincel <pattern>[:<count>] [options]\n", .{});
    std.debug.print("   or: VANITY_PATTERN=<pattern> grincel [options]\n", .{});
    std.debug.print("\nOptions:\n", .{});
    std.debug.print("  -h, --help            Show this help message\n", .{});
    std.debug.print("  -s, --case-sensitive  Case sensitive matching\n", .{});
    std.debug.print("  --cpu                 Use CPU only (no GPU)\n", .{});
    std.debug.print("  --prefix              Match at start of address (default)\n", .{});
    std.debug.print("  --suffix              Match at end of address\n", .{});
    std.debug.print("  --anywhere            Match anywhere in address\n", .{});
    std.debug.print("  --benchmark           Run CPU vs GPU benchmark\n", .{});
    std.debug.print("\nPattern syntax:\n", .{});
    std.debug.print("  PATTERN               Find one match for PATTERN\n", .{});
    std.debug.print("  PATTERN:N             Find N matches for PATTERN\n", .{});
    std.debug.print("  ?                     Wildcard (matches any character)\n", .{});
    std.debug.print("\nValid characters: 1-9, A-H, J-N, P-Z, a-k, m-z (Base58, no 0/O/I/l)\n", .{});
    std.debug.print("\nOutput: Keys are saved as <address>.json (Solana keypair format)\n", .{});
    std.debug.print("\nExamples:\n", .{});
    std.debug.print("  grincel SOL                    # Find one address starting with 'sol'\n", .{});
    std.debug.print("  grincel SOL:5                  # Find 5 addresses starting with 'sol'\n", .{});
    std.debug.print("  grincel ABC -s                 # Case-sensitive: starts with 'ABC'\n", .{});
    std.debug.print("  grincel XYZ --suffix           # Address ends with 'xyz'\n", .{});
    std.debug.print("  grincel A?C                    # Wildcard: A_C where _ is any char\n", .{});
}

fn envIsTruthy(allocator: std.mem.Allocator, name: []const u8) bool {
    const val = std.process.getEnvVarOwned(allocator, name) catch return false;
    defer allocator.free(val);
    return std.mem.eql(u8, val, "1") or
        std.mem.eql(u8, val, "true") or
        std.mem.eql(u8, val, "yes") or
        std.mem.eql(u8, val, "TRUE") or
        std.mem.eql(u8, val, "YES");
}

fn getMatchMode(allocator: std.mem.Allocator) MatchMode {
    const val = std.process.getEnvVarOwned(allocator, "MATCH_MODE") catch return .prefix;
    defer allocator.free(val);

    if (std.mem.eql(u8, val, "suffix") or std.mem.eql(u8, val, "end") or std.mem.eql(u8, val, "ends")) {
        return .suffix;
    } else if (std.mem.eql(u8, val, "anywhere") or std.mem.eql(u8, val, "contains") or std.mem.eql(u8, val, "any")) {
        return .anywhere;
    }
    return .prefix;
}

// ============================================================================
// Pattern Validation
// ============================================================================

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn isValidBase58Char(c: u8) bool {
    for (BASE58_ALPHABET) |valid| {
        if (c == valid) return true;
    }
    return false;
}

const PatternValidationError = error{
    InvalidCharacter,
    PatternTooLong,
};

fn validatePattern(pattern_str: []const u8) PatternValidationError!void {
    if (pattern_str.len > 44) {
        return PatternValidationError.PatternTooLong;
    }

    for (pattern_str, 0..) |c, i| {
        // Allow '?' as wildcard
        if (c == '?') continue;

        if (!isValidBase58Char(c)) {
            std.debug.print("Error: Invalid character '{c}' at position {d}\n", .{ c, i });
            std.debug.print("Base58 alphabet does not include: 0, O, I, l\n", .{});
            return PatternValidationError.InvalidCharacter;
        }
    }
}

/// Parse pattern string, extracting count if present (e.g., "SOL:5" -> "SOL", 5)
fn parsePatternWithCount(input: []const u8) struct { pattern: []const u8, count: u32 } {
    // Find the last ':' that's followed by digits
    var i: usize = input.len;
    while (i > 0) {
        i -= 1;
        if (input[i] == ':') {
            const count_str = input[i + 1 ..];
            if (count_str.len > 0) {
                const count = std.fmt.parseInt(u32, count_str, 10) catch {
                    // Not a valid number, treat whole thing as pattern
                    return .{ .pattern = input, .count = 1 };
                };
                if (count > 0) {
                    return .{ .pattern = input[0..i], .count = count };
                }
            }
            break;
        }
    }
    return .{ .pattern = input, .count = 1 };
}

// ============================================================================
// JSON Output
// ============================================================================

fn saveKeyAsJson(allocator: std.mem.Allocator, found: FoundKey) !void {
    // Create filename: <address>.json
    const filename = try std.fmt.allocPrint(allocator, "{s}.json", .{found.address});
    defer allocator.free(filename);

    // Build JSON content - Solana keypair format is a byte array of the 64-byte private key
    var json_buf = std.ArrayList(u8).init(allocator);
    defer json_buf.deinit();

    try json_buf.appendSlice("[");
    for (found.private_key, 0..) |byte, i| {
        if (i > 0) try json_buf.appendSlice(",");
        var num_buf: [4]u8 = undefined;
        const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{byte}) catch unreachable;
        try json_buf.appendSlice(num_str);
    }
    try json_buf.appendSlice("]\n");

    // Write to file
    const file = try std.fs.cwd().createFile(filename, .{});
    defer file.close();
    try file.writeAll(json_buf.items);

    std.debug.print("Saved: {s}\n", .{filename});
}
