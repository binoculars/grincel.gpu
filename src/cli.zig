const std = @import("std");
const build_options = @import("build_options");
const Base58 = @import("cpu/base58.zig").Base58;
const Ed25519 = @import("cpu/ed25519.zig").Ed25519;
const pattern_mod = @import("pattern.zig");
const Pattern = pattern_mod.Pattern;
const PatternOptions = pattern_mod.PatternOptions;
const MatchMode = pattern_mod.MatchMode;
const grinders = @import("grinders/mod.zig");
const FoundKey = grinders.FoundKey;
const CpuGrinder = grinders.CpuGrinder;
const VulkanGrinder = grinders.VulkanGrinder;
const BATCH_SIZE = grinders.BATCH_SIZE;

// MetalGrinder only available on macOS
const MetalGrinder = grinders.MetalGrinder;

// Backend selection
const GpuBackend = enum { metal, vulkan };
const IS_MACOS = build_options.is_macos;

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
    var threads_per_group: ?usize = null; // null = use default (64)
    var gpu_backend: ?GpuBackend = null; // null = auto-detect

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--cpu")) {
            use_gpu = false;
        } else if (std.mem.eql(u8, arg, "--vulkan")) {
            gpu_backend = .vulkan;
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
        } else if (std.mem.eql(u8, arg, "--threads") or std.mem.eql(u8, arg, "-t")) {
            if (i + 1 < args.len) {
                i += 1;
                threads_per_group = std.fmt.parseInt(usize, args[i], 10) catch {
                    std.debug.print("Error: Invalid value for --threads: {s}\n", .{args[i]});
                    return;
                };
            } else {
                std.debug.print("Error: --threads requires a value\n", .{});
                return;
            }
        }
    }

    // Auto-detect GPU backend if not specified
    const selected_backend: ?GpuBackend = if (!use_gpu) null else if (gpu_backend) |b| b else blk: {
        // Default: Metal on macOS, Vulkan elsewhere
        if (IS_MACOS) {
            break :blk .metal;
        } else {
            break :blk .vulkan;
        }
    };

    const options = PatternOptions{
        .ignore_case = ignore_case,
        .match_mode = match_mode,
    };

    try searchVanity(allocator, pattern_str, options, selected_backend, match_count, threads_per_group);
}

// ============================================================================
// Search Functions
// ============================================================================

fn searchVanity(allocator: std.mem.Allocator, pattern_str: []const u8, options: PatternOptions, backend: ?GpuBackend, match_count: u32, threads_per_group: ?usize) !void {
    std.debug.print("\n=== Solana Vanity Address Search ===\n", .{});
    std.debug.print("Pattern: {s}\n", .{pattern_str});
    std.debug.print("Match mode: {s}\n", .{@tagName(options.match_mode)});
    std.debug.print("Case sensitive: {}\n", .{!options.ignore_case});
    if (match_count > 1) {
        std.debug.print("Finding: {d} matches\n", .{match_count});
    }
    const backend_name = if (backend) |b| switch (b) {
        .metal => "Metal GPU + CPU",
        .vulkan => "Vulkan GPU + CPU",
    } else "CPU";
    std.debug.print("Using: {s}\n", .{backend_name});

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

    if (backend) |b| {
        switch (b) {
            .metal => {
                if (IS_MACOS) {
                    var thread_safe = std.heap.ThreadSafeAllocator{ .child_allocator = allocator };
                    const alloc = thread_safe.allocator();
                    var grinder = try MetalGrinder.init(alloc, pattern, threads_per_group);
                    defer grinder.deinit();
                    grinder.setP50(stats.p50_attempts);
                    found_count = try searchGpuAndCpu(MetalGrinder, &grinder, alloc, pattern, match_count, stats.p50_attempts, "Metal", threads_per_group == null);
                } else {
                    unreachable; // Metal not available on this platform
                }
            },
            .vulkan => {
                var thread_safe = std.heap.ThreadSafeAllocator{ .child_allocator = allocator };
                const alloc = thread_safe.allocator();
                var grinder = try VulkanGrinder.init(alloc, pattern, threads_per_group);
                defer grinder.deinit();
                grinder.setP50(stats.p50_attempts);
                found_count = try searchGpuAndCpu(VulkanGrinder, &grinder, alloc, pattern, match_count, stats.p50_attempts, "Vulkan", threads_per_group == null);
            },
        }
    } else {
        var thread_safe = std.heap.ThreadSafeAllocator{ .child_allocator = allocator };
        found_count = try searchCpu(thread_safe.allocator(), pattern, match_count, stats.p50_attempts);
    }

    std.debug.print("\nDone! Found {d} matching address(es).\n", .{found_count});
}

const SharedHits = struct {
    mutex: std.Thread.Mutex = .{},
    keys: std.array_list.Managed(FoundKey),
    cpu_attempts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn push(self: *SharedHits, key: FoundKey) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.keys.append(key) catch {
            self.keys.allocator.free(key.address);
        };
    }

    fn pop(self: *SharedHits) ?FoundKey {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.keys.pop();
    }
};

const CpuWorker = struct {
    grinder: CpuGrinder,
    hits: *SharedHits,
    stop: *std.atomic.Value(bool),
};

fn cpuWorkerMain(worker: *CpuWorker) void {
    worker.grinder.stop = worker.stop;
    var published: u64 = 0;
    while (!worker.stop.load(.acquire)) {
        const found = worker.grinder.searchBatch(4096) catch return;
        const attempts = worker.grinder.attempts;
        if (attempts > published) {
            _ = worker.hits.cpu_attempts.fetchAdd(attempts - published, .monotonic);
            published = attempts;
        }
        if (found) |key| worker.hits.push(key);
    }
}

fn logicalCpus() usize {
    const n = std.Thread.getCpuCount() catch 1;
    return if (n == 0) 1 else n;
}

fn fillWorkerCandidates(n: usize, out: []usize) usize {
    const raw = [_]usize{ n, if (n > 1) n - 1 else 1, @max(n / 2, 1) };
    var count: usize = 0;
    for (raw) |c| {
        if (c == 0) continue;
        var seen = false;
        for (out[0..count]) |prev| {
            if (prev == c) seen = true;
        }
        if (!seen) {
            out[count] = c;
            count += 1;
        }
    }
    return count;
}

fn keepFound(allocator: std.mem.Allocator, slot: *?FoundKey, key: ?FoundKey) void {
    if (key) |found| {
        if (slot.* == null) {
            slot.* = found;
        } else {
            allocator.free(found.address);
        }
    }
}

fn rateOf(keys: u64, nanos: u64) f64 {
    const secs = @as(f64, @floatFromInt(nanos)) / 1e9;
    if (secs <= 0) return 0;
    return @as(f64, @floatFromInt(keys)) / secs;
}

/// Time a few threadgroup widths and keep the fastest. `-t` skips this.
fn tuneThreadgroup(gpu: anytype, allocator: std.mem.Allocator, found: *?FoundKey) !void {
    const max_threads = gpu.maxThreadgroupSize();
    const options = [_]usize{ 32, 64, 128, 256, 512 };
    var list: [options.len]usize = undefined;
    var n_opts: usize = 0;
    for (options) |n| {
        if (n <= max_threads and BATCH_SIZE % n == 0) {
            list[n_opts] = n;
            n_opts += 1;
        }
    }
    if (n_opts == 0) return;

    const warm = try gpu.sample(1);
    keepFound(allocator, found, warm.found);
    if (found.* != null) return;

    var best = list[0];
    var best_rate: f64 = -1;
    for (list[0..n_opts]) |n| {
        try gpu.setThreadgroupSize(n);
        const s = try gpu.sample(2);
        keepFound(allocator, found, s.found);
        const rate = rateOf(s.keys, s.nanos);
        if (rate > best_rate) {
            best_rate = rate;
            best = n;
        }
        if (found.* != null) break;
    }
    try gpu.setThreadgroupSize(best);
}

fn tuneHybridWorkers(gpu: anytype, allocator: std.mem.Allocator, pattern: Pattern, found: *?FoundKey) !usize {
    var list: [3]usize = undefined;
    const n_opts = fillWorkerCandidates(logicalCpus(), &list);
    var best = list[0];
    var best_rate: f64 = -1;
    for (list[0..n_opts]) |workers| {
        if (found.* != null) break;
        const rate = try sampleWithWorkers(gpu, allocator, pattern, workers, 2, found);
        if (rate > best_rate) {
            best_rate = rate;
            best = workers;
        }
    }
    return best;
}

fn tuneCpuWorkers(allocator: std.mem.Allocator, pattern: Pattern, found: *?FoundKey) !usize {
    var list: [3]usize = undefined;
    const n_opts = fillWorkerCandidates(logicalCpus(), &list);
    var best = list[0];
    var best_rate: f64 = -1;
    for (list[0..n_opts]) |workers| {
        if (found.* != null) break;
        const rate = try sampleCpuWorkers(allocator, pattern, workers, 250, found);
        if (rate > best_rate) {
            best_rate = rate;
            best = workers;
        }
    }
    return best;
}

fn startWorkers(allocator: std.mem.Allocator, pattern: Pattern, worker_count: usize, stop: *std.atomic.Value(bool), hits: *SharedHits, workers: []CpuWorker, threads: []std.Thread) !usize {
    const seed = @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));
    var started: usize = 0;
    errdefer {
        stop.store(true, .release);
        for (threads[0..started]) |thread| thread.join();
    }
    for (workers[0..worker_count], threads[0..worker_count], 0..) |*worker, *thread, i| {
        worker.* = .{
            .grinder = CpuGrinder.init(allocator, pattern),
            .hits = hits,
            .stop = stop,
        };
        worker.grinder.prng = std.Random.Xoshiro256.init(seed +% (@as(u64, i) +% 1) *% 0x9E3779B97F4A7C15);
        worker.grinder.stop = stop;
        thread.* = try std.Thread.spawn(.{}, cpuWorkerMain, .{worker});
        started += 1;
    }
    return started;
}

fn stopWorkers(stop: *std.atomic.Value(bool), threads: []std.Thread, started: usize) void {
    stop.store(true, .release);
    for (threads[0..started]) |thread| thread.join();
}

fn sampleWithWorkers(gpu: anytype, allocator: std.mem.Allocator, pattern: Pattern, worker_count: usize, batches: usize, found: *?FoundKey) !f64 {
    var stop = std.atomic.Value(bool).init(false);
    var hits = SharedHits{ .keys = std.array_list.Managed(FoundKey).init(allocator) };
    const workers = try allocator.alloc(CpuWorker, worker_count);
    defer allocator.free(workers);
    const threads = try allocator.alloc(std.Thread, worker_count);
    defer allocator.free(threads);

    const started = try startWorkers(allocator, pattern, worker_count, &stop, &hits, workers, threads);
    const s = gpu.sample(batches) catch |err| {
        stopWorkers(&stop, threads, started);
        while (hits.pop()) |key| allocator.free(key.address);
        hits.keys.deinit();
        return err;
    };
    stopWorkers(&stop, threads, started);
    keepFound(allocator, found, s.found);
    while (hits.pop()) |key| keepFound(allocator, found, key);
    const cpu_keys = hits.cpu_attempts.load(.monotonic);
    hits.keys.deinit();
    return rateOf(s.keys + cpu_keys, s.nanos);
}

fn sampleCpuWorkers(allocator: std.mem.Allocator, pattern: Pattern, worker_count: usize, millis: u64, found: *?FoundKey) !f64 {
    var stop = std.atomic.Value(bool).init(false);
    var hits = SharedHits{ .keys = std.array_list.Managed(FoundKey).init(allocator) };
    const workers = try allocator.alloc(CpuWorker, worker_count);
    defer allocator.free(workers);
    const threads = try allocator.alloc(std.Thread, worker_count);
    defer allocator.free(threads);

    const started = try startWorkers(allocator, pattern, worker_count, &stop, &hits, workers, threads);
    const t0 = std.time.nanoTimestamp();
    std.Thread.sleep(millis * std.time.ns_per_ms);
    stopWorkers(&stop, threads, started);
    const nanos: u64 = @intCast(std.time.nanoTimestamp() - t0);
    while (hits.pop()) |key| keepFound(allocator, found, key);
    const cpu_keys = hits.cpu_attempts.load(.monotonic);
    hits.keys.deinit();
    return rateOf(cpu_keys, nanos);
}

fn searchCpu(allocator: std.mem.Allocator, pattern: Pattern, match_count: u32, p50_attempts: f64) !u32 {
    var early: ?FoundKey = null;
    std.debug.print("Tuning CPU workers...\n", .{});
    const worker_count = try tuneCpuWorkers(allocator, pattern, &early);

    var found_count: u32 = 0;
    if (early) |key| {
        found_count = 1;
        std.debug.print("\n\n*** FOUND MATCH 1/{d}! ***\n", .{match_count});
        printFoundKey(key, pattern, allocator);
        allocator.free(key.address);
        early = null;
        if (found_count >= match_count) return found_count;
    }

    std.debug.print("Using {d} CPU workers\n", .{worker_count});
    var stop = std.atomic.Value(bool).init(false);
    var hits = SharedHits{ .keys = std.array_list.Managed(FoundKey).init(allocator) };
    defer {
        while (hits.pop()) |key| allocator.free(key.address);
        hits.keys.deinit();
    }
    const workers = try allocator.alloc(CpuWorker, worker_count);
    defer allocator.free(workers);
    const threads = try allocator.alloc(std.Thread, worker_count);
    defer allocator.free(threads);
    const started = try startWorkers(allocator, pattern, worker_count, &stop, &hits, workers, threads);
    defer stopWorkers(&stop, threads, started);

    std.debug.print("Searching...\n", .{});
    const start_ms = std.time.milliTimestamp();
    while (found_count < match_count) {
        takeCpuHits(&hits, 0, &found_count, match_count, pattern, allocator);
        if (found_count >= match_count) break;
        std.Thread.sleep(100 * std.time.ns_per_ms);
        const cpu_attempts = hits.cpu_attempts.load(.monotonic);
        const elapsed_ms = std.time.milliTimestamp() - start_ms;
        const elapsed = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
        const rate = if (elapsed > 0) @as(f64, @floatFromInt(cpu_attempts)) / elapsed else 0;
        std.debug.print("\r[CPU] {d} keys, {d:.0} k/s, ", .{ cpu_attempts, rate / 1000.0 });
        grinders.formatTimeToP50(cpu_attempts, p50_attempts, rate);
        std.debug.print("        ", .{});
    }
    return found_count;
}

fn combinedAttempts(gpu_attempts: u64, hits: *SharedHits) u64 {
    return gpu_attempts + hits.cpu_attempts.load(.monotonic);
}

fn takeCpuHits(
    hits: *SharedHits,
    gpu_attempts: u64,
    found_count: *u32,
    match_count: u32,
    pattern: Pattern,
    allocator: std.mem.Allocator,
) void {
    while (found_count.* < match_count) {
        var found = hits.pop() orelse break;
        found_count.* += 1;
        found.attempts = combinedAttempts(gpu_attempts, hits);
        std.debug.print("\n\n*** FOUND MATCH {d}/{d}! ***\n", .{ found_count.*, match_count });
        printFoundKey(found, pattern, allocator);
        allocator.free(found.address);
        if (found_count.* < match_count) {
            std.debug.print("\nContinuing search...\n", .{});
        }
    }
}

fn reportHybrid(
    gpu_label: []const u8,
    gpu_attempts: u64,
    cpu_attempts: u64,
    start_ms: i64,
    p50_attempts: f64,
) void {
    const total = gpu_attempts + cpu_attempts;
    const elapsed_ms = std.time.milliTimestamp() - start_ms;
    const elapsed = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
    const rate = if (elapsed > 0) @as(f64, @floatFromInt(total)) / elapsed else 0;
    const gpu_rate = if (elapsed > 0) @as(f64, @floatFromInt(gpu_attempts)) / elapsed else 0;
    const cpu_rate = if (elapsed > 0) @as(f64, @floatFromInt(cpu_attempts)) / elapsed else 0;
    std.debug.print("\r[{s}+CPU] {d} keys, {d:.0} k/s ({d:.0} GPU + {d:.0} CPU), ", .{
        gpu_label,
        total,
        rate / 1000.0,
        gpu_rate / 1000.0,
        cpu_rate / 1000.0,
    });
    grinders.formatTimeToP50(total, p50_attempts, rate);
    std.debug.print("        ", .{});
}

/// Run the GPU grinder on this thread and CPU grinders on the cores that measured fastest.
fn searchGpuAndCpu(
    comptime Gpu: type,
    gpu: *Gpu,
    allocator: std.mem.Allocator,
    pattern: Pattern,
    match_count: u32,
    p50_attempts: f64,
    gpu_label: []const u8,
    tune_gpu: bool,
) !u32 {
    var early: ?FoundKey = null;
    if (tune_gpu) {
        std.debug.print("Tuning GPU threads and CPU workers...\n", .{});
        try tuneThreadgroup(gpu, allocator, &early);
    } else {
        std.debug.print("Tuning CPU workers...\n", .{});
    }

    var found_count: u32 = 0;
    if (early) |key| {
        found_count = 1;
        std.debug.print("\n\n*** FOUND MATCH 1/{d}! ***\n", .{match_count});
        printFoundKey(key, pattern, allocator);
        allocator.free(key.address);
        early = null;
        if (found_count >= match_count) return found_count;
    }

    const worker_count = try tuneHybridWorkers(gpu, allocator, pattern, &early);
    if (early) |key| {
        if (found_count < match_count) {
            found_count += 1;
            std.debug.print("\n\n*** FOUND MATCH {d}/{d}! ***\n", .{ found_count, match_count });
            printFoundKey(key, pattern, allocator);
            allocator.free(key.address);
            early = null;
            if (found_count >= match_count) return found_count;
        } else {
            allocator.free(key.address);
            early = null;
        }
    }
    gpu.resetCounters();
    std.debug.print("Using {d} GPU threads and {d} CPU workers\n", .{ gpu.threadgroupSize(), worker_count });
    var stop = std.atomic.Value(bool).init(false);
    var hits = SharedHits{
        .keys = std.array_list.Managed(FoundKey).init(allocator),
    };
    defer {
        while (hits.pop()) |key| allocator.free(key.address);
        hits.keys.deinit();
    }

    const workers = try allocator.alloc(CpuWorker, worker_count);
    defer allocator.free(workers);
    const threads = try allocator.alloc(std.Thread, worker_count);
    defer allocator.free(threads);

    var started: usize = 0;
    defer {
        stop.store(true, .release);
        for (threads[0..started]) |thread| thread.join();
    }

    const seed = @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));
    const start_ms = std.time.milliTimestamp();
    for (workers, threads, 0..) |*worker, *thread, i| {
        worker.* = .{
            .grinder = CpuGrinder.init(allocator, pattern),
            .hits = &hits,
            .stop = &stop,
        };
        worker.grinder.prng = std.Random.Xoshiro256.init(seed +% (@as(u64, i) +% 1) *% 0x9E3779B97F4A7C15);
        worker.grinder.stop = &stop;
        thread.* = try std.Thread.spawn(.{}, cpuWorkerMain, .{worker});
        started += 1;
    }

    std.debug.print("Searching...\n", .{});

    while (found_count < match_count) {
        const gpu_attempts = gpu.attempts.load(.monotonic);
        takeCpuHits(&hits, gpu_attempts, &found_count, match_count, pattern, allocator);
        if (found_count >= match_count) break;

        if (try gpu.searchBatch(BATCH_SIZE)) |found| {
            if (found_count < match_count) {
                var found_key = found;
                found_count += 1;
                found_key.attempts = combinedAttempts(gpu.attempts.load(.monotonic), &hits);
                std.debug.print("\n\n*** FOUND MATCH {d}/{d}! ***\n", .{ found_count, match_count });
                printFoundKey(found_key, pattern, allocator);
                allocator.free(found_key.address);
                if (found_count < match_count) {
                    std.debug.print("\nContinuing search...\n", .{});
                }
            } else {
                allocator.free(found.address);
            }
        }

        takeCpuHits(&hits, gpu.attempts.load(.monotonic), &found_count, match_count, pattern, allocator);
        if (found_count < match_count) {
            reportHybrid(gpu_label, gpu.attempts.load(.monotonic), hits.cpu_attempts.load(.monotonic), start_ms, p50_attempts);
        }
    }

    return found_count;
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

    if (!Ed25519.matchesSolanaKeypair(found.public_key, found.private_key)) {
        std.debug.print("VERIFICATION FAILED: secret seed does not derive this public key\n", .{});
        return;
    }
    std.debug.print("VERIFIED: Keypair matches solana-keygen format\n", .{});

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

    // Metal benchmark (macOS only)
    var metal_rate: f64 = 0;

    if (IS_MACOS) {
        std.debug.print("Metal GPU benchmark...\n", .{});
        var metal_grinder = try MetalGrinder.init(allocator, pattern, null);
        defer metal_grinder.deinit();

        const metal_start = std.time.milliTimestamp();
        while (std.time.milliTimestamp() - metal_start < BENCHMARK_DURATION_MS) {
            if (try metal_grinder.searchBatch(BATCH_SIZE)) |found| {
                allocator.free(found.address);
            }
        }
        const metal_elapsed = @as(f64, @floatFromInt(std.time.milliTimestamp() - metal_start)) / 1000.0;
        const metal_attempts = metal_grinder.attempts.load(.acquire);
        metal_rate = @as(f64, @floatFromInt(metal_attempts)) / metal_elapsed;
        std.debug.print("  Metal GPU: {d:.2} k/s\n", .{metal_rate / 1000.0});
    }

    // Vulkan GPU Benchmark
    std.debug.print("Vulkan GPU benchmark...\n", .{});
    var vulkan_grinder = try VulkanGrinder.init(allocator, pattern, null);
    defer vulkan_grinder.deinit();

    const vulkan_start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - vulkan_start < BENCHMARK_DURATION_MS) {
        if (try vulkan_grinder.searchBatch(BATCH_SIZE)) |found| {
            allocator.free(found.address);
        }
    }
    const vulkan_elapsed = @as(f64, @floatFromInt(std.time.milliTimestamp() - vulkan_start)) / 1000.0;
    const vulkan_attempts = vulkan_grinder.attempts.load(.acquire);
    const vulkan_rate = @as(f64, @floatFromInt(vulkan_attempts)) / vulkan_elapsed;
    std.debug.print("  Vulkan GPU: {d:.2} k/s\n", .{vulkan_rate / 1000.0});

    // Results
    std.debug.print("\n=== Results ===\n", .{});
    std.debug.print("CPU:        {d:.2} k/s (baseline)\n", .{cpu_rate / 1000.0});
    if (IS_MACOS) {
        std.debug.print("Metal GPU:  {d:.2} k/s ({d:.0}x faster)\n", .{ metal_rate / 1000.0, metal_rate / cpu_rate });
    }
    std.debug.print("Vulkan GPU: {d:.2} k/s ({d:.0}x faster)\n", .{ vulkan_rate / 1000.0, vulkan_rate / cpu_rate });

    // Determine fastest
    const best_rate = if (IS_MACOS)
        @max(cpu_rate, @max(metal_rate, vulkan_rate))
    else
        @max(cpu_rate, vulkan_rate);

    if (IS_MACOS and best_rate == metal_rate) {
        std.debug.print("\nMetal GPU mode is fastest!\n", .{});
    } else if (best_rate == vulkan_rate) {
        std.debug.print("\nVulkan GPU mode is fastest!\n", .{});
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
    const backend_desc = if (IS_MACOS) "Metal" else "Vulkan";
    std.debug.print("grincel - Solana vanity address grinder with {s} GPU acceleration\n\n", .{backend_desc});
    std.debug.print("Usage: grincel <pattern>[:<count>] [options]\n", .{});
    std.debug.print("   or: VANITY_PATTERN=<pattern> grincel [options]\n", .{});
    std.debug.print("\nOptions:\n", .{});
    std.debug.print("  -h, --help            Show this help message\n", .{});
    std.debug.print("  -s, --case-sensitive  Case sensitive matching\n", .{});
    std.debug.print("  -t, --threads N       GPU threads per workgroup. Default: measured at startup\n", .{});
    std.debug.print("  --cpu                 Use CPUs only. The default uses the GPU and CPUs together\n", .{});
    // Only show --vulkan flag on macOS where both backends are available
    if (IS_MACOS) {
        std.debug.print("  --vulkan              Use Vulkan GPU backend instead of Metal\n", .{});
    }
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
    std.debug.print("  grincel Ace                    # Find one address starting with 'ace'\n", .{});
    std.debug.print("  grincel Ace:5                  # Find 5 addresses starting with 'ace'\n", .{});
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
    var json_buf = std.array_list.Managed(u8).init(allocator);
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
