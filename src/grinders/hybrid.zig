const std = @import("std");
const mtl = @import("zig-metal");
const Ed25519 = @import("../cpu/ed25519.zig").Ed25519;
const Base58 = @import("../cpu/base58.zig").Base58;
const mod = @import("mod.zig");
const Pattern = mod.Pattern;
const FoundKey = mod.FoundKey;
const BATCH_SIZE = mod.BATCH_SIZE;
const NUM_BUFFERS = mod.NUM_BUFFERS;
const NUM_CPU_THREADS = mod.NUM_CPU_THREADS;
const EMBEDDED_SHADER = mod.EMBEDDED_SHADER;

/// GPU-accelerated seed generation with multi-threaded CPU processing
/// Uses triple buffering + thread pool for maximum throughput:
/// - GPU generates seeds in parallel across all cores
/// - Multiple CPU threads process seeds simultaneously
pub const HybridGrinder = struct {
    device: mtl.MTLDevice,
    command_queue: mtl.MTLCommandQueue,
    compute_pso: mtl.MTLComputePipelineState,
    seed_buffers: [NUM_BUFFERS]mtl.MTLBuffer,
    state_buffers: [NUM_BUFFERS]mtl.MTLBuffer,
    pattern: Pattern,
    attempts: std.atomic.Value(u64),
    start_time: i64,
    allocator: std.mem.Allocator,
    cpu_prng: std.Random.Xoshiro256,
    max_threads_per_group: usize,
    thread_pool: *std.Thread.Pool,
    p50_attempts: f64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pattern: Pattern) !Self {
        const device = mtl.createSystemDefaultDevice() orelse {
            return error.NoMetalDevice;
        };

        const name = device.name();
        std.debug.print("Metal Device: {s}\n", .{name.UTF8String()});

        const command_queue = device.newCommandQueue() orelse {
            device.release();
            return error.NoCommandQueue;
        };

        // Use embedded shader (compiled into binary)
        std.debug.print("Shader size: {d} bytes (embedded)\n", .{EMBEDDED_SHADER.len});

        const source_ns = mtl.NSString.stringWithUTF8String(EMBEDDED_SHADER.ptr);
        var library = device.newLibraryWithSourceOptionsError(source_ns, null, null) orelse {
            command_queue.release();
            device.release();
            return error.ShaderCompileFailed;
        };
        defer library.release();

        const func_name = mtl.NSString.stringWithUTF8String("generate_seeds");
        var func = library.newFunctionWithName(func_name) orelse {
            command_queue.release();
            device.release();
            return error.FunctionNotFound;
        };
        defer func.release();

        var compute_pso = device.newComputePipelineStateWithFunctionError(func, null) orelse {
            command_queue.release();
            device.release();
            return error.PipelineCreationFailed;
        };

        const max_threads = compute_pso.maxTotalThreadsPerThreadgroup();
        std.debug.print("Max threads per threadgroup: {d}\n", .{max_threads});
        std.debug.print("CPU threads for processing: {d}\n", .{NUM_CPU_THREADS});

        // Create triple-buffered resources
        var seed_buffers: [NUM_BUFFERS]mtl.MTLBuffer = undefined;
        var state_buffers: [NUM_BUFFERS]mtl.MTLBuffer = undefined;
        const seed_buffer_size = BATCH_SIZE * 32;

        for (0..NUM_BUFFERS) |i| {
            seed_buffers[i] = device.newBufferWithLengthOptions(
                @intCast(seed_buffer_size),
                .MTLResourceCPUCacheModeDefaultCache,
            ) orelse {
                for (0..i) |j| {
                    seed_buffers[j].release();
                    state_buffers[j].release();
                }
                compute_pso.release();
                command_queue.release();
                device.release();
                return error.BufferCreationFailed;
            };

            state_buffers[i] = device.newBufferWithLengthOptions(
                16,
                .MTLResourceCPUCacheModeDefaultCache,
            ) orelse {
                seed_buffers[i].release();
                for (0..i) |j| {
                    seed_buffers[j].release();
                    state_buffers[j].release();
                }
                compute_pso.release();
                command_queue.release();
                device.release();
                return error.BufferCreationFailed;
            };
        }

        const thread_pool = try allocator.create(std.Thread.Pool);
        try thread_pool.init(.{
            .allocator = allocator,
            .n_jobs = NUM_CPU_THREADS,
        });

        const cpu_seed = @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));

        return Self{
            .device = device,
            .command_queue = command_queue,
            .compute_pso = compute_pso,
            .seed_buffers = seed_buffers,
            .state_buffers = state_buffers,
            .pattern = pattern,
            .attempts = std.atomic.Value(u64).init(0),
            .start_time = std.time.milliTimestamp(),
            .allocator = allocator,
            .cpu_prng = std.Random.Xoshiro256.init(cpu_seed),
            .max_threads_per_group = max_threads,
            .thread_pool = thread_pool,
            .p50_attempts = 0,
        };
    }

    /// Set the P50 attempts for progress display
    pub fn setP50(self: *Self, p50: f64) void {
        self.p50_attempts = p50;
    }

    pub fn deinit(self: *Self) void {
        self.thread_pool.deinit();
        self.allocator.destroy(self.thread_pool);
        for (0..NUM_BUFFERS) |i| {
            self.state_buffers[i].release();
            self.seed_buffers[i].release();
        }
        self.compute_pso.release();
        self.command_queue.release();
        self.device.release();
    }

    fn submitGpuWork(self: *Self, buffer_idx: usize) ?mtl.MTLCommandBuffer {
        const state_ptr: *[2]u64 = @ptrCast(@alignCast(self.state_buffers[buffer_idx].contents()));
        state_ptr[0] = self.cpu_prng.next();
        state_ptr[1] = self.cpu_prng.next();

        var cmd_buffer = self.command_queue.commandBuffer() orelse return null;
        var encoder = cmd_buffer.computeCommandEncoder() orelse return null;

        encoder.setComputePipelineState(self.compute_pso);
        encoder.setBufferOffsetAtIndex(self.seed_buffers[buffer_idx], 0, 0);
        encoder.setBufferOffsetAtIndex(self.state_buffers[buffer_idx], 0, 1);

        const grid_size = mtl.MTLSize{ .width = BATCH_SIZE, .height = 1, .depth = 1 };
        const threadgroup_size = mtl.MTLSize{
            .width = @min(self.max_threads_per_group, 1024),
            .height = 1,
            .depth = 1,
        };

        encoder.dispatchThreadsThreadsPerThreadgroup(grid_size, threadgroup_size);
        encoder.endEncoding();
        cmd_buffer.commit();

        return cmd_buffer;
    }

    const WorkerContext = struct {
        seeds_ptr: [*]const [32]u8,
        start_idx: usize,
        end_idx: usize,
        pattern: Pattern,
        attempts: *std.atomic.Value(u64),
        found: *std.atomic.Value(bool),
        result: *?FoundKey,
        result_mutex: *std.Thread.Mutex,
        allocator: std.mem.Allocator,
        wg: *std.Thread.WaitGroup,
    };

    fn workerFn(ctx: WorkerContext) void {
        defer ctx.wg.finish();

        for (ctx.start_idx..ctx.end_idx) |i| {
            if (ctx.found.load(.acquire)) return;

            const seed = ctx.seeds_ptr[i];
            const keypair = Ed25519.generateKeypair(&seed);

            var address_buf: [64]u8 = undefined;
            const addr_len = Base58.encode(&address_buf, &keypair.public) catch continue;
            const address = address_buf[0..addr_len];

            _ = ctx.attempts.fetchAdd(1, .monotonic);

            if (ctx.pattern.matches(address)) {
                ctx.result_mutex.lock();
                defer ctx.result_mutex.unlock();

                if (!ctx.found.load(.acquire)) {
                    ctx.found.store(true, .release);
                    ctx.result.* = FoundKey{
                        .public_key = keypair.public,
                        .private_key = keypair.private,
                        .address = ctx.allocator.dupe(u8, address) catch return,
                        .attempts = ctx.attempts.load(.acquire),
                    };
                }
                return;
            }
        }
    }

    fn processCpuWorkParallel(self: *Self, buffer_idx: usize, found: *std.atomic.Value(bool), result: *?FoundKey, result_mutex: *std.Thread.Mutex, wg: *std.Thread.WaitGroup) void {
        const seeds_ptr: [*]const [32]u8 = @ptrCast(@alignCast(self.seed_buffers[buffer_idx].contents()));
        const chunk_size = BATCH_SIZE / NUM_CPU_THREADS;

        for (0..NUM_CPU_THREADS) |t| {
            const start_idx = t * chunk_size;
            const end_idx = if (t == NUM_CPU_THREADS - 1) BATCH_SIZE else (t + 1) * chunk_size;

            wg.start();
            self.thread_pool.spawn(workerFn, .{WorkerContext{
                .seeds_ptr = seeds_ptr,
                .start_idx = start_idx,
                .end_idx = end_idx,
                .pattern = self.pattern,
                .attempts = &self.attempts,
                .found = found,
                .result = result,
                .result_mutex = result_mutex,
                .allocator = self.allocator,
                .wg = wg,
            }}) catch {
                wg.finish();
            };
        }
    }

    pub fn searchBatch(self: *Self, max_attempts: u64) !?FoundKey {
        const num_batches = max_attempts / BATCH_SIZE;
        if (num_batches == 0) return null;

        var cmd_buffers: [NUM_BUFFERS]?mtl.MTLCommandBuffer = .{ null, null, null };
        var found = std.atomic.Value(bool).init(false);
        var result: ?FoundKey = null;
        var result_mutex = std.Thread.Mutex{};

        for (0..@min(NUM_BUFFERS, num_batches)) |i| {
            cmd_buffers[i] = self.submitGpuWork(i);
        }

        var batch: u64 = 0;
        var active_buffer: usize = 0;

        while (batch < num_batches and !found.load(.acquire)) {
            if (cmd_buffers[active_buffer]) |*cmd| {
                cmd.waitUntilCompleted();
            }

            const next_batch = batch + NUM_BUFFERS;
            if (next_batch < num_batches) {
                cmd_buffers[active_buffer] = self.submitGpuWork(active_buffer);
            }

            var wg = std.Thread.WaitGroup{};
            self.processCpuWorkParallel(active_buffer, &found, &result, &result_mutex, &wg);
            self.thread_pool.waitAndWork(&wg);

            if (batch % 5 == 0) {
                self.reportProgress();
            }

            batch += 1;
            active_buffer = (active_buffer + 1) % NUM_BUFFERS;
        }

        return result;
    }

    fn reportProgress(self: *Self) void {
        const elapsed_ms = std.time.milliTimestamp() - self.start_time;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
        const current_attempts = self.attempts.load(.acquire);
        const rate = if (elapsed_secs > 0)
            @as(f64, @floatFromInt(current_attempts)) / elapsed_secs
        else
            0;

        std.debug.print("\r[Hybrid GPU+{d}CPU] {d} keys, {d:.2} k/s, ", .{
            NUM_CPU_THREADS,
            current_attempts,
            rate / 1000.0,
        });
        mod.formatTimeToP50(current_attempts, self.p50_attempts, rate);
        std.debug.print("        ", .{}); // Clear trailing chars
    }

    pub fn getRate(self: *Self) f64 {
        const elapsed_ms = std.time.milliTimestamp() - self.start_time;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
        const current_attempts = self.attempts.load(.acquire);
        return if (elapsed_secs > 0)
            @as(f64, @floatFromInt(current_attempts)) / elapsed_secs
        else
            0;
    }
};
