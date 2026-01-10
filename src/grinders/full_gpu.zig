const std = @import("std");
const mtl = @import("zig-metal");
const mod = @import("mod.zig");
const Pattern = mod.Pattern;
const FoundKey = mod.FoundKey;
const GpuPatternConfig = mod.GpuPatternConfig;
const GpuResultBuffer = mod.GpuResultBuffer;
const BATCH_SIZE = mod.BATCH_SIZE;
const SHADER_PATH = mod.SHADER_PATH;

/// Full GPU vanity search - SHA512, Ed25519, Base58, pattern matching all on GPU
/// This is the highest throughput mode, performing all operations on the GPU.
pub const FullGpuGrinder = struct {
    device: *mtl.MTLDevice,
    command_queue: *mtl.MTLCommandQueue,
    compute_pso: *mtl.MTLComputePipelineState,
    state_buffer: *mtl.MTLBuffer,
    pattern_buffer: *mtl.MTLBuffer,
    result_buffer: *mtl.MTLBuffer,
    found_flag_buffer: *mtl.MTLBuffer,
    pattern: Pattern,
    attempts: std.atomic.Value(u64),
    start_time: i64,
    allocator: std.mem.Allocator,
    cpu_prng: std.Random.Xoshiro256,
    max_threads_per_group: usize,
    p50_attempts: f64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pattern: Pattern) !Self {
        const device = mtl.MTLCreateSystemDefaultDevice() orelse {
            return error.NoMetalDevice;
        };

        const name = device.name();
        std.debug.print("Metal Device: {s}\n", .{name.UTF8String()});

        const command_queue = device.newCommandQueue() orelse {
            device.release();
            return error.NoCommandQueue;
        };

        // Load and compile shader from file
        const shader_source = std.fs.cwd().readFileAlloc(allocator, SHADER_PATH, 1024 * 1024) catch |err| {
            std.debug.print("Failed to load shader from {s}: {}\n", .{ SHADER_PATH, err });
            command_queue.release();
            device.release();
            return error.ShaderLoadFailed;
        };
        defer allocator.free(shader_source);

        const shader_z = allocator.dupeZ(u8, shader_source) catch {
            command_queue.release();
            device.release();
            return error.OutOfMemory;
        };
        defer allocator.free(shader_z);

        std.debug.print("Loaded shader: {s} ({d} bytes)\n", .{ SHADER_PATH, shader_source.len });

        const source_ns = mtl.NSString.stringWithUTF8String(shader_z.ptr);
        const library = device.newLibraryWithSourceOptionsError(source_ns, null, null) orelse {
            std.debug.print("Shader compilation failed\n", .{});
            command_queue.release();
            device.release();
            return error.ShaderCompileFailed;
        };
        defer library.release();

        const func_name = mtl.NSString.stringWithUTF8String("vanity_search");
        const func = library.newFunctionWithName(func_name) orelse {
            std.debug.print("Function 'vanity_search' not found\n", .{});
            command_queue.release();
            device.release();
            return error.FunctionNotFound;
        };
        defer func.release();

        const compute_pso = device.newComputePipelineStateWithFunctionError(func, null) orelse {
            command_queue.release();
            device.release();
            return error.PipelineCreationFailed;
        };

        const max_threads = compute_pso.maxTotalThreadsPerThreadgroup();
        std.debug.print("Max threads per threadgroup: {d}\n", .{max_threads});
        std.debug.print("Full GPU mode: SHA512 + Ed25519 + Base58 + Pattern all on GPU\n", .{});

        // Create buffers
        const state_buffer = device.newBufferWithLengthOptions(16, .MTLResourceCPUCacheModeDefaultCache) orelse {
            compute_pso.release();
            command_queue.release();
            device.release();
            return error.BufferCreationFailed;
        };

        const pattern_buffer = device.newBufferWithLengthOptions(@sizeOf(GpuPatternConfig), .MTLResourceCPUCacheModeDefaultCache) orelse {
            state_buffer.release();
            compute_pso.release();
            command_queue.release();
            device.release();
            return error.BufferCreationFailed;
        };

        const result_buffer = device.newBufferWithLengthOptions(@sizeOf(GpuResultBuffer), .MTLResourceCPUCacheModeDefaultCache) orelse {
            pattern_buffer.release();
            state_buffer.release();
            compute_pso.release();
            command_queue.release();
            device.release();
            return error.BufferCreationFailed;
        };

        const found_flag_buffer = device.newBufferWithLengthOptions(4, .MTLResourceCPUCacheModeDefaultCache) orelse {
            result_buffer.release();
            pattern_buffer.release();
            state_buffer.release();
            compute_pso.release();
            command_queue.release();
            device.release();
            return error.BufferCreationFailed;
        };

        // Initialize pattern buffer
        const pattern_ptr: *GpuPatternConfig = @ptrCast(@alignCast(pattern_buffer.contents()));
        pattern_ptr.* = GpuPatternConfig.fromPattern(pattern);

        const cpu_seed = @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));

        return Self{
            .device = device,
            .command_queue = command_queue,
            .compute_pso = compute_pso,
            .state_buffer = state_buffer,
            .pattern_buffer = pattern_buffer,
            .result_buffer = result_buffer,
            .found_flag_buffer = found_flag_buffer,
            .pattern = pattern,
            .attempts = std.atomic.Value(u64).init(0),
            .start_time = std.time.milliTimestamp(),
            .allocator = allocator,
            .cpu_prng = std.Random.Xoshiro256.init(cpu_seed),
            .max_threads_per_group = max_threads,
            .p50_attempts = 0, // Set via setP50() before searching
        };
    }

    /// Set the P50 attempts for progress display
    pub fn setP50(self: *Self, p50: f64) void {
        self.p50_attempts = p50;
    }

    pub fn deinit(self: *Self) void {
        self.found_flag_buffer.release();
        self.result_buffer.release();
        self.pattern_buffer.release();
        self.state_buffer.release();
        self.compute_pso.release();
        self.command_queue.release();
        self.device.release();
    }

    fn runBatch(self: *Self) ?GpuResultBuffer {
        const found_ptr: *u32 = @ptrCast(@alignCast(self.found_flag_buffer.contents()));
        found_ptr.* = 0;

        const result_ptr: *GpuResultBuffer = @ptrCast(@alignCast(self.result_buffer.contents()));
        result_ptr.found = 0;

        const state_ptr: *[2]u64 = @ptrCast(@alignCast(self.state_buffer.contents()));
        state_ptr[0] = self.cpu_prng.next();
        state_ptr[1] = self.cpu_prng.next();

        const cmd_buffer = self.command_queue.commandBuffer() orelse return null;
        const encoder = cmd_buffer.computeCommandEncoder() orelse return null;

        encoder.setComputePipelineState(self.compute_pso);
        encoder.setBufferOffsetAtIndex(self.state_buffer, 0, 0);
        encoder.setBufferOffsetAtIndex(self.pattern_buffer, 0, 1);
        encoder.setBufferOffsetAtIndex(self.result_buffer, 0, 2);
        encoder.setBufferOffsetAtIndex(self.found_flag_buffer, 0, 3);

        const grid_size = mtl.MTLSize{ .width = BATCH_SIZE, .height = 1, .depth = 1 };
        const threadgroup_size = mtl.MTLSize{
            .width = @min(self.max_threads_per_group, 256),
            .height = 1,
            .depth = 1,
        };

        encoder.dispatchThreadsThreadsPerThreadgroup(grid_size, threadgroup_size);
        encoder.endEncoding();
        cmd_buffer.commit();
        cmd_buffer.waitUntilCompleted();

        _ = self.attempts.fetchAdd(BATCH_SIZE, .monotonic);

        if (result_ptr.found != 0) {
            return result_ptr.*;
        }
        return null;
    }

    pub fn searchBatch(self: *Self, max_attempts: u64) !?FoundKey {
        const num_batches = max_attempts / BATCH_SIZE;
        if (num_batches == 0) return null;

        var batch: u64 = 0;
        while (batch < num_batches) {
            if (self.runBatch()) |result| {
                const addr_len = @min(result.address_len, 48);
                return FoundKey{
                    .public_key = result.public_key,
                    .private_key = result.private_key,
                    .address = try self.allocator.dupe(u8, result.address[0..addr_len]),
                    .attempts = self.attempts.load(.acquire),
                };
            }

            batch += 1;
            if (batch % 10 == 0) {
                self.reportProgress();
            }
        }
        return null;
    }

    fn reportProgress(self: *Self) void {
        const elapsed_ms = std.time.milliTimestamp() - self.start_time;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
        const current_attempts = self.attempts.load(.acquire);
        const rate = if (elapsed_secs > 0)
            @as(f64, @floatFromInt(current_attempts)) / elapsed_secs
        else
            0;

        std.debug.print("\r[Full GPU] {d} keys, {d:.0} k/s, ", .{
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
