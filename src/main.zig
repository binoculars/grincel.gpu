const std = @import("std");
const mtl = @import("zig-metal");

// Shader source embedded in binary for simplicity
const shader_source: [*:0]const u8 =
    \\#include <metal_stdlib>
    \\using namespace metal;
    \\
    \\struct Pattern {
    \\    uint32_t pattern_length;
    \\    uint8_t _padding1[12];
    \\    uint32_t fixed_chars[8];
    \\    uint8_t _padding2[16];
    \\    uint32_t mask[8];
    \\    uint8_t _padding3[16];
    \\    uint32_t case_sensitive;
    \\    uint8_t _padding4[12];
    \\} __attribute__((aligned(16)));
    \\
    \\struct KeyPair {
    \\    uint32_t private_key[8] __attribute__((aligned(16)));
    \\    uint32_t _padding1[4];
    \\    uint32_t public_key[8] __attribute__((aligned(16)));
    \\    uint32_t _padding2[4];
    \\    uint32_t debug[36] __attribute__((aligned(16)));
    \\    uint32_t _padding3[12];
    \\} __attribute__((aligned(16)));
    \\
    \\kernel void compute(device const Pattern* pattern [[buffer(0)]],
    \\                   device KeyPair* key_pairs [[buffer(1)]],
    \\                   uint thread_position_in_grid [[thread_position_in_grid]]) {
    \\
    \\    device KeyPair& key_pair = key_pairs[thread_position_in_grid];
    \\
    \\    // Write test values directly to debug array
    \\    key_pair.debug[0] = 0xDEADBEEF;
    \\    key_pair.debug[1] = 0xCAFEBABE;
    \\    key_pair.debug[2] = 0x12345678;
    \\
    \\    // Write pattern data
    \\    key_pair.debug[3] = pattern->pattern_length;
    \\    key_pair.debug[4] = pattern->case_sensitive;
    \\
    \\    // Copy pattern data
    \\    for (uint i = 0; i < 8; i++) {
    \\        key_pair.debug[5 + i] = pattern->fixed_chars[i];
    \\        key_pair.debug[13 + i] = pattern->mask[i];
    \\    }
    \\
    \\    // Write struct sizes
    \\    key_pair.debug[21] = sizeof(Pattern);
    \\    key_pair.debug[22] = 0;
    \\    key_pair.debug[23] = 16;
    \\    key_pair.debug[24] = 64;
    \\    key_pair.debug[25] = 112;
    \\
    \\    // Write thread info
    \\    key_pair.debug[34] = thread_position_in_grid;
    \\    key_pair.debug[35] = 0xFFFFFFFF;
    \\}
;

// Match the Pattern struct from the shader
const Pattern = extern struct {
    pattern_length: u32 align(4),
    _padding1: [3]u32,
    fixed_chars: [8]u32,
    _padding2: [4]u32,
    mask: [8]u32,
    _padding3: [4]u32,
    case_sensitive: u32,
    _padding4: [3]u32,
};

// Match the KeyPair struct from the shader
const KeyPair = extern struct {
    private_key: [8]u32 align(16),
    _padding1: [4]u32,
    public_key: [8]u32 align(16),
    _padding2: [4]u32,
    debug: [36]u32 align(16),
    _padding3: [12]u32,
};

pub fn main() !void {
    std.debug.print("Grincel GPU - Metal Compute with zig-metal\n", .{});
    std.debug.print("==========================================\n\n", .{});

    // Print struct layouts
    std.debug.print("Zig Pattern struct: {} bytes\n", .{@sizeOf(Pattern)});
    std.debug.print("Zig KeyPair struct: {} bytes\n\n", .{@sizeOf(KeyPair)});

    // Create Metal device
    std.debug.print("Initializing Metal...\n", .{});
    const device = mtl.MTLCreateSystemDefaultDevice() orelse {
        std.debug.print("Failed to create Metal device\n", .{});
        return error.NoDevice;
    };
    defer device.release();

    const name_ns = device.name();
    if (name_ns.UTF8String()) |name| {
        std.debug.print("Metal device: {s}\n", .{name});
    }

    // Create command queue
    const command_queue = device.newCommandQueue() orelse {
        std.debug.print("Failed to create command queue\n", .{});
        return error.NoCommandQueue;
    };
    defer command_queue.release();
    std.debug.print("Command queue created\n", .{});

    // Create library from shader source
    std.debug.print("Compiling shader...\n", .{});
    const source_ns = mtl.NSString.stringWithUTF8String(shader_source);
    const library = device.newLibraryWithSourceOptionsError(source_ns, null, null) orelse {
        std.debug.print("Failed to create library\n", .{});
        return error.NoLibrary;
    };
    defer library.release();
    std.debug.print("Library created\n", .{});

    // Get compute function
    const func_name = mtl.NSString.stringWithUTF8String("compute");
    const func = library.newFunctionWithName(func_name) orelse {
        std.debug.print("Failed to get compute function\n", .{});
        return error.NoFunction;
    };
    defer func.release();
    std.debug.print("Got compute function\n", .{});

    // Create compute pipeline state
    const pso = device.newComputePipelineStateWithFunctionError(func, null) orelse {
        std.debug.print("Failed to create compute pipeline state\n", .{});
        return error.NoPipelineState;
    };
    defer pso.release();
    std.debug.print("Pipeline state created\n", .{});

    // Create test pattern
    var pattern = Pattern{
        .pattern_length = 4,
        .fixed_chars = [_]u32{ 0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0 }, // "ABCD"
        .mask = [_]u32{ 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0 },
        .case_sensitive = 1,
        ._padding1 = [_]u32{0} ** 3,
        ._padding2 = [_]u32{0} ** 4,
        ._padding3 = [_]u32{0} ** 4,
        ._padding4 = [_]u32{0} ** 3,
    };

    // Create output buffer for one key pair
    var key_pair = std.mem.zeroes(KeyPair);

    // Create Metal buffers
    const pattern_buffer = device.newBufferWithBytesLengthOptions(
        @ptrCast(&pattern),
        @intCast(@sizeOf(Pattern)),
        .MTLResourceCPUCacheModeDefaultCache,
    ) orelse {
        std.debug.print("Failed to create pattern buffer\n", .{});
        return error.NoBuffer;
    };
    defer pattern_buffer.release();

    const keypair_buffer = device.newBufferWithBytesLengthOptions(
        @ptrCast(&key_pair),
        @intCast(@sizeOf(KeyPair)),
        .MTLResourceCPUCacheModeDefaultCache,
    ) orelse {
        std.debug.print("Failed to create keypair buffer\n", .{});
        return error.NoBuffer;
    };
    defer keypair_buffer.release();
    std.debug.print("Buffers created\n", .{});

    // Create command buffer
    const cmd_buffer = command_queue.commandBuffer() orelse {
        std.debug.print("Failed to create command buffer\n", .{});
        return error.NoCommandBuffer;
    };

    // Create compute encoder
    const encoder = cmd_buffer.computeCommandEncoder() orelse {
        std.debug.print("Failed to create compute encoder\n", .{});
        return error.NoEncoder;
    };

    // Set pipeline and buffers
    encoder.setComputePipelineState(pso);
    encoder.setBufferOffsetAtIndex(pattern_buffer, 0, 0);
    encoder.setBufferOffsetAtIndex(keypair_buffer, 0, 1);

    // Dispatch with 1 thread
    const grid_size = mtl.MTLSize{ .width = 1, .height = 1, .depth = 1 };
    const threadgroup_size = mtl.MTLSize{ .width = 1, .height = 1, .depth = 1 };
    encoder.dispatchThreadgroupsThreadsPerThreadgroup(grid_size, threadgroup_size);

    // End encoding and commit
    encoder.endEncoding();
    std.debug.print("Dispatching compute...\n", .{});
    cmd_buffer.commit();
    cmd_buffer.waitUntilCompleted();
    std.debug.print("Compute completed!\n\n", .{});

    // Read results
    const contents = keypair_buffer.contents();
    const result: *const KeyPair = @ptrCast(@alignCast(contents));

    std.debug.print("Debug values from GPU:\n", .{});
    std.debug.print("  debug[0] = 0x{X:0>8} (expected 0xDEADBEEF)\n", .{result.debug[0]});
    std.debug.print("  debug[1] = 0x{X:0>8} (expected 0xCAFEBABE)\n", .{result.debug[1]});
    std.debug.print("  debug[2] = 0x{X:0>8} (expected 0x12345678)\n", .{result.debug[2]});
    std.debug.print("  debug[3] = {} (pattern_length, expected 4)\n", .{result.debug[3]});
    std.debug.print("  debug[4] = {} (case_sensitive, expected 1)\n", .{result.debug[4]});
    std.debug.print("  debug[21] = {} (sizeof(Pattern), expected 128)\n", .{result.debug[21]});
    std.debug.print("  debug[34] = {} (thread_position)\n", .{result.debug[34]});
    std.debug.print("  debug[35] = 0x{X:0>8} (end marker)\n", .{result.debug[35]});

    // Verify
    const success = result.debug[0] == 0xDEADBEEF and
        result.debug[1] == 0xCAFEBABE and
        result.debug[2] == 0x12345678 and
        result.debug[35] == 0xFFFFFFFF;

    if (success) {
        std.debug.print("\n*** SUCCESS: GPU compute working correctly! ***\n", .{});
    } else {
        std.debug.print("\n*** FAILED: Unexpected values ***\n", .{});
    }
}
