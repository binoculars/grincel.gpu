const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create zigtrait module (dependency of zig-metal)
    const zigtrait_module = b.addModule("zigtrait", .{
        .root_source_file = b.path("libs/zig-metal/libs/zigtrait/src/zigtrait.zig"),
    });

    // Create zig-metal module
    const zig_metal_module = b.addModule("zig-metal", .{
        .root_source_file = b.path("libs/zig-metal/src/main.zig"),
        .imports = &.{
            .{ .name = "zigtrait", .module = zigtrait_module },
        },
    });

    // Main executable using zig-metal
    const exe = b.addExecutable(.{
        .name = "grincel",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig-metal", .module = zig_metal_module },
            },
        }),
    });

    // Link frameworks on macOS
    exe.linkFramework("Foundation");
    exe.linkFramework("Metal");
    exe.linkFramework("QuartzCore");

    b.installArtifact(exe);

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
