const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const is_macos = target.result.os.tag == .macos;

    // Create zigtrait module (vendored due to Zig 0.15 build.zig incompatibility upstream)
    const zigtrait_module = b.addModule("zigtrait", .{
        .root_source_file = b.path("libs/zigtrait/zigtrait.zig"),
    });

    // Get zig-metal dependency and create module with zigtrait import
    const zig_metal_dep = b.dependency("zig_metal", .{});
    const zig_metal_module = b.addModule("zig-metal", .{
        .root_source_file = zig_metal_dep.path("src/main.zig"),
        .imports = &.{
            .{ .name = "zigtrait", .module = zigtrait_module },
        },
    });

    // Build options module to pass compile-time config to source
    const build_options = b.addOptions();
    build_options.addOption(bool, "is_macos", is_macos);

    // Get vulkan-zig dependency with the Vulkan registry
    const vulkan_headers = b.dependency("vulkan_headers", .{});
    const vulkan_dep = b.dependency("vulkan_zig", .{
        .registry = vulkan_headers.path("registry/vk.xml"),
    });
    const vulkan_module = vulkan_dep.module("vulkan-zig");

    // Compile SPIR-V shader from GLSL
    const spirv_compile = b.addSystemCommand(&.{
        "glslc",
        "--target-env=vulkan1.2",
        "-O",
        "-o",
    });
    const spirv_output = spirv_compile.addOutputFileArg("vanity.spv");
    spirv_compile.addFileArg(b.path("src/shaders/vanity.comp"));

    // Create embedded SPIR-V module
    const spirv_module = b.addModule("spirv", .{
        .root_source_file = b.addWriteFiles().add("spirv.zig",
            \\pub const EMBEDDED_SPIRV = @embedFile("vanity.spv");
        ),
    });
    spirv_module.addAnonymousImport("vanity.spv", .{ .root_source_file = spirv_output });

    // Main executable
    const exe = b.addExecutable(.{
        .name = "grincel",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig-metal", .module = zig_metal_module },
                .{ .name = "build_options", .module = build_options.createModule() },
                .{ .name = "vulkan", .module = vulkan_module },
                .{ .name = "spirv", .module = spirv_module },
            },
        }),
    });

    // Check if we're cross-compiling
    const is_native = target.result.os.tag == @import("builtin").os.tag;

    // Platform-specific linking
    if (is_macos) {
        // Link Metal frameworks on macOS (only when building natively)
        if (is_native) {
            exe.linkFramework("Foundation");
            exe.linkFramework("Metal");
            exe.linkFramework("QuartzCore");

            // On macOS, use MoltenVK from Homebrew
            exe.root_module.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/molten-vk/lib" });
            exe.linkSystemLibrary("MoltenVK");
        }
    } else {
        // On Linux, link standard Vulkan (only when building natively)
        // When cross-compiling, Vulkan is loaded dynamically at runtime
        if (is_native) {
            exe.linkSystemLibrary("vulkan");
        }
    }

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
