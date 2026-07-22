const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const injection_dependency = b.dependency("injection", .{
        .target = target,
        .optimize = optimize,
    });

    const waf = b.addModule("waf", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    waf.addImport("injection", injection_dependency.module("injection"));

    const cli_module = b.createModule(.{
        .root_source_file = b.path("src/cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    cli_module.addImport("waf", waf);
    const cli = b.addExecutable(.{ .name = "zig-waf", .root_module = cli_module });
    b.installArtifact(cli);

    const daemon_module = b.createModule(.{
        .root_source_file = b.path("src/daemon.zig"),
        .target = target,
        .optimize = optimize,
    });
    daemon_module.addImport("waf", waf);
    const daemon = b.addExecutable(.{ .name = "zig-wafd", .root_module = daemon_module });
    b.installArtifact(daemon);

    const tests = b.addTest(.{ .root_module = waf });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    const check_step = b.step("check", "Compile libraries and executables");
    check_step.dependOn(&cli.step);
    check_step.dependOn(&daemon.step);
    check_step.dependOn(&tests.step);
}
