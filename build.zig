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

    const c_api_module = b.createModule(.{
        .root_source_file = b.path("src/c_api.zig"),
        .target = target,
        .optimize = optimize,
    });
    c_api_module.addImport("waf", waf);
    const c_api = b.addLibrary(.{
        .name = "zig-waf",
        .linkage = .static,
        .root_module = c_api_module,
    });
    c_api.installHeader(b.path("include/zig_waf.h"), "zig_waf.h");
    b.installArtifact(c_api);

    const c_smoke = b.addExecutable(.{
        .name = "c-api-smoke",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    c_smoke.root_module.addCSourceFile(.{ .file = b.path("tests/c_api_smoke.c") });
    c_smoke.root_module.addIncludePath(b.path("include"));
    c_smoke.root_module.linkLibrary(c_api);
    const run_c_smoke = b.addRunArtifact(c_smoke);

    const tests = b.addTest(.{ .root_module = waf });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_c_smoke.step);

    const check_step = b.step("check", "Compile libraries and executables");
    check_step.dependOn(&cli.step);
    check_step.dependOn(&daemon.step);
    check_step.dependOn(&c_api.step);
    check_step.dependOn(&tests.step);

    const ownership_benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/ownership.zig"),
        .target = target,
        .optimize = optimize,
    });
    ownership_benchmark_module.addImport("waf", waf);
    const ownership_benchmark = b.addExecutable(.{
        .name = "ownership-benchmark",
        .root_module = ownership_benchmark_module,
    });
    const run_ownership_benchmark = b.addRunArtifact(ownership_benchmark);
    const benchmark_step = b.step("bench-ownership", "Benchmark transaction ownership and generation pinning");
    benchmark_step.dependOn(&run_ownership_benchmark.step);
}
