const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const injection_dependency = b.dependency("injection", .{
        .target = target,
        .optimize = optimize,
    });
    const regex_dependency = b.dependency("regex", .{
        .target = target,
        .optimize = optimize,
    });
    const lmdb_translate = b.addTranslateC(.{
        .root_source_file = b.path("pantry/openldap.org/liblmdb/v0.9.35/include/lmdb.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const lmdb_module = lmdb_translate.createModule();

    const waf = b.addModule("waf", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    waf.addIncludePath(b.path("pantry/openldap.org/liblmdb/v0.9.35/include"));
    waf.addObjectFile(b.path("pantry/openldap.org/liblmdb/v0.9.35/lib/liblmdb.a"));
    waf.addImport("injection", injection_dependency.module("injection"));
    waf.addImport("regex", regex_dependency.module("regex"));
    waf.addImport("lmdb", lmdb_module);

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
    const transformation_evidence_module = b.createModule(.{
        .root_source_file = b.path("tests/transformation_evidence.zig"),
        .target = target,
        .optimize = optimize,
    });
    transformation_evidence_module.addImport("waf", waf);
    const transformation_evidence_tests = b.addTest(.{ .root_module = transformation_evidence_module });
    const run_transformation_evidence_tests = b.addRunArtifact(transformation_evidence_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_c_smoke.step);
    test_step.dependOn(&run_transformation_evidence_tests.step);

    const check_step = b.step("check", "Compile libraries and executables");
    check_step.dependOn(&cli.step);
    check_step.dependOn(&daemon.step);
    check_step.dependOn(&c_api.step);
    check_step.dependOn(&tests.step);
    check_step.dependOn(&transformation_evidence_tests.step);

    const parser_corpus_module = b.createModule(.{
        .root_source_file = b.path("tools/parser_corpus.zig"),
        .target = target,
        .optimize = optimize,
    });
    parser_corpus_module.addImport("waf", waf);
    const parser_corpus = b.addExecutable(.{
        .name = "parser-corpus",
        .root_module = parser_corpus_module,
    });
    const run_parser_corpus = b.addRunArtifact(parser_corpus);
    if (b.option([]const []const u8, "parser-corpus", "SecLang corpus file or directory (repeatable)")) |corpus_roots|
        run_parser_corpus.addArgs(corpus_roots);
    const parser_corpus_step = b.step("test-parser-corpus", "Parse SecLang files beneath corpus roots");
    parser_corpus_step.dependOn(&run_parser_corpus.step);

    const run_plan_corpus = b.addRunArtifact(parser_corpus);
    run_plan_corpus.addArg("--compile-plan");
    if (b.option([]const []const u8, "plan-corpus", "SecLang structural plan corpus file or directory (repeatable)")) |corpus_roots|
        run_plan_corpus.addArgs(corpus_roots);
    const plan_corpus_step = b.step("test-plan-corpus", "Compile structural plans beneath corpus roots");
    plan_corpus_step.dependOn(&run_plan_corpus.step);

    const run_directive_corpus = b.addRunArtifact(parser_corpus);
    run_directive_corpus.addArg("--validate-directives");
    if (b.option([]const []const u8, "directive-corpus", "SecLang directive corpus file or directory (repeatable)")) |corpus_roots|
        run_directive_corpus.addArgs(corpus_roots);
    const directive_corpus_step = b.step("test-directive-corpus", "Validate stable directives beneath corpus roots");
    directive_corpus_step.dependOn(&run_directive_corpus.step);

    const directive_inventory_module = b.createModule(.{
        .root_source_file = b.path("tools/directive_inventory.zig"),
        .target = target,
        .optimize = optimize,
    });
    directive_inventory_module.addImport("waf", waf);
    const directive_inventory = b.addExecutable(.{
        .name = "directive-inventory",
        .root_module = directive_inventory_module,
    });
    const run_directive_inventory = b.addRunArtifact(directive_inventory);
    if (b.option([]const u8, "modsecurity-scanner", "Pinned ModSecurity seclang-scanner.ll")) |path|
        run_directive_inventory.addArg(path);
    if (b.option([]const u8, "modsecurity-parser", "Pinned ModSecurity seclang-parser.yy")) |path|
        run_directive_inventory.addArg(path);
    if (b.option([]const u8, "coraza-directives", "Pinned Coraza directivesmap.gen.go")) |path|
        run_directive_inventory.addArg(path);
    const directive_inventory_step = b.step("test-directive-inventory", "Compare the registry with pinned upstream inventories");
    directive_inventory_step.dependOn(&run_directive_inventory.step);

    const transformation_inventory_module = b.createModule(.{
        .root_source_file = b.path("tools/transformation_inventory.zig"),
        .target = target,
        .optimize = optimize,
    });
    transformation_inventory_module.addImport("waf", waf);
    const transformation_inventory = b.addExecutable(.{
        .name = "transformation-inventory",
        .root_module = transformation_inventory_module,
    });
    const run_transformation_inventory = b.addRunArtifact(transformation_inventory);
    if (b.option([]const u8, "modsecurity-transformation-scanner", "Pinned ModSecurity seclang-scanner.ll")) |path|
        run_transformation_inventory.addArg(path);
    if (b.option([]const u8, "modsecurity-transformation-parser", "Pinned ModSecurity seclang-parser.yy")) |path|
        run_transformation_inventory.addArg(path);
    if (b.option([]const u8, "coraza-transformations", "Pinned Coraza transformations.go")) |path|
        run_transformation_inventory.addArg(path);
    const transformation_inventory_step = b.step("test-transformation-inventory", "Compare the typed transformation registry with pinned upstream inventories");
    transformation_inventory_step.dependOn(&run_transformation_inventory.step);

    const crs_configuration_module = b.createModule(.{
        .root_source_file = b.path("tools/crs_configuration.zig"),
        .target = target,
        .optimize = optimize,
    });
    crs_configuration_module.addImport("waf", waf);
    const crs_configuration = b.addExecutable(.{
        .name = "crs-configuration",
        .root_module = crs_configuration_module,
    });
    const run_crs_configuration = b.addRunArtifact(crs_configuration);
    if (b.option([]const []const u8, "crs-configuration", "Ordered CRS configuration root (repeatable)")) |roots|
        run_crs_configuration.addArgs(roots);
    const crs_configuration_step = b.step("test-crs-configuration", "Compile CRS as one ordered directive configuration");
    crs_configuration_step.dependOn(&run_crs_configuration.step);

    const parser_fuzz_module = b.createModule(.{
        .root_source_file = b.path("tools/parser_fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    parser_fuzz_module.addImport("waf", waf);
    const parser_fuzz = b.addExecutable(.{
        .name = "parser-fuzz",
        .root_module = parser_fuzz_module,
    });
    const run_parser_fuzz = b.addRunArtifact(parser_fuzz);
    const parser_fuzz_iterations = b.option(usize, "parser-fuzz-iterations", "Deterministic parser fuzz case count") orelse 10_000;
    const parser_fuzz_seed = b.option(u64, "parser-fuzz-seed", "Deterministic parser fuzz seed") orelse 6_840_335_614_489_015_467;
    run_parser_fuzz.addArgs(&.{ b.fmt("{d}", .{parser_fuzz_iterations}), b.fmt("{d}", .{parser_fuzz_seed}) });
    const parser_fuzz_step = b.step("fuzz-parser", "Run deterministic SecLang parser fuzz cases");
    parser_fuzz_step.dependOn(&run_parser_fuzz.step);

    const plan_fuzz_module = b.createModule(.{
        .root_source_file = b.path("tools/plan_fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    plan_fuzz_module.addImport("waf", waf);
    const plan_fuzz = b.addExecutable(.{
        .name = "plan-fuzz",
        .root_module = plan_fuzz_module,
    });
    const run_plan_fuzz = b.addRunArtifact(plan_fuzz);
    const plan_fuzz_iterations = b.option(usize, "plan-fuzz-iterations", "Deterministic plan fuzz case count") orelse 10_000;
    const plan_fuzz_seed = b.option(u64, "plan-fuzz-seed", "Deterministic plan fuzz seed") orelse 11_936_128_518_282_651_045;
    run_plan_fuzz.addArgs(&.{ b.fmt("{d}", .{plan_fuzz_iterations}), b.fmt("{d}", .{plan_fuzz_seed}) });
    const plan_fuzz_step = b.step("fuzz-plan", "Run deterministic structural plan fuzz cases");
    plan_fuzz_step.dependOn(&run_plan_fuzz.step);

    const run_directive_fuzz = b.addRunArtifact(plan_fuzz);
    const directive_fuzz_iterations = b.option(usize, "directive-fuzz-iterations", "Deterministic directive fuzz case count") orelse 10_000;
    const directive_fuzz_seed = b.option(u64, "directive-fuzz-seed", "Deterministic directive fuzz seed") orelse 15_781_766_438_473_941_791;
    run_directive_fuzz.addArgs(&.{ b.fmt("{d}", .{directive_fuzz_iterations}), b.fmt("{d}", .{directive_fuzz_seed}) });
    const directive_fuzz_step = b.step("fuzz-directives", "Run deterministic typed directive fuzz cases");
    directive_fuzz_step.dependOn(&run_directive_fuzz.step);

    const action_fuzz_module = b.createModule(.{
        .root_source_file = b.path("tools/action_fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    action_fuzz_module.addImport("waf", waf);
    const action_fuzz = b.addExecutable(.{
        .name = "action-fuzz",
        .root_module = action_fuzz_module,
    });
    const run_action_fuzz = b.addRunArtifact(action_fuzz);
    const action_fuzz_iterations = b.option(usize, "action-fuzz-iterations", "Deterministic action runtime fuzz case count") orelse 10_000;
    const action_fuzz_seed = b.option(u64, "action-fuzz-seed", "Deterministic action runtime fuzz seed") orelse 13_907_095_936_298_285_211;
    run_action_fuzz.addArgs(&.{ b.fmt("{d}", .{action_fuzz_iterations}), b.fmt("{d}", .{action_fuzz_seed}) });
    const action_fuzz_step = b.step("fuzz-actions", "Run deterministic SecLang action runtime fuzz cases");
    action_fuzz_step.dependOn(&run_action_fuzz.step);

    const transformation_fuzz_module = b.createModule(.{
        .root_source_file = b.path("tools/transformation_fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    transformation_fuzz_module.addImport("waf", waf);
    const transformation_fuzz = b.addExecutable(.{
        .name = "transformation-fuzz",
        .root_module = transformation_fuzz_module,
    });
    const run_transformation_fuzz = b.addRunArtifact(transformation_fuzz);
    const transformation_fuzz_iterations = b.option(usize, "transformation-fuzz-iterations", "Deterministic transformation fuzz case count") orelse 10_000;
    const transformation_fuzz_seed = b.option(u64, "transformation-fuzz-seed", "Deterministic transformation fuzz seed") orelse 16_045_690_984_503_098_046;
    run_transformation_fuzz.addArgs(&.{ b.fmt("{d}", .{transformation_fuzz_iterations}), b.fmt("{d}", .{transformation_fuzz_seed}) });
    const transformation_fuzz_step = b.step("fuzz-transformations", "Run deterministic transformation and pipeline fuzz cases");
    transformation_fuzz_step.dependOn(&run_transformation_fuzz.step);

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

    const lifecycle_benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/lifecycle.zig"),
        .target = target,
        .optimize = optimize,
    });
    lifecycle_benchmark_module.addImport("waf", waf);
    const lifecycle_benchmark = b.addExecutable(.{
        .name = "lifecycle-benchmark",
        .root_module = lifecycle_benchmark_module,
    });
    const run_lifecycle_benchmark = b.addRunArtifact(lifecycle_benchmark);
    const lifecycle_benchmark_step = b.step("bench-lifecycle", "Benchmark the complete connector lifecycle");
    lifecycle_benchmark_step.dependOn(&run_lifecycle_benchmark.step);

    const scalar_benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/scalars.zig"),
        .target = target,
        .optimize = optimize,
    });
    scalar_benchmark_module.addImport("waf", waf);
    const scalar_benchmark = b.addExecutable(.{
        .name = "scalar-benchmark",
        .root_module = scalar_benchmark_module,
    });
    const run_scalar_benchmark = b.addRunArtifact(scalar_benchmark);
    const scalar_benchmark_step = b.step("bench-scalars", "Benchmark populated scalar transaction state");
    scalar_benchmark_step.dependOn(&run_scalar_benchmark.step);

    const collection_benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/collections.zig"),
        .target = target,
        .optimize = optimize,
    });
    collection_benchmark_module.addImport("waf", waf);
    const collection_benchmark = b.addExecutable(.{
        .name = "collection-benchmark",
        .root_module = collection_benchmark_module,
    });
    const run_collection_benchmark = b.addRunArtifact(collection_benchmark);
    const collection_benchmark_step = b.step("bench-collections", "Benchmark collection targets and runtime macros");
    collection_benchmark_step.dependOn(&run_collection_benchmark.step);

    const persistence_benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/persistence.zig"),
        .target = target,
        .optimize = optimize,
    });
    persistence_benchmark_module.addImport("waf", waf);
    const persistence_benchmark = b.addExecutable(.{
        .name = "persistence-benchmark",
        .root_module = persistence_benchmark_module,
    });
    const run_persistence_benchmark = b.addRunArtifact(persistence_benchmark);
    const persistence_benchmark_step = b.step("bench-persistence", "Benchmark disabled and initialized persistent collection paths");
    persistence_benchmark_step.dependOn(&run_persistence_benchmark.step);

    const action_benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/actions.zig"),
        .target = target,
        .optimize = optimize,
    });
    action_benchmark_module.addImport("waf", waf);
    const action_benchmark = b.addExecutable(.{
        .name = "action-benchmark",
        .root_module = action_benchmark_module,
    });
    const run_action_benchmark = b.addRunArtifact(action_benchmark);
    const action_benchmark_step = b.step("bench-actions", "Benchmark bounded non-disruptive action application");
    action_benchmark_step.dependOn(&run_action_benchmark.step);

    const parser_benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/parser.zig"),
        .target = target,
        .optimize = optimize,
    });
    parser_benchmark_module.addImport("waf", waf);
    const parser_benchmark = b.addExecutable(.{
        .name = "parser-benchmark",
        .root_module = parser_benchmark_module,
    });
    const run_parser_benchmark = b.addRunArtifact(parser_benchmark);
    if (b.option([]const u8, "parser-benchmark", "Optional SecLang file for the parser benchmark")) |benchmark_path|
        run_parser_benchmark.addArg(benchmark_path);
    const parser_benchmark_step = b.step("bench-parser", "Benchmark SecLang parsing throughput and ownership");
    parser_benchmark_step.dependOn(&run_parser_benchmark.step);

    const plan_benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/plan.zig"),
        .target = target,
        .optimize = optimize,
    });
    plan_benchmark_module.addImport("waf", waf);
    const plan_benchmark = b.addExecutable(.{
        .name = "plan-benchmark",
        .root_module = plan_benchmark_module,
    });
    const run_plan_benchmark = b.addRunArtifact(plan_benchmark);
    if (b.option([]const u8, "plan-benchmark", "Optional SecLang file for the plan benchmark")) |benchmark_path|
        run_plan_benchmark.addArg(benchmark_path);
    const plan_benchmark_step = b.step("bench-plan", "Benchmark structural plan compilation, traversal, reuse, and publication");
    plan_benchmark_step.dependOn(&run_plan_benchmark.step);

    const directive_benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/directives.zig"),
        .target = target,
        .optimize = optimize,
    });
    directive_benchmark_module.addImport("waf", waf);
    const directive_benchmark = b.addExecutable(.{
        .name = "directive-benchmark",
        .root_module = directive_benchmark_module,
    });
    const run_directive_benchmark = b.addRunArtifact(directive_benchmark);
    if (b.option([]const u8, "directive-benchmark", "Optional SecLang file for the directive benchmark")) |benchmark_path|
        run_directive_benchmark.addArg(benchmark_path);
    const directive_benchmark_step = b.step("bench-directives", "Benchmark validation and typed configuration throughput");
    directive_benchmark_step.dependOn(&run_directive_benchmark.step);

    const transformation_benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/transformations.zig"),
        .target = target,
        .optimize = optimize,
    });
    transformation_benchmark_module.addImport("waf", waf);
    const transformation_benchmark = b.addExecutable(.{
        .name = "transformation-benchmark",
        .root_module = transformation_benchmark_module,
    });
    const run_transformation_benchmark = b.addRunArtifact(transformation_benchmark);
    const transformation_benchmark_step = b.step("bench-transformations", "Benchmark borrowed steps, decoder pipelines, digests, multiMatch, and cache behavior");
    transformation_benchmark_step.dependOn(&run_transformation_benchmark.step);
}
