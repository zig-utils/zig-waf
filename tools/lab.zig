//! Benchmark lab orchestrator: zig-waf, ModSecurity and Coraza on the same rules
//! and the same requests (zig-utils/zig-waf#6).
//!
//! `zig build lab` builds one driver per engine (benchmarks/lab) and runs this
//! program with their paths. For every scenario it:
//!
//! 1. assembles the scenario's rule set into one file, identical for all three
//!    engines: benchmarks/lab/base.conf, then for CRS `crs-setup.conf.example`
//!    and `rules/*.conf` in name order. CRS's data files are copied next to it,
//!    because each engine resolves `@pmFromFile` relative to the rule file;
//! 2. runs each driver as its own process under zig-bench's process sampler, so
//!    memory is measured the same way from outside for all three (peak RSS and
//!    private dirty memory, which is `phys_footprint` on macOS);
//! 3. runs the two C drivers again with the malloc counter loaded
//!    (benchmarks/lab/alloc_count.c) to get allocations per request, never
//!    reporting latency from that run. Coraza reports its own allocations from
//!    the Go runtime in the timed run;
//! 4. checks every engine's decisions against the scenario's expectations.
//!
//! It writes `results.json` and `results.md` to the output directory and exits
//! non-zero when an engine fails or disagrees with a scenario: the scenarios are
//! chosen so all three should agree, so a disagreement is a finding to explain,
//! not a number to publish.
//!
//! Usage: lab <crs-dir> <lab-dir> <output-dir> <iterations> <optimize>
//!            <zig-waf-driver> <modsecurity-driver> <coraza-driver> <alloc-counter>

const std = @import("std");
const builtin = @import("builtin");
const process = @import("process");

const Run = struct {
    scenario: []const u8,
    threads: u32,
};

/// Every scenario single-threaded, then the mixed one under concurrency.
const runs = [_]Run{
    .{ .scenario = "no-rules", .threads = 1 },
    .{ .scenario = "crs-get", .threads = 1 },
    .{ .scenario = "crs-get-h2", .threads = 1 },
    .{ .scenario = "crs-attacks", .threads = 1 },
    .{ .scenario = "crs-form-post", .threads = 1 },
    .{ .scenario = "crs-json-post", .threads = 1 },
    .{ .scenario = "crs-mixed", .threads = 1 },
    .{ .scenario = "crs-mixed", .threads = 4 },
};

const Engine = struct {
    name: []const u8,
    driver: []const u8,
    /// Whether allocations come from the malloc counter (the C drivers) rather
    /// than from the driver itself (Go).
    counts_with_interposer: bool,
};

/// What a driver prints (benchmarks/lab/lab.h, benchmarks/lab/coraza/main.go).
const DriverResult = struct {
    engine: []const u8,
    version: []const u8,
    threads: u32,
    requests: u64,
    distinct_requests: u64,
    blocked: u64,
    mismatches: u64,
    load_ns: u64,
    p50_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
    mean_ns: u64,
    throughput_rps: u64,
    peak_rss_bytes: u64,
    allocs_per_request: ?f64,
    alloc_bytes_per_request: ?f64,
};

const Measurement = struct {
    scenario: []const u8,
    driver: DriverResult,
    allocs_per_request: ?f64,
    alloc_bytes_per_request: ?f64,
    sampled_peak_rss_bytes: ?u64,
    sampled_peak_private_dirty_bytes: ?u64,
    kernel_max_rss_bytes: ?u64,
    user_cpu_ns: ?u64,
    system_cpu_ns: ?u64,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const crs_dir = arguments.next() orelse return usage();
    const lab_dir = arguments.next() orelse return usage();
    const output_dir = arguments.next() orelse return usage();
    const iterations = try std.fmt.parseInt(u32, arguments.next() orelse return usage(), 10);
    const optimize = arguments.next() orelse return usage();
    const engines = [_]Engine{
        .{ .name = "zig-waf", .driver = arguments.next() orelse return usage(), .counts_with_interposer = true },
        .{ .name = "modsecurity", .driver = arguments.next() orelse return usage(), .counts_with_interposer = true },
        .{ .name = "coraza", .driver = arguments.next() orelse return usage(), .counts_with_interposer = false },
    };
    const alloc_counter = arguments.next() orelse return usage();

    // Numbers from a Debug build of zig-waf measure Zig's safety checks, not the
    // engine. The other two are always built optimized.
    // The mode's tag is `ReleaseFast` on Zig 0.17 and `fast` on 0.18.
    if (!std.mem.eql(u8, optimize, "ReleaseFast") and !std.mem.eql(u8, optimize, "fast")) {
        std.debug.print("lab: run with -Doptimize=ReleaseFast (got {s}); other modes do not measure the engine\n", .{optimize});
        std.process.exit(2);
    }

    const cwd = std.Io.Dir.cwd();
    const rules_dir = try std.fs.path.join(arena, &.{ output_dir, "rules" });
    try cwd.createDirPath(io, rules_dir);
    const data_files = try assembleRules(arena, io, crs_dir, lab_dir, rules_dir);

    var measurements: std.ArrayList(Measurement) = .empty;
    var problems: usize = 0;
    for (runs) |run| {
        const scenario_path = try std.fmt.allocPrint(arena, "{s}/scenarios/{s}.lab", .{ lab_dir, run.scenario });
        const rule_set = try ruleSetOf(arena, io, scenario_path);
        const rules_path = try std.fmt.allocPrint(arena, "{s}/{s}.conf", .{ rules_dir, rule_set });
        for (engines) |engine| {
            std.debug.print("lab: {s} x{d} on {s}\n", .{ run.scenario, run.threads, engine.name });
            const measured = measure(arena, io, init.environ_map, .{
                .engine = engine,
                .run = run,
                .rules_path = rules_path,
                .data_dir = rules_dir,
                .scenario_path = scenario_path,
                .iterations = iterations,
                .output_dir = output_dir,
                .alloc_counter = alloc_counter,
            }) catch |err| {
                std.debug.print("lab: {s} on {s} failed: {t}\n", .{ run.scenario, engine.name, err });
                problems += 1;
                continue;
            };
            if (measured.driver.mismatches != 0) {
                std.debug.print("lab: {s} disagreed with {d} of {d} expectations in {s}\n", .{
                    engine.name, measured.driver.mismatches, measured.driver.requests, run.scenario,
                });
                problems += 1;
            }
            try measurements.append(arena, measured);
        }
    }

    try writeResults(arena, io, output_dir, measurements.items, data_files, iterations);
    if (problems != 0) {
        std.debug.print("lab: {d} problem(s); see above\n", .{problems});
        std.process.exit(1);
    }
}

fn usage() error{InvalidArguments} {
    std.debug.print(
        "usage: lab <crs-dir> <lab-dir> <output-dir> <iterations> <optimize> " ++
            "<zig-waf-driver> <modsecurity-driver> <coraza-driver> <alloc-counter>\n",
        .{},
    );
    return error.InvalidArguments;
}

/// Writes `none.conf` and `crs.conf` and copies CRS's data files beside them.
/// Returns how many data files were copied.
fn assembleRules(arena: std.mem.Allocator, io: std.Io, crs_dir: []const u8, lab_dir: []const u8, rules_dir: []const u8) !usize {
    const cwd = std.Io.Dir.cwd();
    const limit: std.Io.Limit = .limited(64 * 1024 * 1024);
    const base = try cwd.readFileAlloc(io, try std.fs.path.join(arena, &.{ lab_dir, "base.conf" }), arena, limit);
    try cwd.writeFile(io, .{ .sub_path = try std.fs.path.join(arena, &.{ rules_dir, "none.conf" }), .data = base });

    var crs: std.Io.Writer.Allocating = .init(arena);
    try crs.writer.writeAll(base);
    try crs.writer.writeAll("\n");
    try crs.writer.writeAll(try cwd.readFileAlloc(io, try std.fs.path.join(arena, &.{ crs_dir, "crs-setup.conf.example" }), arena, limit));
    try crs.writer.writeAll("\n");

    const crs_rules = try std.fs.path.join(arena, &.{ crs_dir, "rules" });
    var directory = try cwd.openDir(io, crs_rules, .{ .iterate = true });
    defer directory.close(io);
    var configs: std.ArrayList([]const u8) = .empty;
    var data_files: usize = 0;
    var entries = directory.iterate();
    while (try entries.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.endsWith(u8, entry.name, ".conf")) {
            try configs.append(arena, try arena.dupe(u8, entry.name));
        } else if (std.mem.endsWith(u8, entry.name, ".data")) {
            try directory.copyFile(entry.name, cwd, try std.fs.path.join(arena, &.{ rules_dir, entry.name }), io, .{});
            data_files += 1;
        }
    }
    std.mem.sort([]const u8, configs.items, {}, lessThan);
    for (configs.items) |name| {
        try crs.writer.writeAll(try cwd.readFileAlloc(io, try std.fs.path.join(arena, &.{ crs_rules, name }), arena, limit));
        try crs.writer.writeAll("\n");
    }
    if (configs.items.len == 0) return error.NoCrsRules;
    try cwd.writeFile(io, .{ .sub_path = try std.fs.path.join(arena, &.{ rules_dir, "crs.conf" }), .data = crs.written() });
    std.debug.print("lab: assembled CRS from {d} rule files and {d} data files\n", .{ configs.items.len, data_files });
    return data_files;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// The `rules <set>` line of a scenario.
fn ruleSetOf(arena: std.mem.Allocator, io: std.Io, scenario_path: []const u8) ![]const u8 {
    const text = try std.Io.Dir.cwd().readFileAlloc(io, scenario_path, arena, .limited(1024 * 1024));
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "rules ")) {
            const set = std.mem.trim(u8, line["rules ".len..], " \r");
            if (std.mem.eql(u8, set, "none") or std.mem.eql(u8, set, "crs")) return set;
            return error.UnknownRuleSet;
        }
    }
    return error.ScenarioWithoutRuleSet;
}

const Job = struct {
    engine: Engine,
    run: Run,
    rules_path: []const u8,
    data_dir: []const u8,
    scenario_path: []const u8,
    iterations: u32,
    output_dir: []const u8,
    alloc_counter: []const u8,
};

fn measure(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, job: Job) !Measurement {
    const result_path = try std.fmt.allocPrint(arena, "{s}/{s}-{s}-x{d}.json", .{
        job.output_dir, job.engine.name, job.run.scenario, job.run.threads,
    });
    const timed = try runDriver(arena, io, environ, job, job.iterations, result_path, null);

    var allocs = timed.driver.allocs_per_request;
    var alloc_bytes = timed.driver.alloc_bytes_per_request;
    if (job.engine.counts_with_interposer) {
        // A shorter run is enough: allocations per request do not depend on how
        // long the loop runs, and counting slows every call.
        const counted_path = try std.fmt.allocPrint(arena, "{s}/{s}-{s}-x{d}-allocs.json", .{
            job.output_dir, job.engine.name, job.run.scenario, job.run.threads,
        });
        const counted = try runDriver(arena, io, environ, job, @max(job.iterations / 10, 100), counted_path, job.alloc_counter);
        allocs = counted.driver.allocs_per_request orelse return error.AllocationCounterNotLoaded;
        alloc_bytes = counted.driver.alloc_bytes_per_request;
    }

    return .{
        .scenario = job.run.scenario,
        .driver = timed.driver,
        .allocs_per_request = allocs,
        .alloc_bytes_per_request = alloc_bytes,
        .sampled_peak_rss_bytes = timed.peak_rss,
        .sampled_peak_private_dirty_bytes = timed.peak_private_dirty,
        .kernel_max_rss_bytes = timed.max_rss,
        .user_cpu_ns = timed.user_cpu_ns,
        .system_cpu_ns = timed.system_cpu_ns,
    };
}

const DriverRun = struct {
    driver: DriverResult,
    peak_rss: ?u64,
    peak_private_dirty: ?u64,
    max_rss: ?u64,
    user_cpu_ns: ?u64,
    system_cpu_ns: ?u64,
};

fn runDriver(
    arena: std.mem.Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
    job: Job,
    iterations: u32,
    result_path: []const u8,
    alloc_counter: ?[]const u8,
) !DriverRun {
    var env = try environ.clone(arena);
    try env.put("LAB_RESULT", result_path);
    if (alloc_counter) |library| {
        try env.put(if (builtin.os.tag == .macos) "DYLD_INSERT_LIBRARIES" else "LD_PRELOAD", library);
    }
    const iterations_text = try std.fmt.allocPrint(arena, "{d}", .{iterations});
    const threads_text = try std.fmt.allocPrint(arena, "{d}", .{job.run.threads});
    var result = try process.run(arena, io, .{
        .argv = &.{ job.engine.driver, job.rules_path, job.data_dir, job.scenario_path, iterations_text, threads_text },
        .sample_hz = 20,
        .environ_map = &env,
        .stdout = .ignore,
        .stderr = .inherit,
        .timeout_ns = 30 * 60 * std.time.ns_per_s,
    });
    defer result.deinit();
    if (result.timed_out or !result.term.success()) return error.DriverFailed;

    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, result_path, arena, .limited(64 * 1024));
    const parsed = try std.json.parseFromSliceLeaky(DriverResult, arena, bytes, .{ .ignore_unknown_fields = true });
    return .{
        .driver = parsed,
        .peak_rss = result.stat(.rss, .peak),
        .peak_private_dirty = result.stat(.private_dirty, .peak),
        .max_rss = result.max_rss,
        .user_cpu_ns = result.user_cpu_ns,
        .system_cpu_ns = result.system_cpu_ns,
    };
}

fn writeResults(
    arena: std.mem.Allocator,
    io: std.Io,
    output_dir: []const u8,
    measurements: []const Measurement,
    data_files: usize,
    iterations: u32,
) !void {
    const cwd = std.Io.Dir.cwd();

    var json: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(measurements, .{ .whitespace = .indent_2 }, &json.writer);
    try json.writer.writeAll("\n");
    try cwd.writeFile(io, .{ .sub_path = try std.fs.path.join(arena, &.{ output_dir, "results.json" }), .data = json.written() });

    var md: std.Io.Writer.Allocating = .init(arena);
    const w = &md.writer;
    try w.print("{d} timed requests per run, CRS data files: {d}, {s}-{s}.\n\n", .{
        iterations, data_files, @tagName(builtin.cpu.arch), @tagName(builtin.os.tag),
    });
    try w.writeAll("| Scenario | Threads | Engine | p50 | p99 | p99.9 | Throughput | Allocs/req | Alloc KiB/req | Peak RSS | Peak dirty | Load | Blocked | Mismatches |\n");
    try w.writeAll("| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for (measurements) |m| {
        const d = m.driver;
        try w.print("| {s} | {d} | {s} {s} | ", .{ m.scenario, d.threads, d.engine, d.version });
        try writeDuration(w, d.p50_ns);
        try w.writeAll(" | ");
        try writeDuration(w, d.p99_ns);
        try w.writeAll(" | ");
        try writeDuration(w, d.p999_ns);
        try w.print(" | {d} rps | ", .{d.throughput_rps});
        if (m.allocs_per_request) |a| try w.print("{d:.0}", .{a}) else try w.writeAll("n/a");
        try w.writeAll(" | ");
        if (m.alloc_bytes_per_request) |b| try w.print("{d:.1}", .{b / 1024.0}) else try w.writeAll("n/a");
        try w.writeAll(" | ");
        // A short run can end between samples, so the kernel's own maximum
        // stands in whenever it is the larger figure.
        try writeMebibytes(w, maxOptional(m.sampled_peak_rss_bytes, m.kernel_max_rss_bytes));
        try w.writeAll(" | ");
        try writeMebibytes(w, m.sampled_peak_private_dirty_bytes);
        try w.writeAll(" | ");
        try writeDuration(w, d.load_ns);
        try w.print(" | {d}/{d} | {d} |\n", .{ d.blocked, d.requests, d.mismatches });
    }
    try cwd.writeFile(io, .{ .sub_path = try std.fs.path.join(arena, &.{ output_dir, "results.md" }), .data = md.written() });
    std.debug.print("lab: wrote {s}/results.json and {s}/results.md\n", .{ output_dir, output_dir });
}

fn maxOptional(a: ?u64, b: ?u64) ?u64 {
    if (a == null) return b;
    if (b == null) return a;
    return @max(a.?, b.?);
}

fn writeDuration(w: *std.Io.Writer, ns: u64) !void {
    if (ns >= std.time.ns_per_s) {
        try w.print("{d:.2} s", .{@as(f64, @floatFromInt(ns)) / std.time.ns_per_s});
    } else if (ns >= std.time.ns_per_ms) {
        try w.print("{d:.2} ms", .{@as(f64, @floatFromInt(ns)) / std.time.ns_per_ms});
    } else {
        try w.print("{d:.1} µs", .{@as(f64, @floatFromInt(ns)) / std.time.ns_per_us});
    }
}

fn writeMebibytes(w: *std.Io.Writer, bytes: ?u64) !void {
    const value = bytes orelse return w.writeAll("n/a");
    try w.print("{d:.1} MiB", .{@as(f64, @floatFromInt(value)) / (1024.0 * 1024.0)});
}
