//! Parse every SecLang configuration file below one or more corpus roots.

const std = @import("std");
const waf = @import("waf");

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    var totals: Totals = .{};
    var root_count: usize = 0;
    var compile_plans = false;
    while (arguments.next()) |root| {
        if (std.mem.eql(u8, root, "--compile-plan")) {
            compile_plans = true;
            continue;
        }
        root_count += 1;
        try parseRoot(init.gpa, init.io, root, compile_plans, &totals);
    }
    if (root_count == 0) return error.MissingCorpusRoot;
    std.debug.print(
        "parser corpus roots={d} files={d} bytes={d} directives={d} plans={d} rules={d} plan_owned_bytes={d}\n",
        .{ root_count, totals.files, totals.bytes, totals.directives, totals.plans, totals.rules, totals.plan_owned_bytes },
    );
}

const Totals = struct {
    files: usize = 0,
    bytes: usize = 0,
    directives: usize = 0,
    plans: usize = 0,
    rules: usize = 0,
    plan_owned_bytes: usize = 0,
};

fn parseRoot(allocator: std.mem.Allocator, io: std.Io, root_path: []const u8, compile_plans: bool, totals: *Totals) !void {
    const canonical_root = try std.Io.Dir.cwd().realPathFileAlloc(io, root_path, allocator);
    defer allocator.free(canonical_root);
    const stat = try std.Io.Dir.cwd().statFile(io, canonical_root, .{});
    if (stat.kind == .file) {
        if (!isConfiguration(std.fs.path.basename(canonical_root))) return error.NotConfigurationFile;
        return parseFile(allocator, io, canonical_root, compile_plans, totals);
    }
    if (stat.kind != .directory) return error.InvalidCorpusRoot;
    var directory = try std.Io.Dir.openDirAbsolute(io, canonical_root, .{ .iterate = true });
    defer directory.close(io);
    var walker = try directory.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file or !isConfiguration(entry.basename)) continue;
        const path = try std.fs.path.join(allocator, &.{ canonical_root, entry.path });
        defer allocator.free(path);
        try parseFile(allocator, io, path, compile_plans, totals);
    }
}

fn parseFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8, compile_plans: bool, totals: *Totals) !void {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(32 * 1024 * 1024));
    defer allocator.free(bytes);
    var parsed = try waf.seclang.parser.parseBytesOutcome(allocator, path, bytes, .{}, .{});
    defer parsed.deinit();
    switch (parsed.outcome) {
        .document => |document| {
            totals.files += 1;
            totals.bytes += bytes.len;
            totals.directives += document.directives.items.len;
            if (compile_plans) {
                var documents = [_]waf.seclang.parser.Document{document};
                const compiled = waf.plan.compile(allocator, &parsed.registry, &documents, .{}) catch |failure| {
                    std.debug.print("{s}: structural plan compilation failed: {t}\n", .{ path, failure });
                    return error.PlanCorpusCompileFailed;
                };
                defer compiled.deinit();
                totals.plans += 1;
                totals.rules += compiled.rules.len;
                totals.plan_owned_bytes += compiled.owned_bytes;
            }
        },
        .diagnostic => |value| {
            const rendered = try waf.seclang.diagnostic.renderHuman(allocator, &parsed.registry, value, .{});
            defer allocator.free(rendered);
            std.debug.print("{s}", .{rendered});
            return error.CorpusParseFailed;
        },
    }
}

fn isConfiguration(name: []const u8) bool {
    return std.mem.endsWith(u8, name, ".conf") or std.mem.endsWith(u8, name, ".conf.example");
}

test "corpus extension selection is explicit" {
    try std.testing.expect(isConfiguration("rules.conf"));
    try std.testing.expect(isConfiguration("setup.conf.example"));
    try std.testing.expect(!isConfiguration("rules.yaml"));
}
