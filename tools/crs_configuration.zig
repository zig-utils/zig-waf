//! Compile and validate deployable CRS files as one ordered configuration.

const std = @import("std");
const waf = @import("waf");

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    var paths: std.ArrayList([]u8) = .empty;
    defer {
        for (paths.items) |path| init.gpa.free(path);
        paths.deinit(init.gpa);
    }
    var root_count: usize = 0;
    while (arguments.next()) |root| {
        root_count += 1;
        try collectRoot(init.gpa, init.io, root, &paths);
    }
    if (root_count == 0) return error.MissingConfigurationRoot;
    std.mem.sort([]u8, paths.items, {}, pathLessThan);

    var registry = try waf.seclang.source.Registry.init(init.gpa, .{});
    defer registry.deinit();
    var documents: std.ArrayList(waf.seclang.parser.Document) = .empty;
    defer {
        for (documents.items) |*document| document.deinit();
        documents.deinit(init.gpa);
    }
    var input_bytes: usize = 0;
    for (paths.items) |path| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(32 * 1024 * 1024));
        defer init.gpa.free(bytes);
        const source_id = try registry.add(path, bytes, null);
        var document = try waf.seclang.parser.parseSource(init.gpa, &registry, source_id, .{});
        documents.append(init.gpa, document) catch |failure| {
            document.deinit();
            return failure;
        };
        input_bytes += bytes.len;
    }

    const compiled = waf.plan.compile(init.gpa, &registry, documents.items, .{}) catch |failure| {
        std.debug.print("ordered CRS plan compilation failed: {t}\n", .{failure});
        return error.CrsPlanCompileFailed;
    };
    defer compiled.deinit();
    switch (waf.directives.validatePlan(compiled, .full())) {
        .valid => {},
        .diagnostic => |diagnostic| {
            const location = try compiled.sourceLocation(diagnostic.primary.source, diagnostic.primary.start);
            const source_record = compiled.sources[@backingInt(diagnostic.primary.source)];
            std.debug.print(
                "{s}:{d}:{d}: {s}: {s}\n",
                .{ compiled.string(source_record.path).?, location.line, location.column, diagnostic.code.id(), diagnostic.message },
            );
            return error.CrsDirectiveValidationFailed;
        },
    }
    const configuration = waf.directives.Configuration.init(compiled, .full()).configuration;
    std.debug.print(
        "ordered CRS roots={d} files={d} bytes={d} directives={d} rules={d} plan_owned_bytes={d} fingerprint={x}\n",
        .{ root_count, paths.items.len, input_bytes, compiled.directives.len, compiled.rules.len, compiled.owned_bytes, configuration.fingerprint },
    );
}

fn collectRoot(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_path: []const u8,
    paths: *std.ArrayList([]u8),
) !void {
    const resolved_root = try std.Io.Dir.cwd().realPathFileAlloc(io, root_path, allocator);
    defer allocator.free(resolved_root);
    const canonical_root = try allocator.dupe(u8, resolved_root);
    errdefer allocator.free(canonical_root);
    const stat = try std.Io.Dir.cwd().statFile(io, canonical_root, .{});
    if (stat.kind == .file) {
        if (!isConfiguration(std.fs.path.basename(canonical_root))) return error.NotConfigurationFile;
        try paths.append(allocator, canonical_root);
        return;
    }
    defer allocator.free(canonical_root);
    if (stat.kind != .directory) return error.InvalidConfigurationRoot;
    var directory = try std.Io.Dir.openDirAbsolute(io, canonical_root, .{ .iterate = true });
    defer directory.close(io);
    var walker = try directory.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file or !isConfiguration(entry.basename)) continue;
        try paths.append(allocator, try std.fs.path.join(allocator, &.{ canonical_root, entry.path }));
    }
}

fn isConfiguration(name: []const u8) bool {
    return std.mem.endsWith(u8, name, ".conf") or std.mem.endsWith(u8, name, ".conf.example");
}

fn pathLessThan(_: void, first: []u8, second: []u8) bool {
    return std.mem.order(u8, first, second) == .lt;
}

test "configuration selection and ordering are deterministic" {
    try std.testing.expect(isConfiguration("REQUEST-901.conf"));
    try std.testing.expect(isConfiguration("crs-setup.conf.example"));
    try std.testing.expect(!isConfiguration("README.md"));
    var paths = [_][]u8{ @constCast("z.conf"), @constCast("a.conf"), @constCast("m.conf") };
    std.mem.sort([]u8, &paths, {}, pathLessThan);
    try std.testing.expectEqualStrings("a.conf", paths[0]);
    try std.testing.expectEqualStrings("m.conf", paths[1]);
    try std.testing.expectEqualStrings("z.conf", paths[2]);
}
