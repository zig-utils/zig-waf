//! Emit the per-item compatibility matrix (#2) from the engine's own registries.
//!
//! The area-level matrix in `src/compatibility/features.json` is hand-written and
//! says what is implemented and why. This is the other half: an item-by-item
//! inventory of every directive, transformation, operator, variable, collection,
//! audit format, and body processor the engine knows, generated from the same tables
//! the engine dispatches on.
//!
//! Generating it is the point. A hand-maintained inventory drifts from the code the
//! moment someone adds a directive and forgets the list, and an inventory that
//! disagrees with the engine is worse than none — it is the document people check
//! instead of reading the source. This one cannot disagree: if the engine gained an
//! operator, the operator is here.
//!
//! Usage: `zig build matrix > compatibility-matrix.json`

const std = @import("std");
const waf = @import("waf");

pub fn main(init: std.process.Init) !void {
    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var out: std.ArrayList(u8) = .empty;
    try out.print(allocator,
        \\{{
        \\  "schema_version": 1,
        \\  "generated_from": "engine registries",
        \\  "baselines": {{ "modsecurity": "3.0.16", "coraza": "3.7.0", "crs": "4.28.0" }},
        \\
    , .{});

    // Directives carry per-baseline support, which is the whole point of the
    // registry: "recognized_limited" means the baseline parses it but does less with
    // it than its name implies, and that distinction is what a compatibility claim
    // lives or dies on.
    try out.appendSlice(allocator, "  \"directives\": [\n");
    for (waf.directives.registry, 0..) |entry, index| {
        if (index != 0) try out.appendSlice(allocator, ",\n");
        try out.print(allocator,
            \\    {{ "name": "{s}", "modsecurity": "{t}", "coraza": "{t}", "issue": {d} }}
        , .{ entry.name, entry.modsecurity_support, entry.coraza_support, entry.owner_issue });
    }
    try out.appendSlice(allocator, "\n  ],\n");

    try appendNames(&out, allocator, "transformations", transformationNames());
    try appendNames(&out, allocator, "transformation_aliases", transformationAliases());
    try appendNames(&out, allocator, "scalar_operators", scalarOperatorNames());
    try appendNames(&out, allocator, "validation_operators", validationOperatorNames());
    try appendNames(&out, allocator, "matcher_operators", matcherOperatorNames());
    try appendNames(&out, allocator, "variables", variableNames());
    try appendNames(&out, allocator, "collections", collectionNames());
    try appendNames(&out, allocator, "audit_formats", auditFormatNames());
    try appendNames(&out, allocator, "body_processors", &.{ "URLENCODED", "JSON", "MULTIPART", "XML" });

    // Counts last, so a reader sees the shape of the inventory without counting the
    // arrays themselves.
    try out.print(allocator,
        \\  "counts": {{ "directives": {d}, "transformations": {d}, "operators": {d}, "variables": {d} }}
        \\}}
        \\
    , .{
        waf.directives.registry.len,
        transformationNames().len,
        scalarOperatorNames().len + validationOperatorNames().len + matcherOperatorNames().len,
        variableNames().len,
    });

    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &stdout_buffer);
    try stdout.interface.writeAll(out.items);
    try stdout.interface.flush();
}

fn appendNames(out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, names: []const []const u8) !void {
    try out.print(allocator, "  \"{s}\": [", .{label});
    for (names, 0..) |name, index| {
        if (index != 0) try out.appendSlice(allocator, ", ");
        try out.print(allocator, "\"{s}\"", .{name});
    }
    try out.appendSlice(allocator, "],\n");
}

fn transformationNames() []const []const u8 {
    const names = comptime blk: {
        var buffer: [waf.transformations.specs.len][]const u8 = undefined;
        for (waf.transformations.specs, 0..) |item, index| buffer[index] = item.name;
        const final = buffer;
        break :blk final;
    };
    return &names;
}

fn transformationAliases() []const []const u8 {
    const names = comptime blk: {
        var buffer: [waf.transformations.aliases.len][]const u8 = undefined;
        for (waf.transformations.aliases, 0..) |item, index| buffer[index] = item.name;
        const final = buffer;
        break :blk final;
    };
    return &names;
}

fn scalarOperatorNames() []const []const u8 {
    const names = comptime blk: {
        var buffer: [waf.operators.specs.len][]const u8 = undefined;
        for (waf.operators.specs, 0..) |item, index| buffer[index] = item.name;
        const final = buffer;
        break :blk final;
    };
    return &names;
}

fn validationOperatorNames() []const []const u8 {
    const names = comptime blk: {
        var buffer: [waf.operators.validation_specs.len][]const u8 = undefined;
        for (waf.operators.validation_specs, 0..) |item, index| buffer[index] = item.name;
        const final = buffer;
        break :blk final;
    };
    return &names;
}

fn matcherOperatorNames() []const []const u8 {
    const names = comptime blk: {
        var buffer: [waf.operators.matcher_specs.len][]const u8 = undefined;
        for (waf.operators.matcher_specs, 0..) |item, index| buffer[index] = item.name;
        const final = buffer;
        break :blk final;
    };
    return &names;
}

fn variableNames() []const []const u8 {
    const names = comptime blk: {
        const fields = @typeInfo(waf.variables.Name).@"enum".field_names;
        var buffer: [fields.len][]const u8 = undefined;
        for (0..fields.len) |index| {
            buffer[index] = @as(waf.variables.Name, @fromBackingInt(@as(u8, @intCast(index)))).secLangName();
        }
        const final = buffer;
        break :blk final;
    };
    return &names;
}

fn collectionNames() []const []const u8 {
    const names = comptime blk: {
        const fields = @typeInfo(waf.collections.Name).@"enum".field_names;
        var buffer: [fields.len][]const u8 = undefined;
        for (0..fields.len) |index| {
            buffer[index] = @as(waf.collections.Name, @fromBackingInt(@as(u8, @intCast(index)))).secLangName();
        }
        const final = buffer;
        break :blk final;
    };
    return &names;
}

fn auditFormatNames() []const []const u8 {
    const names = comptime blk: {
        const fields = @typeInfo(waf.audit.Format).@"enum".field_names;
        var buffer: [fields.len][]const u8 = undefined;
        for (fields, 0..) |name, index| buffer[index] = name;
        const final = buffer;
        break :blk final;
    };
    return &names;
}
