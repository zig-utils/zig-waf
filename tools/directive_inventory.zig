//! Compare the compiled registry with pinned upstream parser inventories.

const std = @import("std");
const waf = @import("waf");

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const modsecurity_path = arguments.next() orelse return error.MissingModSecurityScanner;
    const modsecurity_parser_path = arguments.next() orelse return error.MissingModSecurityParser;
    const coraza_path = arguments.next() orelse return error.MissingCorazaDirectiveMap;
    if (arguments.next() != null) return error.UnexpectedArgument;

    const modsecurity_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, modsecurity_path, init.gpa, .limited(4 * 1024 * 1024));
    defer init.gpa.free(modsecurity_bytes);
    const modsecurity_parser_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, modsecurity_parser_path, init.gpa, .limited(4 * 1024 * 1024));
    defer init.gpa.free(modsecurity_parser_bytes);
    const coraza_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, coraza_path, init.gpa, .limited(4 * 1024 * 1024));
    defer init.gpa.free(coraza_bytes);

    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    var modsecurity = try extractModSecurity(allocator, modsecurity_bytes);
    var modsecurity_limited = try extractModSecurityLimitations(allocator, modsecurity_parser_bytes);
    var coraza = try extractCoraza(allocator, coraza_bytes);

    var mismatches: usize = 0;
    for (modsecurity.names.items) |name| {
        if (waf.directives.lookup(name) != null) continue;
        std.debug.print("missing registry directive from ModSecurity: {s}\n", .{name});
        mismatches += 1;
    }
    for (coraza.names.items) |name| {
        if (waf.directives.lookup(name) != null) continue;
        std.debug.print("missing registry directive from Coraza: {s}\n", .{name});
        mismatches += 1;
    }
    for (waf.directives.registry) |entry| {
        const in_modsecurity = modsecurity.contains(entry.name);
        const in_coraza = coraza.contains(entry.name);
        const modsecurity_support: waf.directives.UpstreamSupport = if (!in_modsecurity)
            .absent
        else if (modsecurity_limited.contains(entry.name))
            .recognized_limited
        else
            .implemented;
        const coraza_support: waf.directives.UpstreamSupport = if (!in_coraza)
            .absent
        else if (coraza.limitedContains(entry.name))
            .recognized_limited
        else
            .implemented;
        if (!in_modsecurity and !in_coraza) {
            std.debug.print("registry directive absent from both upstream inventories: {s}\n", .{entry.name});
            mismatches += 1;
        }
        if (entry.presence.modsecurity != in_modsecurity) {
            std.debug.print(
                "ModSecurity presence mismatch for {s}: registry={} upstream={}\n",
                .{ entry.name, entry.presence.modsecurity, in_modsecurity },
            );
            mismatches += 1;
        }
        if (entry.presence.coraza != in_coraza) {
            std.debug.print(
                "Coraza presence mismatch for {s}: registry={} upstream={}\n",
                .{ entry.name, entry.presence.coraza, in_coraza },
            );
            mismatches += 1;
        }
        if (entry.modsecurity_support != modsecurity_support) {
            std.debug.print(
                "ModSecurity support mismatch for {s}: registry={t} upstream={t}\n",
                .{ entry.name, entry.modsecurity_support, modsecurity_support },
            );
            mismatches += 1;
        }
        if (entry.coraza_support != coraza_support) {
            std.debug.print(
                "Coraza support mismatch for {s}: registry={t} upstream={t}\n",
                .{ entry.name, entry.coraza_support, coraza_support },
            );
            mismatches += 1;
        }
    }
    if (mismatches != 0) return error.DirectiveInventoryDrift;
    std.debug.print(
        "directive inventory modsecurity={d} modsecurity_limited={d} coraza={d} coraza_limited={d} stable_union={d} mismatches=0\n",
        .{ modsecurity.names.items.len, modsecurity_limited.names.items.len, coraza.names.items.len, coraza.limited.count(), waf.directives.registry.len },
    );
}

const Inventory = struct {
    set: std.StringHashMapUnmanaged(void) = .empty,
    limited: std.StringHashMapUnmanaged(void) = .empty,
    names: std.ArrayList([]const u8) = .empty,

    fn add(self: *Inventory, allocator: std.mem.Allocator, candidate: []const u8, is_limited: bool) !void {
        const owned = try allocator.dupe(u8, candidate);
        for (owned) |*byte| byte.* = std.ascii.toLower(byte.*);
        if (!self.set.contains(owned)) {
            try self.set.put(allocator, owned, {});
            try self.names.append(allocator, owned);
        }
        if (is_limited and !self.limited.contains(owned)) try self.limited.put(allocator, owned, {});
    }

    fn contains(self: *const Inventory, candidate: []const u8) bool {
        for (self.names.items) |name| if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
        return false;
    }

    fn limitedContains(self: *const Inventory, candidate: []const u8) bool {
        var iterator = self.limited.keyIterator();
        while (iterator.next()) |name| if (std.ascii.eqlIgnoreCase(name.*, candidate)) return true;
        return false;
    }
};

fn extractModSecurity(allocator: std.mem.Allocator, bytes: []const u8) !Inventory {
    var inventory: Inventory = .{};
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        const marker = std.mem.indexOf(u8, line, "(?i:Sec") orelse continue;
        const start = marker + "(?i:".len;
        const end_offset = std.mem.indexOfScalar(u8, line[start..], ')') orelse continue;
        const candidate = line[start .. start + end_offset];
        if (!validName(candidate)) continue;
        try inventory.add(allocator, candidate, false);
    }
    return inventory;
}

fn extractModSecurityLimitations(allocator: std.mem.Allocator, bytes: []const u8) !Inventory {
    var inventory: Inventory = .{};
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "supported") == null) continue;
        const start = std.mem.lastIndexOf(u8, line, "Sec") orelse continue;
        var end = start;
        while (end < line.len and std.ascii.isAlphanumeric(line[end])) end += 1;
        const candidate = line[start..end];
        if (!validName(candidate)) continue;
        try inventory.add(allocator, candidate, true);
    }
    return inventory;
}

fn extractCoraza(allocator: std.mem.Allocator, bytes: []const u8) !Inventory {
    var inventory: Inventory = .{};
    var in_map = false;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        if (!in_map) {
            if (std.mem.indexOf(u8, line, "var directivesMap = map[string]directive{") != null) in_map = true;
            continue;
        }
        const trimmed = std.mem.trimStart(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, "}")) break;
        if (trimmed.len < 2 or trimmed[0] != '"') continue;
        const end = std.mem.indexOfScalar(u8, trimmed[1..], '"') orelse continue;
        const candidate = trimmed[1 .. 1 + end];
        if (!validName(candidate)) continue;
        try inventory.add(allocator, candidate, std.mem.indexOf(u8, trimmed, "directiveUnsupported") != null);
    }
    return inventory;
}

fn validName(value: []const u8) bool {
    if (value.len <= 3 or !std.ascii.eqlIgnoreCase(value[0..3], "Sec")) return false;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte)) return false;
    return true;
}

test "inventory extractors include implemented and unsupported stable names" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const modsecurity = try extractModSecurity(arena.allocator(),
        \\CONFIG_RULE (?i:SecRule)
        \\CONFIG_LIMIT (?i:SecConnReadStateLimit)
        \\ACTION (?i:deny)
    );
    try std.testing.expect(modsecurity.set.contains("secrule"));
    try std.testing.expect(modsecurity.set.contains("secconnreadstatelimit"));
    try std.testing.expectEqual(@as(usize, 2), modsecurity.names.items.len);

    const modsecurity_limited = try extractModSecurityLimitations(arena.allocator(),
        \\driver.error(@0, "SecConnReadStateLimit is not yet supported.");
    );
    try std.testing.expect(modsecurity_limited.contains("SecConnReadStateLimit"));

    const coraza = try extractCoraza(arena.allocator(),
        \\var directivesMap = map[string]directive{
        \\    "secrule": directiveSecRule,
        \\    // Unsupported directives
        \\    "secunicodemap": directiveUnsupported,
        \\}
    );
    try std.testing.expect(coraza.set.contains("secrule"));
    try std.testing.expect(coraza.set.contains("secunicodemap"));
    try std.testing.expect(coraza.limited.contains("secunicodemap"));
    try std.testing.expectEqual(@as(usize, 2), coraza.names.items.len);
}
