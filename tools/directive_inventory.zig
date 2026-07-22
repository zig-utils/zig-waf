//! Compare the compiled registry with pinned upstream parser inventories.

const std = @import("std");
const waf = @import("waf");

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const modsecurity_path = arguments.next() orelse return error.MissingModSecurityScanner;
    const coraza_path = arguments.next() orelse return error.MissingCorazaDirectiveMap;
    if (arguments.next() != null) return error.UnexpectedArgument;

    const modsecurity_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, modsecurity_path, init.gpa, .limited(4 * 1024 * 1024));
    defer init.gpa.free(modsecurity_bytes);
    const coraza_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, coraza_path, init.gpa, .limited(4 * 1024 * 1024));
    defer init.gpa.free(coraza_bytes);

    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    var modsecurity = try extractModSecurity(allocator, modsecurity_bytes);
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
    }
    if (mismatches != 0) return error.DirectiveInventoryDrift;
    std.debug.print(
        "directive inventory modsecurity={d} coraza={d} stable_union={d} mismatches=0\n",
        .{ modsecurity.names.items.len, coraza.names.items.len, waf.directives.registry.len },
    );
}

const Inventory = struct {
    set: std.StringHashMapUnmanaged(void) = .empty,
    names: std.ArrayList([]const u8) = .empty,

    fn add(self: *Inventory, allocator: std.mem.Allocator, candidate: []const u8) !void {
        if (self.set.contains(candidate)) return;
        const owned = try allocator.dupe(u8, candidate);
        for (owned) |*byte| byte.* = std.ascii.toLower(byte.*);
        if (self.set.contains(owned)) return;
        try self.set.put(allocator, owned, {});
        try self.names.append(allocator, owned);
    }

    fn contains(self: *const Inventory, candidate: []const u8) bool {
        for (self.names.items) |name| if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
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
        try inventory.add(allocator, candidate);
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
        try inventory.add(allocator, candidate);
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

    const coraza = try extractCoraza(arena.allocator(),
        \\var directivesMap = map[string]directive{
        \\    "secrule": directiveSecRule,
        \\    // Unsupported directives
        \\    "secunicodemap": directiveUnsupported,
        \\}
    );
    try std.testing.expect(coraza.set.contains("secrule"));
    try std.testing.expect(coraza.set.contains("secunicodemap"));
    try std.testing.expectEqual(@as(usize, 2), coraza.names.items.len);
}
