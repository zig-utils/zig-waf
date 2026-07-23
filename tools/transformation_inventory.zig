//! Compare the typed transformation registry with pinned upstream inventories.

const std = @import("std");
const transformations = @import("waf").transformations;

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const scanner_path = arguments.next() orelse return error.MissingModSecurityScanner;
    const parser_path = arguments.next() orelse return error.MissingModSecurityParser;
    const coraza_path = arguments.next() orelse return error.MissingCorazaRegistry;
    if (arguments.next() != null) return error.UnexpectedArgument;

    const scanner_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, scanner_path, init.gpa, .limited(4 * 1024 * 1024));
    defer init.gpa.free(scanner_bytes);
    const parser_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, parser_path, init.gpa, .limited(4 * 1024 * 1024));
    defer init.gpa.free(parser_bytes);
    const coraza_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, coraza_path, init.gpa, .limited(4 * 1024 * 1024));
    defer init.gpa.free(coraza_bytes);

    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    var modsecurity = try extractModSecurity(allocator, scanner_bytes);
    var coraza = try extractCoraza(allocator, coraza_bytes);
    var mismatches: usize = 0;

    for (modsecurity.tokens.items) |token| {
        const marker = try std.fmt.allocPrint(allocator, "| {s}", .{token});
        if (std.mem.indexOf(u8, parser_bytes, marker) != null) continue;
        std.debug.print("ModSecurity scanner token has no parser action: {s}\n", .{token});
        mismatches += 1;
    }
    for (modsecurity.names.items) |name| {
        if (transformations.resolve(name) != null) continue;
        std.debug.print("missing transformation from ModSecurity scanner: {s}\n", .{name});
        mismatches += 1;
    }
    for (coraza.names.items) |name| {
        if (transformations.resolve(name) != null) continue;
        std.debug.print("missing transformation from Coraza registry: {s}\n", .{name});
        mismatches += 1;
    }
    for (transformations.specs) |spec| {
        mismatches += checkLocalName(spec.name, &modsecurity.inventory, &coraza);
    }
    mismatches += checkLocalName("none", &modsecurity.inventory, &coraza);
    for (transformations.aliases) |alias| {
        mismatches += checkLocalName(alias.name, &modsecurity.inventory, &coraza);
        const resolution = transformations.resolve(alias.name) orelse unreachable;
        if (resolution != .builtin or resolution.builtin != alias.kind) {
            std.debug.print("typed alias target mismatch: {s}\n", .{alias.name});
            mismatches += 1;
        }
    }

    if (mismatches != 0) return error.TransformationInventoryDrift;
    std.debug.print(
        "transformation inventory modsecurity_names={d} modsecurity_tokens={d} coraza_names={d} canonical={d} aliases={d} reset=1 mismatches=0\n",
        .{ modsecurity.names.items.len, modsecurity.tokens.items.len, coraza.names.items.len, transformations.specs.len, transformations.aliases.len },
    );
}

fn checkLocalName(name: []const u8, modsecurity: *const Inventory, coraza: *const Inventory) usize {
    if (modsecurity.contains(name) or coraza.contains(name)) return 0;
    std.debug.print("typed registry name absent from both upstream inventories: {s}\n", .{name});
    return 1;
}

const Inventory = struct {
    names: std.ArrayList([]const u8) = .empty,

    fn add(self: *Inventory, allocator: std.mem.Allocator, candidate: []const u8) !void {
        if (self.contains(candidate)) return;
        const owned = try allocator.dupe(u8, candidate);
        for (owned) |*byte| byte.* = std.ascii.toLower(byte.*);
        try self.names.append(allocator, owned);
    }

    fn contains(self: *const Inventory, candidate: []const u8) bool {
        for (self.names.items) |name| {
            if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
        }
        return false;
    }
};

const ModSecurityInventory = struct {
    inventory: Inventory = .{},
    names: std.ArrayList([]const u8) = .empty,
    tokens: std.ArrayList([]const u8) = .empty,
};

fn extractModSecurity(allocator: std.mem.Allocator, bytes: []const u8) !ModSecurityInventory {
    var result: ModSecurityInventory = .{};
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, "ACTION_TRANSFORMATION_")) continue;
        const marker = std.mem.indexOf(u8, trimmed, "(?i:t:") orelse continue;
        var fields = std.mem.tokenizeAny(u8, trimmed[0..marker], " \t");
        const token = fields.next() orelse return error.InvalidModSecurityToken;
        if (fields.next() != null) return error.InvalidModSecurityDefinition;
        try result.tokens.append(allocator, try allocator.dupe(u8, token));

        var expression = std.mem.trim(u8, trimmed[marker + "(?i:t:".len ..], " \t\r");
        if (expression.len == 0 or expression[expression.len - 1] != ')') return error.InvalidModSecurityExpression;
        expression = expression[0 .. expression.len - 1];
        if (expression.len >= 2 and expression[0] == '(' and expression[expression.len - 1] == ')')
            expression = expression[1 .. expression.len - 1];
        var names = std.mem.splitScalar(u8, expression, '|');
        while (names.next()) |name| {
            if (!validName(name)) return error.InvalidModSecurityName;
            try result.inventory.add(allocator, name);
        }
    }
    try result.names.appendSlice(allocator, result.inventory.names.items);
    return result;
}

fn extractCoraza(allocator: std.mem.Allocator, bytes: []const u8) !Inventory {
    var result: Inventory = .{};
    var remaining = bytes;
    const marker = "Register(\"";
    while (std.mem.indexOf(u8, remaining, marker)) |offset| {
        const start = offset + marker.len;
        const end = std.mem.indexOfScalar(u8, remaining[start..], '"') orelse return error.InvalidCorazaRegistration;
        const name = remaining[start .. start + end];
        if (!validName(name)) return error.InvalidCorazaName;
        try result.add(allocator, name);
        remaining = remaining[start + end + 1 ..];
    }
    return result;
}

fn validName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte)) return false;
    }
    return true;
}

test "pinned inventory extractors preserve spellings and aliases" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const modsecurity = try extractModSecurity(arena.allocator(),
        \\ACTION_TRANSFORMATION_BASE (?i:t:base64Decode)
        \\ACTION_TRANSFORMATION_PATH (?i:t:(normalisePath|normalizePath))
    );
    try std.testing.expectEqual(@as(usize, 2), modsecurity.tokens.items.len);
    try std.testing.expectEqual(@as(usize, 3), modsecurity.names.items.len);
    try std.testing.expect(modsecurity.inventory.contains("NORMALIZEPATH"));

    const coraza = try extractCoraza(arena.allocator(),
        \\func init() {
        \\    Register("base64Decode", base64decode)
        \\    Register("normalizePath", normalisePath)
        \\}
    );
    try std.testing.expectEqual(@as(usize, 2), coraza.names.items.len);
    try std.testing.expect(coraza.contains("Base64Decode"));
}
