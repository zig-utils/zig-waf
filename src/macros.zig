//! Compiled, bounded SecLang runtime macro expansion.

const std = @import("std");
const collections = @import("collections.zig");
const variables = @import("variables.zig");

pub const Limits = struct {
    max_input_bytes: usize = 16 * 1024,
    max_tokens: usize = 128,
    max_output_bytes: usize = 32 * 1024,
};

pub const MissingPolicy = enum {
    /// ModSecurity behavior: an unavailable value contributes no bytes.
    empty,
    /// Coraza compatibility: preserve the expression text without `%{`/`}`.
    expression,
};

pub const Resolver = struct {
    context: *anyopaque,
    scalarFn: *const fn (context: *anyopaque, name: variables.Name) ?[]const u8,
    collectionFn: *const fn (context: *anyopaque, name: collections.Name, key: ?[]const u8) ?[]const u8,

    pub fn scalar(self: Resolver, name: variables.Name) ?[]const u8 {
        return self.scalarFn(self.context, name);
    }

    pub fn collection(self: Resolver, name: collections.Name, key: ?[]const u8) ?[]const u8 {
        return self.collectionFn(self.context, name, key);
    }
};

const Range = struct {
    start: usize,
    end: usize,

    fn slice(self: Range, source: []const u8) []const u8 {
        return source[self.start..self.end];
    }
};

const CollectionToken = struct {
    name: collections.Name,
    key: ?Range,
    expression: Range,
};

const Token = union(enum) {
    literal: Range,
    scalar: struct { name: variables.Name, expression: Range },
    collection: CollectionToken,
};

pub const CompileError = std.mem.Allocator.Error || error{
    EmptyMacro,
    MacroInputTooLarge,
    TooManyMacroTokens,
    EmptyMacroExpression,
    EmptyMacroCollection,
    EmptyMacroKey,
    UnknownMacroVariable,
    InvalidMacroCharacter,
    UnterminatedMacro,
};

pub const ExpandError = std.mem.Allocator.Error || error{MacroOutputTooLarge};

pub const Compiled = struct {
    allocator: std.mem.Allocator,
    source: []u8,
    tokens: std.ArrayList(Token) = .empty,
    max_output_bytes: usize,

    pub fn compile(allocator: std.mem.Allocator, input: []const u8, limits: Limits) CompileError!Compiled {
        if (input.len == 0) return error.EmptyMacro;
        if (input.len > limits.max_input_bytes) return error.MacroInputTooLarge;
        const source = try allocator.dupe(u8, input);
        errdefer allocator.free(source);
        var compiled: Compiled = .{
            .allocator = allocator,
            .source = source,
            .max_output_bytes = limits.max_output_bytes,
        };
        errdefer compiled.tokens.deinit(allocator);
        try compiled.tokenize(limits.max_tokens);
        return compiled;
    }

    pub fn expand(
        self: *const Compiled,
        allocator: std.mem.Allocator,
        resolver: Resolver,
        missing_policy: MissingPolicy,
    ) ExpandError![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);
        for (self.tokens.items) |token| {
            const value = switch (token) {
                .literal => |range| range.slice(self.source),
                .scalar => |scalar| resolver.scalar(scalar.name) orelse missingValue(scalar.expression.slice(self.source), missing_policy),
                .collection => |collection| resolver.collection(
                    collection.name,
                    if (collection.key) |key| key.slice(self.source) else null,
                ) orelse missingValue(collection.expression.slice(self.source), missing_policy),
            };
            if (value.len > self.max_output_bytes -| output.items.len) return error.MacroOutputTooLarge;
            try output.appendSlice(allocator, value);
        }
        return output.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *Compiled) void {
        self.tokens.deinit(self.allocator);
        self.allocator.free(self.source);
        self.* = undefined;
    }

    fn tokenize(self: *Compiled, max_tokens: usize) CompileError!void {
        var literal_start: usize = 0;
        var cursor: usize = 0;
        while (cursor < self.source.len) {
            if (self.source[cursor] != '%' or cursor + 1 == self.source.len or self.source[cursor + 1] != '{') {
                cursor += 1;
                continue;
            }
            if (literal_start < cursor) try self.appendToken(.{ .literal = .{ .start = literal_start, .end = cursor } }, max_tokens);
            const expression_start = cursor + 2;
            var expression_end = expression_start;
            while (expression_end < self.source.len and self.source[expression_end] != '}') : (expression_end += 1) {
                if (!validCharacter(self.source[expression_end])) return error.InvalidMacroCharacter;
            }
            if (expression_end == self.source.len) return error.UnterminatedMacro;
            if (expression_end == expression_start) return error.EmptyMacroExpression;
            try self.appendExpression(expression_start, expression_end, max_tokens);
            cursor = expression_end + 1;
            literal_start = cursor;
        }
        if (literal_start < self.source.len) {
            try self.appendToken(.{ .literal = .{ .start = literal_start, .end = self.source.len } }, max_tokens);
        }
    }

    fn appendExpression(self: *Compiled, start: usize, end: usize, max_tokens: usize) CompileError!void {
        const expression = self.source[start..end];
        if (std.mem.indexOfScalar(u8, expression, '.')) |dot| {
            if (dot == 0) return error.EmptyMacroCollection;
            if (dot + 1 == expression.len) return error.EmptyMacroKey;
            const collection = collections.Name.parse(expression[0..dot]) orelse return error.UnknownMacroVariable;
            try self.appendToken(.{ .collection = .{
                .name = collection,
                .key = .{ .start = start + dot + 1, .end = end },
                .expression = .{ .start = start, .end = end },
            } }, max_tokens);
            return;
        }
        if (variables.Name.parse(expression)) |scalar| {
            try self.appendToken(.{ .scalar = .{
                .name = scalar,
                .expression = .{ .start = start, .end = end },
            } }, max_tokens);
            return;
        }
        if (collections.Name.parse(expression)) |collection| {
            try self.appendToken(.{ .collection = .{
                .name = collection,
                .key = null,
                .expression = .{ .start = start, .end = end },
            } }, max_tokens);
            return;
        }
        return error.UnknownMacroVariable;
    }

    fn appendToken(self: *Compiled, token: Token, max_tokens: usize) CompileError!void {
        if (self.tokens.items.len == max_tokens) return error.TooManyMacroTokens;
        try self.tokens.append(self.allocator, token);
    }
};

fn missingValue(expression: []const u8, policy: MissingPolicy) []const u8 {
    return switch (policy) {
        .empty => "",
        .expression => expression,
    };
}

fn validCharacter(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-' or byte == '.' or byte == '[' or byte == ']';
}

const TestResolver = struct {
    fn scalar(_: *anyopaque, name: variables.Name) ?[]const u8 {
        return switch (name) {
            .unique_id => "tx-123",
            else => null,
        };
    }

    fn collection(_: *anyopaque, name: collections.Name, key: ?[]const u8) ?[]const u8 {
        if (name == .tx and key != null and std.ascii.eqlIgnoreCase(key.?, "user")) return "alice";
        if (name == .args and key == null) return "first-argument";
        return null;
    }
};

test "compiled macros expand scalars, keyed collections, and first values" {
    var context: u8 = 0;
    const resolver: Resolver = .{
        .context = &context,
        .scalarFn = TestResolver.scalar,
        .collectionFn = TestResolver.collection,
    };
    var compiled = try Compiled.compile(std.testing.allocator, "%{UNIQUE_ID} %{tx.User} %{ARGS}", .{});
    defer compiled.deinit();
    const expanded = try compiled.expand(std.testing.allocator, resolver, .empty);
    defer std.testing.allocator.free(expanded);
    try std.testing.expectEqualStrings("tx-123 alice first-argument", expanded);
}

test "missing macro policy exposes baseline difference explicitly" {
    var context: u8 = 0;
    const resolver: Resolver = .{
        .context = &context,
        .scalarFn = TestResolver.scalar,
        .collectionFn = TestResolver.collection,
    };
    var compiled = try Compiled.compile(std.testing.allocator, "a=%{tx.missing}", .{});
    defer compiled.deinit();
    const modsecurity = try compiled.expand(std.testing.allocator, resolver, .empty);
    defer std.testing.allocator.free(modsecurity);
    try std.testing.expectEqualStrings("a=", modsecurity);
    const coraza = try compiled.expand(std.testing.allocator, resolver, .expression);
    defer std.testing.allocator.free(coraza);
    try std.testing.expectEqualStrings("a=tx.missing", coraza);
}

test "macro compilation and expansion enforce hostile-input bounds" {
    try std.testing.expectError(error.EmptyMacro, Compiled.compile(std.testing.allocator, "", .{}));
    try std.testing.expectError(error.EmptyMacroExpression, Compiled.compile(std.testing.allocator, "%{}", .{}));
    try std.testing.expectError(error.EmptyMacroKey, Compiled.compile(std.testing.allocator, "%{tx.}", .{}));
    try std.testing.expectError(error.EmptyMacroCollection, Compiled.compile(std.testing.allocator, "%{.key}", .{}));
    try std.testing.expectError(error.UnterminatedMacro, Compiled.compile(std.testing.allocator, "%{tx.key", .{}));
    try std.testing.expectError(error.InvalidMacroCharacter, Compiled.compile(std.testing.allocator, "%{tx:key}", .{}));
    try std.testing.expectError(error.UnknownMacroVariable, Compiled.compile(std.testing.allocator, "%{unknown.key}", .{}));

    var context: u8 = 0;
    const resolver: Resolver = .{
        .context = &context,
        .scalarFn = TestResolver.scalar,
        .collectionFn = TestResolver.collection,
    };
    var bounded = try Compiled.compile(std.testing.allocator, "%{UNIQUE_ID}", .{ .max_output_bytes = 3 });
    defer bounded.deinit();
    try std.testing.expectError(error.MacroOutputTooLarge, bounded.expand(std.testing.allocator, resolver, .empty));
}
