//! Lossless directive-shape parser for bounded SecLang tokens.

const std = @import("std");
const lexer = @import("lexer.zig");
const source = @import("source.zig");
const syntax = @import("syntax.zig");

pub const Limits = struct {
    lexer: lexer.Limits = .{},
    syntax: syntax.Limits = .{},
    max_directives: usize = 100_000,
    max_arguments: usize = 500_000,

    pub fn validate(self: Limits) error{InvalidParserLimit}!void {
        self.lexer.validate() catch return error.InvalidParserLimit;
        self.syntax.validate() catch return error.InvalidParserLimit;
        if (self.max_directives == 0 or self.max_arguments == 0) return error.InvalidParserLimit;
    }
};

pub const Kind = enum {
    generic,
    sec_rule,
    sec_action,
    sec_default_action,
    sec_marker,
    include,
    include_optional,
};

pub const Argument = struct {
    raw: []const u8,
    quote: lexer.Quote,
    physical: source.Span,

    pub fn content(self: Argument) []const u8 {
        if (self.raw.len < 2) return self.raw;
        return switch (self.quote) {
            .single => if (self.raw[0] == '\'' and self.raw[self.raw.len - 1] == '\'') self.raw[1 .. self.raw.len - 1] else self.raw,
            .double => if (self.raw[0] == '"' and self.raw[self.raw.len - 1] == '"') self.raw[1 .. self.raw.len - 1] else self.raw,
            else => self.raw,
        };
    }
};

pub const Directive = struct {
    name: []const u8,
    name_span: source.Span,
    physical: source.Span,
    arguments: []const Argument,
    kind: Kind,
    parsed_targets: []const syntax.Target = &.{},
    parsed_operator: ?syntax.Operator = null,
    parsed_actions: []const syntax.Action = &.{},

    pub fn targets(self: Directive) ?Argument {
        if (self.kind != .sec_rule) return null;
        return self.arguments[0];
    }

    pub fn operator(self: Directive) ?Argument {
        if (self.kind != .sec_rule) return null;
        return self.arguments[1];
    }

    pub fn actions(self: Directive) ?Argument {
        return switch (self.kind) {
            .sec_rule => if (self.arguments.len == 3) self.arguments[2] else null,
            .sec_action, .sec_default_action => self.arguments[0],
            else => null,
        };
    }
};

pub const Document = struct {
    arena: std.heap.ArenaAllocator,
    source_id: source.SourceId,
    directives: std.ArrayList(Directive) = .empty,
    argument_count: usize = 0,

    pub fn deinit(self: *Document) void {
        self.directives.deinit(self.arena.allocator());
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const ParseError = lexer.LexerError || syntax.SyntaxError || std.mem.Allocator.Error || error{
    InvalidParserLimit,
    InvalidSourceId,
    TooManyDirectives,
    TooManyArguments,
    InvalidDirectiveName,
    MissingRuleTargets,
    MissingRuleOperator,
    TooManyRuleArguments,
    MissingActionList,
    TooManyActionArguments,
    MissingMarker,
    TooManyMarkerArguments,
    MissingIncludePath,
    TooManyIncludeArguments,
};

pub fn parseSource(
    allocator: std.mem.Allocator,
    registry: *const source.Registry,
    source_id: source.SourceId,
    limits: Limits,
) ParseError!Document {
    try limits.validate();
    const input = registry.get(source_id) orelse return error.InvalidSourceId;
    var document: Document = .{ .arena = .init(allocator), .source_id = source_id };
    errdefer document.deinit();
    var lines = try lexer.LogicalLineIterator.init(input, limits.lexer);
    while (try lines.next(allocator)) |line_value| {
        var line = line_value;
        defer line.deinit();
        var tokens = try lexer.tokenize(&line, allocator, limits.lexer);
        defer tokens.deinit();
        if (tokens.tokens.len == 0) continue;
        if (document.directives.items.len == limits.max_directives) return error.TooManyDirectives;
        const name_token = tokens.tokens[0];
        if (name_token.quote != .unquoted or !validDirectiveName(name_token.raw)) return error.InvalidDirectiveName;
        const argument_count = tokens.tokens.len - 1;
        if (argument_count > limits.max_arguments -| document.argument_count) return error.TooManyArguments;
        const kind = classify(name_token.raw);
        try validateShape(kind, argument_count);

        const arena = document.arena.allocator();
        const arguments = try arena.alloc(Argument, argument_count);
        for (tokens.tokens[1..], arguments) |token, *argument| {
            argument.* = .{
                .raw = try arena.dupe(u8, token.raw),
                .quote = token.quote,
                .physical = token.physical,
            };
        }
        var parsed_targets: []const syntax.Target = &.{};
        var parsed_operator: ?syntax.Operator = null;
        var parsed_actions: []const syntax.Action = &.{};
        switch (kind) {
            .sec_rule => {
                parsed_targets = try syntax.parseTargets(arena, arguments[0].content(), limits.syntax);
                parsed_operator = try syntax.parseOperator(arguments[1].content());
                if (arguments.len == 3) {
                    parsed_actions = try syntax.parseActions(arena, arguments[2].content(), limits.syntax);
                }
            },
            .sec_action, .sec_default_action => {
                parsed_actions = try syntax.parseActions(arena, arguments[0].content(), limits.syntax);
            },
            else => {},
        }
        try document.directives.append(arena, .{
            .name = try arena.dupe(u8, name_token.raw),
            .name_span = name_token.physical,
            .physical = line.physical,
            .arguments = arguments,
            .kind = kind,
            .parsed_targets = parsed_targets,
            .parsed_operator = parsed_operator,
            .parsed_actions = parsed_actions,
        });
        document.argument_count += argument_count;
    }
    return document;
}

fn classify(name: []const u8) Kind {
    if (std.ascii.eqlIgnoreCase(name, "SecRule")) return .sec_rule;
    if (std.ascii.eqlIgnoreCase(name, "SecAction")) return .sec_action;
    if (std.ascii.eqlIgnoreCase(name, "SecDefaultAction")) return .sec_default_action;
    if (std.ascii.eqlIgnoreCase(name, "SecMarker")) return .sec_marker;
    if (std.ascii.eqlIgnoreCase(name, "Include")) return .include;
    if (std.ascii.eqlIgnoreCase(name, "IncludeOptional")) return .include_optional;
    return .generic;
}

fn validateShape(kind: Kind, argument_count: usize) ParseError!void {
    switch (kind) {
        .sec_rule => {
            if (argument_count == 0) return error.MissingRuleTargets;
            if (argument_count == 1) return error.MissingRuleOperator;
            if (argument_count > 3) return error.TooManyRuleArguments;
        },
        .sec_action, .sec_default_action => {
            if (argument_count == 0) return error.MissingActionList;
            if (argument_count > 1) return error.TooManyActionArguments;
        },
        .sec_marker => {
            if (argument_count == 0) return error.MissingMarker;
            if (argument_count > 1) return error.TooManyMarkerArguments;
        },
        .include, .include_optional => {
            if (argument_count == 0) return error.MissingIncludePath;
            if (argument_count > 1) return error.TooManyIncludeArguments;
        },
        .generic => {},
    }
}

fn validDirectiveName(name: []const u8) bool {
    if (name.len == 0 or !std.ascii.isAlphabetic(name[0])) return false;
    for (name[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') return false;
    }
    return true;
}

test "parser owns directive shapes across comments and continuations" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const id = try registry.add(
        "rules.conf",
        "# heading\nSecRule ARGS \\\n  \"@rx ^#attack\" \\\n  \"id:1,deny\" # block\nsecaction \"setvar:tx.score=1,pass\"\nIncludeOptional \"conf.d/*.conf\"",
        null,
    );
    var document = try parseSource(std.testing.allocator, &registry, id, .{});
    defer document.deinit();
    try std.testing.expectEqual(@as(usize, 3), document.directives.items.len);
    const rule = document.directives.items[0];
    try std.testing.expectEqual(Kind.sec_rule, rule.kind);
    try std.testing.expectEqualStrings("ARGS", rule.targets().?.content());
    try std.testing.expectEqualStrings("@rx ^#attack", rule.operator().?.content());
    try std.testing.expectEqualStrings("id:1,deny", rule.actions().?.content());
    try std.testing.expectEqual(@as(usize, 1), rule.parsed_targets.len);
    try std.testing.expectEqualStrings("ARGS", rule.parsed_targets[0].collection);
    try std.testing.expectEqualStrings("rx", rule.parsed_operator.?.name);
    try std.testing.expectEqualStrings("^#attack", rule.parsed_operator.?.parameter);
    try std.testing.expectEqual(@as(usize, 2), rule.parsed_actions.len);
    try std.testing.expectEqualStrings("deny", rule.parsed_actions[1].name);
    try std.testing.expectEqual(Kind.sec_action, document.directives.items[1].kind);
    try std.testing.expectEqual(@as(usize, 2), document.directives.items[1].parsed_actions.len);
    try std.testing.expectEqual(Kind.include_optional, document.directives.items[2].kind);
}

test "parser attaches structured targets operators and actions" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const id = try registry.add(
        "structured.conf",
        "SecRule ARGS|!REQUEST_HEADERS:authorization \"!@contains secret\" \"id:42,msg:'private, token',deny\"\nSecDefaultAction \"phase:2,log,pass\"",
        null,
    );
    var document = try parseSource(std.testing.allocator, &registry, id, .{});
    defer document.deinit();
    const rule = document.directives.items[0];
    try std.testing.expectEqual(@as(usize, 2), rule.parsed_targets.len);
    try std.testing.expectEqual(syntax.Modifier.negated, rule.parsed_targets[1].modifier);
    try std.testing.expectEqualStrings("authorization", rule.parsed_targets[1].selector.?);
    try std.testing.expect(rule.parsed_operator.?.negated);
    try std.testing.expectEqualStrings("contains", rule.parsed_operator.?.name);
    try std.testing.expectEqualStrings("secret", rule.parsed_operator.?.parameter);
    try std.testing.expectEqual(@as(usize, 3), rule.parsed_actions.len);
    try std.testing.expectEqualStrings("'private, token'", rule.parsed_actions[1].value.?);
    try std.testing.expectEqual(@as(usize, 3), document.directives.items[1].parsed_actions.len);
}

test "parser strictly validates directive and rule shapes" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const quoted_name = try registry.add("quoted.conf", "\"SecAction\" pass", null);
    try std.testing.expectError(error.InvalidDirectiveName, parseSource(std.testing.allocator, &registry, quoted_name, .{}));
    const missing_operator = try registry.add("missing.conf", "SecRule ARGS", null);
    try std.testing.expectError(error.MissingRuleOperator, parseSource(std.testing.allocator, &registry, missing_operator, .{}));
    const trailing = try registry.add("many.conf", "SecRule ARGS @rx pass extra", null);
    try std.testing.expectError(error.TooManyRuleArguments, parseSource(std.testing.allocator, &registry, trailing, .{}));
    const no_action = try registry.add("action.conf", "SecAction", null);
    try std.testing.expectError(error.MissingActionList, parseSource(std.testing.allocator, &registry, no_action, .{}));
}

test "parser enforces document aggregate limits" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const id = try registry.add("rules.conf", "SecAction pass\nSecAction deny", null);
    try std.testing.expectError(error.TooManyDirectives, parseSource(std.testing.allocator, &registry, id, .{ .max_directives = 1 }));
    try std.testing.expectError(error.TooManyArguments, parseSource(std.testing.allocator, &registry, id, .{ .max_arguments = 1 }));
}

test "parser propagates structured syntax failures and limits" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const malformed = try registry.add("malformed.conf", "SecRule \"ARGS||TX\" @rx", null);
    try std.testing.expectError(error.EmptyTarget, parseSource(std.testing.allocator, &registry, malformed, .{}));
    const bounded = try registry.add("bounded.conf", "SecAction \"log,pass\"", null);
    try std.testing.expectError(error.TooManyActions, parseSource(std.testing.allocator, &registry, bounded, .{ .syntax = .{ .max_actions = 1 } }));
}
