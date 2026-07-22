//! Structured SecRule target, operator, and action syntax.

const std = @import("std");

pub const Limits = struct {
    max_targets: usize = 4096,
    max_actions: usize = 4096,

    pub fn validate(self: Limits) error{InvalidSyntaxLimit}!void {
        if (self.max_targets == 0 or self.max_actions == 0) return error.InvalidSyntaxLimit;
    }
};

pub const Modifier = enum { normal, negated, count };

pub const Target = struct {
    raw: []const u8,
    modifier: Modifier,
    collection: []const u8,
    selector: ?[]const u8,
};

pub const Operator = struct {
    raw: []const u8,
    negated: bool,
    name: []const u8,
    parameter: []const u8,
    implicit_regex: bool,
};

pub const Action = struct {
    raw: []const u8,
    name: []const u8,
    value: ?[]const u8,
};

pub const SyntaxError = std.mem.Allocator.Error || error{
    InvalidSyntaxLimit,
    TooManyTargets,
    TooManyActions,
    EmptyTarget,
    InvalidTargetModifier,
    MissingTargetCollection,
    EmptyOperator,
    MissingOperatorName,
    EmptyAction,
    MissingActionName,
    UnterminatedNestedQuote,
    DanglingNestedEscape,
};

pub fn parseTargets(allocator: std.mem.Allocator, input: []const u8, limits: Limits) SyntaxError![]Target {
    try limits.validate();
    var targets: std.ArrayList(Target) = .empty;
    defer targets.deinit(allocator);
    var start: usize = 0;
    var escaped = false;
    for (input, 0..) |byte, index| {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (byte == '\\') {
            escaped = true;
            continue;
        }
        if (byte != '|') continue;
        try appendTarget(&targets, allocator, input[start..index], limits);
        start = index + 1;
    }
    if (escaped) return error.DanglingNestedEscape;
    try appendTarget(&targets, allocator, input[start..], limits);
    return targets.toOwnedSlice(allocator);
}

pub fn parseOperator(input: []const u8) SyntaxError!Operator {
    var remaining = std.mem.trim(u8, input, " \t");
    if (remaining.len == 0) return error.EmptyOperator;
    var negated = false;
    if (remaining[0] == '!') {
        negated = true;
        remaining = std.mem.trimStart(u8, remaining[1..], " \t");
        if (remaining.len == 0) return error.MissingOperatorName;
    }
    if (remaining[0] != '@') {
        return .{
            .raw = input,
            .negated = negated,
            .name = "rx",
            .parameter = remaining,
            .implicit_regex = true,
        };
    }
    remaining = remaining[1..];
    var name_end: usize = 0;
    while (name_end < remaining.len and remaining[name_end] != ' ' and remaining[name_end] != '\t') name_end += 1;
    if (name_end == 0) return error.MissingOperatorName;
    return .{
        .raw = input,
        .negated = negated,
        .name = remaining[0..name_end],
        .parameter = std.mem.trimStart(u8, remaining[name_end..], " \t"),
        .implicit_regex = false,
    };
}

pub fn parseActions(allocator: std.mem.Allocator, input: []const u8, limits: Limits) SyntaxError![]Action {
    try limits.validate();
    var actions: std.ArrayList(Action) = .empty;
    defer actions.deinit(allocator);
    var start: usize = 0;
    var quote: ?u8 = null;
    var escaped = false;
    for (input, 0..) |byte, index| {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (byte == '\\') {
            escaped = true;
            continue;
        }
        if (quote) |active| {
            if (byte == active) quote = null;
            continue;
        }
        if (byte == '\'' or byte == '"') {
            quote = byte;
            continue;
        }
        if (byte != ',') continue;
        try appendAction(&actions, allocator, input[start..index], limits);
        start = index + 1;
    }
    if (escaped) return error.DanglingNestedEscape;
    if (quote != null) return error.UnterminatedNestedQuote;
    try appendAction(&actions, allocator, input[start..], limits);
    return actions.toOwnedSlice(allocator);
}

fn appendTarget(targets: *std.ArrayList(Target), allocator: std.mem.Allocator, candidate: []const u8, limits: Limits) SyntaxError!void {
    if (targets.items.len == limits.max_targets) return error.TooManyTargets;
    var raw = std.mem.trim(u8, candidate, " \t");
    if (raw.len == 0) return error.EmptyTarget;
    var modifier: Modifier = .normal;
    if (raw[0] == '!' or raw[0] == '&') {
        modifier = if (raw[0] == '!') .negated else .count;
        raw = raw[1..];
        if (raw.len == 0 or raw[0] == '!' or raw[0] == '&') return error.InvalidTargetModifier;
    }
    const colon = unescapedIndex(raw, ':');
    const collection = if (colon) |index| raw[0..index] else raw;
    if (collection.len == 0) return error.MissingTargetCollection;
    try targets.append(allocator, .{
        .raw = std.mem.trim(u8, candidate, " \t"),
        .modifier = modifier,
        .collection = collection,
        .selector = if (colon) |index| raw[index + 1 ..] else null,
    });
}

fn appendAction(actions: *std.ArrayList(Action), allocator: std.mem.Allocator, candidate: []const u8, limits: Limits) SyntaxError!void {
    if (actions.items.len == limits.max_actions) return error.TooManyActions;
    const raw = std.mem.trim(u8, candidate, " \t");
    if (raw.len == 0) return error.EmptyAction;
    const colon = unescapedIndex(raw, ':');
    const name = if (colon) |index| std.mem.trimEnd(u8, raw[0..index], " \t") else raw;
    if (name.len == 0) return error.MissingActionName;
    try actions.append(allocator, .{
        .raw = raw,
        .name = name,
        .value = if (colon) |index| std.mem.trimStart(u8, raw[index + 1 ..], " \t") else null,
    });
}

fn unescapedIndex(input: []const u8, wanted: u8) ?usize {
    var escaped = false;
    for (input, 0..) |byte, index| {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (byte == '\\') {
            escaped = true;
            continue;
        }
        if (byte == wanted) return index;
    }
    return null;
}

test "targets retain modifiers selectors and escaped pipes" {
    const targets = try parseTargets(std.testing.allocator, "ARGS|!REQUEST_HEADERS:authorization|&TX:/^user\\|admin$/", .{});
    defer std.testing.allocator.free(targets);
    try std.testing.expectEqual(@as(usize, 3), targets.len);
    try std.testing.expectEqual(Modifier.normal, targets[0].modifier);
    try std.testing.expectEqual(Modifier.negated, targets[1].modifier);
    try std.testing.expectEqualStrings("authorization", targets[1].selector.?);
    try std.testing.expectEqual(Modifier.count, targets[2].modifier);
    try std.testing.expectEqualStrings("/^user\\|admin$/", targets[2].selector.?);
}

test "operator supports explicit negation and implicit regex" {
    const explicit = try parseOperator("!@rx attack\\s+now");
    try std.testing.expect(explicit.negated);
    try std.testing.expectEqualStrings("rx", explicit.name);
    try std.testing.expectEqualStrings("attack\\s+now", explicit.parameter);
    const implicit = try parseOperator("^attack$");
    try std.testing.expect(implicit.implicit_regex);
    try std.testing.expectEqualStrings("rx", implicit.name);
}

test "actions split only on top-level unescaped commas" {
    const actions = try parseActions(std.testing.allocator, "id:1,msg:'hello, world',setvar:tx.x=a\\,b,deny", .{});
    defer std.testing.allocator.free(actions);
    try std.testing.expectEqual(@as(usize, 4), actions.len);
    try std.testing.expectEqualStrings("msg", actions[1].name);
    try std.testing.expectEqualStrings("'hello, world'", actions[1].value.?);
    try std.testing.expectEqualStrings("tx.x=a\\,b", actions[2].value.?);
    try std.testing.expect(actions[3].value == null);
}

test "structured syntax rejects empty and unterminated elements" {
    try std.testing.expectError(error.EmptyTarget, parseTargets(std.testing.allocator, "ARGS||TX", .{}));
    try std.testing.expectError(error.EmptyOperator, parseOperator("  "));
    try std.testing.expectError(error.EmptyAction, parseActions(std.testing.allocator, "pass,", .{}));
    try std.testing.expectError(error.UnterminatedNestedQuote, parseActions(std.testing.allocator, "msg:'open", .{}));
}
