//! Operator evaluation for rule execution.
//!
//! Given an operator name, its (macro-expanded) argument, and a transformed
//! variable value, decide whether the operator matches — before rule negation.
//! This is the leaf of the rule-execution engine: the layer above resolves a
//! rule's targets to values and applies its transformations, then calls here
//! once per (value × operator).
//!
//! Compile-free operators (scalar comparisons, SQLi/XSS detection, encoding
//! validators, byte-range) are evaluated directly. Operators that need compiled
//! per-transaction state (`@rx`, `@pm`, `@ipMatch`, …) return `.needs_runtime`;
//! the execution engine supplies those from pre-compiled workers rather than
//! recompiling a pattern on every value.

const std = @import("std");
const operators = @import("operators.zig");

pub const Outcome = union(enum) {
    /// The operator matched (`true`) or did not (`false`), before `!@op` negation.
    decided: bool,
    /// The operator needs compiled runtime state (regex/phrase/ip and friends).
    needs_runtime,
    /// The operator name is not recognized.
    unknown,
};

/// Evaluate a compile-free operator by name. `name` may carry a leading `@`;
/// `parameter` is the already macro-expanded operator argument; `input` is the
/// transformed variable value. Nothing is retained.
pub fn evaluate(name: []const u8, parameter: []const u8, input: []const u8, profile: operators.Profile) Outcome {
    const op = normalize(name);

    // Scalar comparison operators (eq/ge/gt/le/lt/beginsWith/…/streq/strmatch).
    if (operators.resolve(op)) |kind| {
        return .{ .decided = operators.evaluate(kind, profile, parameter, input) };
    }

    // Always-match / never-match operators (parameterless, like ModSecurity's
    // unconditional_match and no_match). `@unconditionalMatch` runs a rule's
    // actions on every request; `@noMatch` is inert unless negated (`!@noMatch`).
    if (eqName(op, "unconditionalMatch")) return .{ .decided = true };
    if (eqName(op, "noMatch")) return .{ .decided = false };

    if (eqName(op, "detectSQLi")) {
        var sqli: operators.SqlInjection = .{};
        return .{ .decided = sqli.evaluate(input).matched };
    }
    if (eqName(op, "detectXSS")) return .{ .decided = operators.detectXss(input) };
    if (eqName(op, "validateUtf8Encoding")) return .{ .decided = operators.validateUtf8Encoding(input) };
    if (eqName(op, "validateUrlEncoding")) return .{ .decided = operators.validateUrlEncoding(input) };
    if (eqName(op, "validateByteRange")) {
        const range = operators.ByteRangeOperator.compile(parameter) catch return .{ .decided = false };
        return .{ .decided = range.matches(input) };
    }

    // Operators that require compiled per-transaction workers.
    if (needsRuntime(op)) return .needs_runtime;

    return .unknown;
}

/// Apply `!@op` negation to a decided outcome; runtime/unknown pass through.
pub fn negate(outcome: Outcome, negated: bool) Outcome {
    return switch (outcome) {
        .decided => |value| .{ .decided = value != negated },
        else => outcome,
    };
}

fn normalize(name: []const u8) []const u8 {
    return if (name.len != 0 and name[0] == '@') name[1..] else name;
}

fn eqName(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn needsRuntime(op: []const u8) bool {
    const runtime = [_][]const u8{
        "rx",      "pm",              "pmf", "pmFromFile",
        "ipMatch", "ipMatchFromFile",
    };
    for (runtime) |name| {
        if (eqName(op, name)) return true;
    }
    return false;
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

fn decided(outcome: Outcome) bool {
    return switch (outcome) {
        .decided => |v| v,
        else => unreachable,
    };
}

test "scalar comparison operators dispatch by name" {
    try testing.expect(decided(evaluate("streq", "abc", "abc", .modsecurity)));
    try testing.expect(!decided(evaluate("@streq", "abc", "abd", .modsecurity)));
    try testing.expect(decided(evaluate("contains", "cd", "abcde", .modsecurity)));
    try testing.expect(decided(evaluate("beginsWith", "ab", "abcde", .modsecurity)));
    try testing.expect(decided(evaluate("@gt", "10", "20", .modsecurity)));
    try testing.expect(!decided(evaluate("gt", "20", "10", .modsecurity)));
}

test "unconditionalMatch always matches and noMatch never does" {
    try testing.expect(decided(evaluate("@unconditionalMatch", "", "", .modsecurity)));
    try testing.expect(decided(evaluate("unconditionalMatch", "ignored", "anything", .coraza)));
    try testing.expect(!decided(evaluate("@noMatch", "", "anything", .modsecurity)));
    // `!@noMatch` (negated) is the always-true idiom.
    try testing.expect(decided(negate(evaluate("noMatch", "", "x", .modsecurity), true)));
}

test "SQLi and XSS detection dispatch" {
    try testing.expect(decided(evaluate("@detectSQLi", "", "1' OR '1'='1", .modsecurity)));
    try testing.expect(!decided(evaluate("detectSQLi", "", "hello world", .modsecurity)));
    try testing.expect(decided(evaluate("@detectXSS", "", "<script>alert(1)</script>", .modsecurity)));
    try testing.expect(!decided(evaluate("detectXSS", "", "plain text", .modsecurity)));
}

test "encoding validators match invalid input" {
    // Valid UTF-8 / URL-encoding do not match; invalid ones do.
    try testing.expect(!decided(evaluate("validateUtf8Encoding", "", "hello", .modsecurity)));
    try testing.expect(decided(evaluate("@validateUtf8Encoding", "", "\xff\xfe", .modsecurity)));
    try testing.expect(!decided(evaluate("validateUrlEncoding", "", "%41%42", .modsecurity)));
    try testing.expect(decided(evaluate("@validateUrlEncoding", "", "%zz", .modsecurity)));
}

test "byte-range matches a byte outside the allowed set" {
    // Allow only printable ASCII 0x20-0x7e; a control byte matches.
    try testing.expect(!decided(evaluate("@validateByteRange", "32-126", "hello", .modsecurity)));
    try testing.expect(decided(evaluate("validateByteRange", "32-126", "hi\x00there", .modsecurity)));
}

test "compiling operators report needs_runtime; unknown reports unknown" {
    try testing.expectEqual(Outcome.needs_runtime, evaluate("@rx", "attack", "x", .modsecurity));
    try testing.expectEqual(Outcome.needs_runtime, evaluate("pm", "a b c", "x", .modsecurity));
    try testing.expectEqual(Outcome.needs_runtime, evaluate("@ipMatch", "10.0.0.0/8", "x", .modsecurity));
    try testing.expectEqual(Outcome.unknown, evaluate("@noSuchOperator", "", "x", .modsecurity));
}

test "negate flips a decided outcome only" {
    try testing.expect(decided(negate(.{ .decided = false }, true)));
    try testing.expect(!decided(negate(.{ .decided = true }, true)));
    try testing.expectEqual(Outcome.needs_runtime, negate(.needs_runtime, true));
}
