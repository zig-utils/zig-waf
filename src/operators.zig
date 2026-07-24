//! Native operator adapters and the stable scalar operator union.
//!
//! Adapters preserve dependency resource-limit and confidence metadata rather
//! than reducing every detector to a boolean. The scalar operators below are a
//! closed, typed union matching ModSecurity 3.0.16 and Coraza 3.7.0. Names
//! resolve case-insensitively while a ruleset is compiled; request-time
//! evaluation performs no string dispatch, allocation, or blocking I/O.

const std = @import("std");
const injection = @import("injection");

pub const SqlInjection = struct {
    state: injection.sqli.State = .{},

    pub const Match = struct {
        matched: bool,
        reason: injection.sqli.Reason,
        confidence: u8,
        fingerprint: [injection.sqli.fingerprint_capacity]u8,
        fingerprint_len: u8,
        inconclusive: bool,

        pub fn fingerprintBytes(self: *const Match) []const u8 {
            return self.fingerprint[0..self.fingerprint_len];
        }
    };

    /// Inspect one SecLang operator input without allocation.
    pub fn evaluate(self: *SqlInjection, input: []const u8) Match {
        const result = injection.sqli.detect(input, &self.state);
        return .{
            .matched = result.is_sqli,
            .reason = result.reason,
            .confidence = result.confidence,
            .fingerprint = result.fingerprint,
            .fingerprint_len = result.fingerprint_len,
            .inconclusive = result.truncated,
        };
    }
};

/// The observable byte semantics of an operator can differ between the two
/// pinned engines. Numeric parsing is the clearest example: ModSecurity uses a
/// prefix-tolerant `std::stoi`, while Coraza uses Go's whole-string
/// `strconv.Atoi`.
pub const Profile = enum {
    modsecurity,
    coraza,
};

/// Closed union of stable scalar operators owned by WAF-17. Regex operators
/// (`rx`, `rxGlobal`, `rsub`) and injection detectors (`detectSQLi`,
/// `detectXSS`) are compiled and evaluated through dedicated paths and are not
/// part of this allocation-free comparison dispatch.
pub const Kind = enum(u8) {
    eq,
    ge,
    gt,
    le,
    lt,
    begins_with,
    ends_with,
    contains,
    contains_word,
    within,
    str_eq,
    str_match,

    pub fn canonicalName(self: Kind) []const u8 {
        return specs[@backingInt(self)].name;
    }
};

pub const Spec = struct {
    kind: Kind,
    name: []const u8,
};

pub const specs = [_]Spec{
    .{ .kind = .eq, .name = "eq" },
    .{ .kind = .ge, .name = "ge" },
    .{ .kind = .gt, .name = "gt" },
    .{ .kind = .le, .name = "le" },
    .{ .kind = .lt, .name = "lt" },
    .{ .kind = .begins_with, .name = "beginsWith" },
    .{ .kind = .ends_with, .name = "endsWith" },
    .{ .kind = .contains, .name = "contains" },
    .{ .kind = .contains_word, .name = "containsWord" },
    .{ .kind = .within, .name = "within" },
    .{ .kind = .str_eq, .name = "streq" },
    .{ .kind = .str_match, .name = "strmatch" },
};

comptime {
    for (specs, 0..) |spec, index| {
        if (@backingInt(spec.kind) != index) @compileError("operator specs must follow enum order");
    }
}

/// Case-insensitive resolution of a canonical scalar operator name.
pub fn resolve(name: []const u8) ?Kind {
    for (specs) |spec| {
        if (std.ascii.eqlIgnoreCase(name, spec.name)) return spec.kind;
    }
    return null;
}

/// Evaluate one scalar operator against a borrowed input value. `parameter` is
/// the already macro-expanded operator argument and `input` is the transformed
/// variable value. Both are arbitrary byte strings; neither is retained. The
/// result is the raw operator outcome before rule negation.
pub fn evaluate(kind: Kind, profile: Profile, parameter: []const u8, input: []const u8) bool {
    return switch (kind) {
        .eq => parseInt(profile, parameter) == parseInt(profile, input),
        .ge => parseInt(profile, input) >= parseInt(profile, parameter),
        .gt => parseInt(profile, input) > parseInt(profile, parameter),
        .le => parseInt(profile, input) <= parseInt(profile, parameter),
        .lt => parseInt(profile, input) < parseInt(profile, parameter),
        .begins_with => std.mem.startsWith(u8, input, parameter),
        .ends_with => std.mem.endsWith(u8, input, parameter),
        .contains, .str_match => std.mem.indexOf(u8, input, parameter) != null,
        .within => std.mem.indexOf(u8, parameter, input) != null,
        .str_eq => std.mem.eql(u8, parameter, input),
        .contains_word => containsWord(input, parameter),
    };
}

/// Apply SecLang operator negation (`!@op`) to a raw operator outcome.
pub fn evaluateNegated(kind: Kind, profile: Profile, parameter: []const u8, input: []const u8, negated: bool) bool {
    return evaluate(kind, profile, parameter, input) != negated;
}

/// Integer parsing with the pinned per-engine semantics.
fn parseInt(profile: Profile, value: []const u8) i64 {
    return switch (profile) {
        .coraza => parseAtoiStrict(value),
        .modsecurity => parseStoiPrefix(value),
    };
}

/// Go `strconv.Atoi`: the entire string must be an optional sign followed by at
/// least one decimal digit. Any deviation, empty input, or 64-bit overflow
/// yields 0.
fn parseAtoiStrict(value: []const u8) i64 {
    if (value.len == 0) return 0;
    var index: usize = 0;
    var negative = false;
    if (value[0] == '+' or value[0] == '-') {
        negative = value[0] == '-';
        index = 1;
    }
    if (index == value.len) return 0;
    var magnitude: i64 = 0;
    while (index < value.len) : (index += 1) {
        const digit = value[index];
        if (digit < '0' or digit > '9') return 0;
        magnitude = std.math.mul(i64, magnitude, 10) catch return 0;
        magnitude = std.math.add(i64, magnitude, digit - '0') catch return 0;
    }
    return if (negative) -magnitude else magnitude;
}

/// C++ `std::stoi`: skip leading ASCII whitespace, take an optional sign and a
/// leading decimal-digit run, and stop at the first non-digit. No digits or a
/// value outside the 32-bit range yields 0.
fn parseStoiPrefix(value: []const u8) i64 {
    var index: usize = 0;
    while (index < value.len and std.ascii.isWhitespace(value[index])) index += 1;
    var negative = false;
    if (index < value.len and (value[index] == '+' or value[index] == '-')) {
        negative = value[index] == '-';
        index += 1;
    }
    var digits: usize = 0;
    var magnitude: i64 = 0;
    var overflow = false;
    while (index < value.len and value[index] >= '0' and value[index] <= '9') : (index += 1) {
        digits += 1;
        if (!overflow) {
            magnitude = magnitude * 10 + (value[index] - '0');
            const signed = if (negative) -magnitude else magnitude;
            if (signed > std.math.maxInt(i32) or signed < std.math.minInt(i32)) overflow = true;
        }
    }
    if (digits == 0 or overflow) return 0;
    return if (negative) -magnitude else magnitude;
}

/// ModSecurity `@containsWord`: `parameter` must appear delimited by non-letter
/// boundaries (start, end, or any byte outside `A-Za-z`, which notably includes
/// digits and punctuation). An empty parameter always matches; an empty input
/// with a non-empty parameter never matches.
fn containsWord(input: []const u8, parameter: []const u8) bool {
    if (parameter.len == 0) return true;
    if (input.len == 0) return false;
    if (std.mem.eql(u8, input, parameter)) return true;

    var start: usize = 0;
    while (std.mem.indexOfPos(u8, input, start, parameter)) |pos| {
        const end = pos + parameter.len;
        const left_ok = pos == 0 or !isWordByte(input[pos - 1]);
        const right_ok = end == input.len or !isWordByte(input[end]);
        // A start-anchored match still requires a non-letter on the right, and
        // an end-anchored match a non-letter on the left, matching the pinned
        // boundary checks where the out-of-range neighbor is not acceptable.
        if (pos == 0) {
            if (end != input.len and !isWordByte(input[end])) return true;
        } else if (end == input.len) {
            if (!isWordByte(input[pos - 1])) return true;
        } else if (left_ok and right_ok) {
            return true;
        }
        start = pos + 1;
    }
    return false;
}

fn isWordByte(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or (byte >= 'a' and byte <= 'z');
}

test "SQL injection adapter preserves detector evidence" {
    var operator: SqlInjection = .{};
    const result = operator.evaluate("1 UNION SELECT password FROM users");
    try std.testing.expect(result.matched);
    try std.testing.expectEqual(injection.sqli.Reason.union_select, result.reason);
    try std.testing.expectEqualStrings("1U", result.fingerprintBytes()[0..2]);
    try std.testing.expect(!result.inconclusive);
}

test "SQL injection adapter remains reusable for benign input" {
    var operator: SqlInjection = .{};
    _ = operator.evaluate("1 OR 1=1");
    const benign = operator.evaluate("alice@example.com");
    try std.testing.expect(!benign.matched);
    try std.testing.expectEqual(injection.sqli.Reason.none, benign.reason);
}

test "scalar operator union resolves canonically and case-insensitively" {
    try std.testing.expectEqual(@as(usize, 12), specs.len);
    for (specs) |spec| {
        try std.testing.expectEqual(spec.kind, resolve(spec.name).?);
        const upper = try std.ascii.allocUpperString(std.testing.allocator, spec.name);
        defer std.testing.allocator.free(upper);
        try std.testing.expectEqual(spec.kind, resolve(upper).?);
        try std.testing.expectEqualStrings(spec.name, spec.kind.canonicalName());
    }
    try std.testing.expect(resolve("notAnOperator") == null);
}

test "numeric operators match pinned Coraza strconv.Atoi semantics" {
    const p = Profile.coraza;
    // Both non-numeric inputs collapse to 0 and compare equal.
    try std.testing.expect(evaluate(.eq, p, "0", ""));
    try std.testing.expect(!evaluate(.eq, p, "5", ""));
    try std.testing.expect(evaluate(.eq, p, "xxx", "0"));
    try std.testing.expect(!evaluate(.eq, p, "xxx", "5"));
    try std.testing.expect(evaluate(.eq, p, "5", "5"));
    // Leading whitespace is not a valid Go integer, so it parses to 0.
    try std.testing.expect(evaluate(.eq, p, "0", " 5"));
    try std.testing.expect(evaluate(.ge, p, "5", "10"));
    try std.testing.expect(evaluate(.gt, p, "5", "10"));
    try std.testing.expect(!evaluate(.gt, p, "10", "5"));
    try std.testing.expect(evaluate(.le, p, "5", "5"));
    try std.testing.expect(evaluate(.lt, p, "5", "-1"));
}

test "numeric operators match pinned ModSecurity std::stoi prefix semantics" {
    const p = Profile.modsecurity;
    // std::stoi skips leading whitespace and parses a digit prefix.
    try std.testing.expect(evaluate(.eq, p, "5", " 5"));
    try std.testing.expect(evaluate(.eq, p, "5", "5abc"));
    try std.testing.expect(evaluate(.eq, p, "0", "abc"));
    try std.testing.expect(evaluate(.gt, p, "5", "10x"));
}

test "string operators match pinned substring and prefix semantics" {
    const p = Profile.coraza;
    try std.testing.expect(evaluate(.begins_with, p, "abc", "abcdef"));
    try std.testing.expect(!evaluate(.begins_with, p, "bcd", "abcdef"));
    try std.testing.expect(evaluate(.ends_with, p, "def", "abcdef"));
    try std.testing.expect(evaluate(.contains, p, "cd", "abcdef"));
    try std.testing.expect(evaluate(.str_match, p, "cd", "abcdef"));
    try std.testing.expect(evaluate(.within, p, "abcdef", "cd"));
    try std.testing.expect(!evaluate(.within, p, "cd", "abcdef"));
    try std.testing.expect(evaluate(.str_eq, p, "abc", "abc"));
    try std.testing.expect(!evaluate(.str_eq, p, "abc", "abcd"));
    // Empty parameter is a prefix, suffix, and substring of everything.
    try std.testing.expect(evaluate(.begins_with, p, "", "abc"));
    try std.testing.expect(evaluate(.contains, p, "", "abc"));
}

test "containsWord requires non-letter word boundaries" {
    const p = Profile.modsecurity;
    // Empty parameter always matches; empty input with a parameter never does.
    try std.testing.expect(evaluate(.contains_word, p, "", ""));
    try std.testing.expect(evaluate(.contains_word, p, "", "TestCase"));
    try std.testing.expect(!evaluate(.contains_word, p, "TestCase", ""));
    // Substrings bounded by letters are not words.
    try std.testing.expect(!evaluate(.contains_word, p, "abc", "abcdefghi"));
    try std.testing.expect(!evaluate(.contains_word, p, "def", "abcdefghi"));
    // Exact match and non-letter boundaries are words.
    try std.testing.expect(evaluate(.contains_word, p, "abc", "abc"));
    try std.testing.expect(evaluate(.contains_word, p, "abc", "abc def"));
    try std.testing.expect(evaluate(.contains_word, p, "def", "abc def ghi"));
    try std.testing.expect(evaluate(.contains_word, p, "ghi", "abc ghi"));
    // Digits are boundaries, not word bytes.
    try std.testing.expect(evaluate(.contains_word, p, "abc", "abc123"));
}

test "operator negation flips the raw outcome" {
    const p = Profile.coraza;
    try std.testing.expect(!evaluateNegated(.str_eq, p, "abc", "abc", true));
    try std.testing.expect(evaluateNegated(.str_eq, p, "abc", "xyz", true));
    try std.testing.expect(evaluateNegated(.str_eq, p, "abc", "abc", false));
}
