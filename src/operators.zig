//! Native operator adapters and the stable scalar operator union.
//!
//! Adapters preserve dependency resource-limit and confidence metadata rather
//! than reducing every detector to a boolean. The scalar operators below are a
//! closed, typed union matching ModSecurity 3.0.16 and Coraza 3.7.0. Names
//! resolve case-insensitively while a ruleset is compiled; request-time
//! evaluation performs no string dispatch, allocation, or blocking I/O.

const std = @import("std");
const injection = @import("injection");
const regex = @import("regex");

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

/// Compile-time errors for a regex operator. These are distinguishable so a
/// ruleset with an invalid or over-complex pattern is rejected before
/// publication instead of failing silently at request time.
pub const RegexCompileError = error{
    InvalidRegexPattern,
    RegexProgramTooComplex,
    OutOfMemory,
};

/// The largest capture field index ModSecurity and Coraza expose. Field 0 is
/// the full match; fields 1..9 are the first nine parenthesized groups.
pub const max_capture_fields = 10;

/// The outcome of one regex evaluation. A bounded runtime error (match-limit,
/// step-limit, oversized input) is not a match; it is reported through
/// `runtime_error`/`limit_exceeded` exactly as ModSecurity sets
/// `TX.MSC_PCRE_ERROR` and `TX.MSC_PCRE_LIMITS_EXCEEDED` and does not match.
pub const RegexOutcome = struct {
    matched: bool = false,
    runtime_error: bool = false,
    limit_exceeded: bool = false,
    /// Number of populated capture fields (0 when unmatched).
    capture_count: u8 = 0,
    /// Global match count; equals 1 for a plain `rx` match.
    match_count: u32 = 0,
    /// Capture fields borrow the evaluated input and are valid only while it is.
    captures: [max_capture_fields][]const u8 = @splat(""),
    /// Whether each capture field participated in the match; a non-participating
    /// optional group is distinct from one that matched the empty string.
    captures_present: [max_capture_fields]bool = @splat(false),
};

/// A ruleset-owned compiled regex operator (`@rx` / `@rxGlobal`). The compiled
/// program is immutable and may be shared by request workers; create one
/// reusable `Worker` per worker thread so mutable matcher caches are never
/// shared. An empty pattern always matches, mirroring the pinned engines.
pub const RegexOperator = struct {
    compiled: ?regex.Regex,

    pub fn compile(allocator: std.mem.Allocator, pattern: []const u8) RegexCompileError!RegexOperator {
        return compileWithFlags(allocator, pattern, .{});
    }

    pub fn compileWithFlags(allocator: std.mem.Allocator, pattern: []const u8, flags: regex.common.CompileFlags) RegexCompileError!RegexOperator {
        if (pattern.len == 0) return .{ .compiled = null };
        const compiled = regex.Regex.compileWithFlags(allocator, pattern, flags) catch |err| {
            const widened: anyerror = err;
            return switch (widened) {
                error.OutOfMemory => error.OutOfMemory,
                error.TooManyStates,
                error.TooManyCaptures,
                error.TooManyAlternations,
                error.PatternTooComplex,
                error.NestingTooDeep,
                error.StackOverflow,
                => error.RegexProgramTooComplex,
                else => error.InvalidRegexPattern,
            };
        };
        return .{ .compiled = compiled };
    }

    pub fn deinit(self: *RegexOperator) void {
        if (self.compiled) |*compiled| compiled.deinit();
        self.* = undefined;
    }

    pub fn worker(self: *const RegexOperator) Worker {
        return .{ .matcher = if (self.compiled) |*compiled| compiled.matcher() else null };
    }

    /// A memoizing worker keeps a bounded per-worker LRU of recent `@rx`
    /// outcomes keyed by exact input bytes. It is optional; the plain `worker`
    /// still amortizes the lazy DFA/NFA construction across evaluations.
    pub fn workerWithMemo(self: *const RegexOperator, allocator: std.mem.Allocator, limits: MemoLimits) Worker {
        var w = self.worker();
        w.memo = Memo{ .allocator = allocator, .limits = limits };
        return w;
    }

    pub const MemoLimits = struct {
        /// Maximum cached distinct inputs before least-recent eviction.
        max_entries: usize = 64,
        /// Inputs longer than this are evaluated without being cached.
        max_input_bytes: usize = 4096,
    };

    pub const MemoStats = struct {
        entries: usize = 0,
        hits: u64 = 0,
        misses: u64 = 0,
        evictions: u64 = 0,
    };

    const MemoEntry = struct {
        input: []u8,
        matched: bool,
        runtime_error: bool,
        limit_exceeded: bool,
        match_count: u32,
        capture_count: u8,
        spans: [max_capture_fields][2]usize,
        present: [max_capture_fields]bool,
        last_used: u64,
    };

    const Memo = struct {
        allocator: std.mem.Allocator,
        limits: MemoLimits,
        entries: std.ArrayList(MemoEntry) = .empty,
        clock: u64 = 0,
        hits: u64 = 0,
        misses: u64 = 0,
        evictions: u64 = 0,

        fn deinit(self: *Memo) void {
            for (self.entries.items) |entry| self.allocator.free(entry.input);
            self.entries.deinit(self.allocator);
        }

        fn find(self: *Memo, input: []const u8) ?*MemoEntry {
            for (self.entries.items) |*entry| {
                if (std.mem.eql(u8, entry.input, input)) return entry;
            }
            return null;
        }
    };

    pub const Worker = struct {
        matcher: ?regex.Regex.Matcher,
        memo: ?Memo = null,

        pub fn deinit(self: *Worker) void {
            if (self.matcher) |*m| m.deinit();
            if (self.memo) |*memo| memo.deinit();
            self.* = undefined;
        }

        pub fn memoStats(self: *const Worker) MemoStats {
            if (self.memo) |memo| return .{
                .entries = memo.entries.items.len,
                .hits = memo.hits,
                .misses = memo.misses,
                .evictions = memo.evictions,
            };
            return .{};
        }

        /// `@rx`: the leftmost match with capture fields 0..9. When a memo is
        /// enabled, an exact repeat input is served from the cache and its
        /// capture fields are rebuilt against the live input.
        pub fn evaluate(self: *Worker, input: []const u8) RegexOutcome {
            if (self.memo != null and input.len <= self.memo.?.limits.max_input_bytes) {
                const memo = &self.memo.?;
                memo.clock += 1;
                if (memo.find(input)) |entry| {
                    memo.hits += 1;
                    entry.last_used = memo.clock;
                    return rebuildFromEntry(entry.*, input);
                }
                memo.misses += 1;
                const outcome = self.evaluateUncached(input);
                storeMemoEntry(memo, input, outcome) catch {};
                return outcome;
            }
            return self.evaluateUncached(input);
        }

        fn evaluateUncached(self: *Worker, input: []const u8) RegexOutcome {
            if (self.matcher == null) return regexAlwaysMatch();
            const matcher = &self.matcher.?;
            var match = (matcher.find(input) catch |err| return regexRuntimeFailure(err)) orelse return .{};
            defer match.deinit(matcher.re.allocator);
            var outcome = RegexOutcome{ .matched = true, .match_count = 1 };
            regexFillCaptures(&outcome, match);
            return outcome;
        }

        /// `@rxGlobal`: every non-overlapping match. Capture fields keep the
        /// first value per field index, matching ModSecurity `storeOrUpdateFirst`.
        /// Global evaluation is not memoized.
        pub fn evaluateGlobal(self: *Worker, allocator: std.mem.Allocator, input: []const u8) RegexOutcome {
            if (self.matcher == null) return regexAlwaysMatch();
            const matcher = &self.matcher.?;
            const matches = matcher.findAll(allocator, input) catch |err| return regexRuntimeFailure(err);
            defer {
                for (matches) |*match| match.deinit(matcher.re.allocator);
                allocator.free(matches);
            }
            if (matches.len == 0) return .{};
            var outcome = RegexOutcome{ .matched = true, .match_count = @intCast(matches.len) };
            regexFillCaptures(&outcome, matches[0]);
            return outcome;
        }
    };
};

/// Rebuild a memoized outcome's capture fields against the live input using the
/// stored byte offsets. The cached and live inputs are byte-equal on a hit, so
/// the offsets address identical bytes.
fn rebuildFromEntry(entry: RegexOperator.MemoEntry, input: []const u8) RegexOutcome {
    var outcome = RegexOutcome{
        .matched = entry.matched,
        .runtime_error = entry.runtime_error,
        .limit_exceeded = entry.limit_exceeded,
        .match_count = entry.match_count,
        .capture_count = entry.capture_count,
    };
    var field: usize = 0;
    while (field < entry.capture_count) : (field += 1) {
        outcome.captures_present[field] = entry.present[field];
        const span = entry.spans[field];
        outcome.captures[field] = if (span[1] != 0 and span[0] + span[1] <= input.len)
            input[span[0] .. span[0] + span[1]]
        else
            "";
    }
    return outcome;
}

fn storeMemoEntry(memo: *RegexOperator.Memo, input: []const u8, outcome: RegexOutcome) !void {
    // Evict the least-recently-used entry when the bound is reached.
    if (memo.entries.items.len >= memo.limits.max_entries) {
        var victim: usize = 0;
        for (memo.entries.items, 0..) |entry, index| {
            if (entry.last_used < memo.entries.items[victim].last_used) victim = index;
        }
        memo.allocator.free(memo.entries.items[victim].input);
        _ = memo.entries.swapRemove(victim);
        memo.evictions += 1;
    }
    const owned = try memo.allocator.dupe(u8, input);
    errdefer memo.allocator.free(owned);

    var entry = RegexOperator.MemoEntry{
        .input = owned,
        .matched = outcome.matched,
        .runtime_error = outcome.runtime_error,
        .limit_exceeded = outcome.limit_exceeded,
        .match_count = outcome.match_count,
        .capture_count = outcome.capture_count,
        .spans = @splat(.{ 0, 0 }),
        .present = outcome.captures_present,
        .last_used = memo.clock,
    };
    var field: usize = 0;
    while (field < outcome.capture_count) : (field += 1) {
        const capture = outcome.captures[field];
        if (capture.len != 0 and
            @intFromPtr(capture.ptr) >= @intFromPtr(input.ptr) and
            @intFromPtr(capture.ptr) + capture.len <= @intFromPtr(input.ptr) + input.len)
        {
            entry.spans[field] = .{ @intFromPtr(capture.ptr) - @intFromPtr(input.ptr), capture.len };
        }
    }
    try memo.entries.append(memo.allocator, entry);
}

fn regexAlwaysMatch() RegexOutcome {
    var present: [max_capture_fields]bool = @splat(false);
    present[0] = true;
    return .{ .matched = true, .match_count = 1, .capture_count = 1, .captures_present = present };
}

fn regexFillCaptures(outcome: *RegexOutcome, match: regex.Match) void {
    outcome.captures[0] = match.slice;
    outcome.captures_present[0] = true;
    var count: u8 = 1;
    for (match.captures, 0..) |group, index| {
        if (count == max_capture_fields) break;
        outcome.captures[count] = group;
        outcome.captures_present[count] = if (index < match.captures_present.len)
            match.captures_present[index]
        else
            true;
        count += 1;
    }
    outcome.capture_count = count;
}

fn regexRuntimeFailure(err: anyerror) RegexOutcome {
    return switch (err) {
        error.Timeout, error.InputTooLong, error.DfaOverflow => .{ .runtime_error = true, .limit_exceeded = true },
        else => .{ .runtime_error = true },
    };
}

/// ModSecurity 3.0.16 leaves `@rsub` unimplemented: `Rsub::evaluate` is a
/// documented stub that returns true. zig-waf preserves that exact pinned
/// behavior rather than inventing substitution semantics the baseline lacks.
/// Actual regex substitution is out of scope until upstream implements it.
pub fn rsub(_: []const u8, _: []const u8) bool {
    return true;
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

test "rx operator matches and extracts capture fields 0..9" {
    var operator = try RegexOperator.compile(std.testing.allocator, "id=([0-9]+)&name=([a-z]+)");
    defer operator.deinit();
    var worker = operator.worker();
    defer worker.deinit();

    const hit = worker.evaluate("path?id=42&name=alice#frag");
    try std.testing.expect(hit.matched);
    try std.testing.expect(!hit.runtime_error);
    try std.testing.expectEqual(@as(u32, 1), hit.match_count);
    try std.testing.expectEqual(@as(u8, 3), hit.capture_count);
    try std.testing.expectEqualStrings("id=42&name=alice", hit.captures[0]);
    try std.testing.expectEqualStrings("42", hit.captures[1]);
    try std.testing.expectEqualStrings("alice", hit.captures[2]);
    try std.testing.expect(hit.captures_present[0]);
    try std.testing.expect(hit.captures_present[1]);

    const miss = worker.evaluate("no identifiers here");
    try std.testing.expect(!miss.matched);
    try std.testing.expectEqual(@as(u8, 0), miss.capture_count);
}

test "rx capture fields borrow the evaluated input" {
    var operator = try RegexOperator.compile(std.testing.allocator, "(a+)(b+)");
    defer operator.deinit();
    var worker = operator.worker();
    defer worker.deinit();

    const input = "xxaaabbyy";
    const outcome = worker.evaluate(input);
    try std.testing.expect(outcome.matched);
    // Full match and each group are slices into the original input.
    try std.testing.expectEqualStrings("aaabb", outcome.captures[0]);
    try std.testing.expect(outcome.captures[0].ptr == input.ptr + 2);
    try std.testing.expectEqualStrings("aaa", outcome.captures[1]);
    try std.testing.expectEqualStrings("bb", outcome.captures[2]);
}

test "empty rx pattern always matches like the pinned engines" {
    var operator = try RegexOperator.compile(std.testing.allocator, "");
    defer operator.deinit();
    var worker = operator.worker();
    defer worker.deinit();

    const outcome = worker.evaluate("anything at all");
    try std.testing.expect(outcome.matched);
    try std.testing.expectEqual(@as(u8, 1), outcome.capture_count);
    try std.testing.expect(outcome.captures_present[0]);
}

test "invalid rx pattern is a distinguishable compile error" {
    try std.testing.expectError(error.InvalidRegexPattern, RegexOperator.compile(std.testing.allocator, "(unterminated"));
}

test "rxGlobal counts every non-overlapping match and keeps first captures" {
    var operator = try RegexOperator.compile(std.testing.allocator, "([0-9]+)");
    defer operator.deinit();
    var worker = operator.worker();
    defer worker.deinit();

    const outcome = worker.evaluateGlobal(std.testing.allocator, "a1bb22ccc333");
    try std.testing.expect(outcome.matched);
    try std.testing.expectEqual(@as(u32, 3), outcome.match_count);
    // First-wins per field index, matching ModSecurity storeOrUpdateFirst.
    try std.testing.expectEqualStrings("1", outcome.captures[0]);
    try std.testing.expectEqualStrings("1", outcome.captures[1]);

    const miss = worker.evaluateGlobal(std.testing.allocator, "no digits");
    try std.testing.expect(!miss.matched);
    try std.testing.expectEqual(@as(u32, 0), miss.match_count);
}

test "rsub preserves the pinned ModSecurity 3.0.16 always-true stub" {
    try std.testing.expect(rsub("s/foo/bar/", "any input"));
    try std.testing.expect(rsub("", ""));
}

test "case-insensitive rx flag folds ASCII case" {
    var operator = try RegexOperator.compileWithFlags(std.testing.allocator, "select", .{ .case_insensitive = true });
    defer operator.deinit();
    var worker = operator.worker();
    defer worker.deinit();
    try std.testing.expect(worker.evaluate("UNION SELECT 1").matched);
    try std.testing.expect(!worker.evaluate("no keyword").matched);
}

test "rx memoization serves repeat inputs and rebuilds captures from the live input" {
    var operator = try RegexOperator.compile(std.testing.allocator, "id=([0-9]+)");
    defer operator.deinit();
    var worker = operator.workerWithMemo(std.testing.allocator, .{});
    defer worker.deinit();

    const first = worker.evaluate("id=42");
    try std.testing.expect(first.matched);
    try std.testing.expectEqualStrings("42", first.captures[1]);
    try std.testing.expectEqual(@as(u64, 0), worker.memoStats().hits);
    try std.testing.expectEqual(@as(u64, 1), worker.memoStats().misses);

    // A distinct buffer with identical bytes must hit the cache and rebuild the
    // capture field to point into this new buffer, not the cached copy.
    var live = [_]u8{ 'i', 'd', '=', '4', '2' };
    const second = worker.evaluate(&live);
    try std.testing.expect(second.matched);
    try std.testing.expectEqualStrings("42", second.captures[1]);
    try std.testing.expect(second.captures[1].ptr == live[3..].ptr);
    try std.testing.expectEqual(@as(u64, 1), worker.memoStats().hits);

    const miss = worker.evaluate("no match here");
    try std.testing.expect(!miss.matched);
    try std.testing.expectEqual(@as(u64, 2), worker.memoStats().misses);
}

test "rx memoization bounds entries with least-recently-used eviction" {
    var operator = try RegexOperator.compile(std.testing.allocator, "[a-z]+");
    defer operator.deinit();
    var worker = operator.workerWithMemo(std.testing.allocator, .{ .max_entries = 2 });
    defer worker.deinit();

    _ = worker.evaluate("alpha");
    _ = worker.evaluate("bravo");
    try std.testing.expectEqual(@as(usize, 2), worker.memoStats().entries);
    // A third distinct input evicts the least-recently-used entry.
    _ = worker.evaluate("charlie");
    try std.testing.expectEqual(@as(usize, 2), worker.memoStats().entries);
    try std.testing.expectEqual(@as(u64, 1), worker.memoStats().evictions);
}
