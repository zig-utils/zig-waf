//! A compiled operator, ready to evaluate against many values.
//!
//! `rule_eval` handles the compile-free operators as a pure function; this layer
//! adds the ones that must compile state once and reuse it — `@rx` (regex),
//! `@pm` (phrase/Aho-Corasick), and `@ipMatch` (CIDR set) — so the rule-execution
//! loop compiles each rule's operator once per plan and evaluates it per
//! target-value without recompiling. Compile-free operators are kept as borrowed
//! name/parameter slices and dispatched through `rule_eval`.

const std = @import("std");
const operators = @import("operators.zig");
const rule_eval = @import("rule_eval.zig");

pub const CompileError = anyerror;

pub const RuntimeOperator = union(enum) {
    /// name and parameter borrowed from the plan's string table (caller keeps
    /// them alive); evaluated through `rule_eval`.
    compile_free: struct { name: []const u8, parameter: []const u8 },
    regex: operators.RegexOperator,
    phrase: operators.PhraseOperator,
    ip: operators.IpMatcher,

    /// Compile an operator by name. `@rx`/`@pm`/`@ipMatch` build reusable state;
    /// every other operator is stored as a borrowed name/parameter pair.
    pub fn compile(allocator: std.mem.Allocator, name: []const u8, parameter: []const u8) CompileError!RuntimeOperator {
        const op = normalize(name);
        if (eqName(op, "rx")) return .{ .regex = try operators.RegexOperator.compile(allocator, parameter) };
        if (eqName(op, "pm")) {
            return .{ .phrase = try operators.PhraseOperator.compile(allocator, parameter, .{}) };
        }
        // For `@pmFromFile` the compiler has already replaced the filename with
        // the file's bytes, and for `@pmFromDataset` the dataset's entries, so
        // `parameter` is a newline-delimited keyword list either way.
        if (eqName(op, "pmf") or eqName(op, "pmFromFile") or eqName(op, "pmFromDataset")) {
            return .{ .phrase = try operators.PhraseOperator.compileFromFileBytes(allocator, parameter, .{}) };
        }
        if (eqName(op, "ipMatch")) {
            return .{ .ip = try operators.compileIpMatch(allocator, parameter, .{}) };
        }
        // Likewise `parameter` here is the subnet-per-line contents of the file or
        // the dataset.
        if (eqName(op, "ipMatchFromFile") or eqName(op, "ipMatchF") or eqName(op, "ipMatchFromDataset")) {
            return .{ .ip = try operators.compileIpMatchFromFileBytes(allocator, parameter, .{}) };
        }
        return .{ .compile_free = .{ .name = name, .parameter = parameter } };
    }

    pub fn deinit(self: *RuntimeOperator) void {
        switch (self.*) {
            .regex => |*re| re.deinit(),
            .phrase => |*p| p.deinit(),
            .ip => |*ip| ip.deinit(),
            .compile_free => {},
        }
        self.* = undefined;
    }

    /// Evaluate the operator against `input` (before rule negation). For `@rx`
    /// this spawns a lightweight per-call worker over the shared compiled
    /// program; the execution loop may instead hold a per-transaction worker for
    /// hot paths. An unrecognized compile-free operator evaluates to false.
    pub fn evaluate(self: *const RuntimeOperator, input: []const u8, profile: operators.Profile) bool {
        return self.match(input, profile).matched;
    }

    /// One operator match: whether it matched, plus the regex capture outcome
    /// (`@rx` only) so the caller can populate TX.0..TX.N when the rule captures.
    /// Capture strings borrow `input` and are valid only while it is.
    pub const Match = struct {
        matched: bool,
        regex: ?operators.RegexOutcome = null,
    };

    pub fn match(self: *const RuntimeOperator, input: []const u8, profile: operators.Profile) Match {
        switch (self.*) {
            .compile_free => |cf| return .{ .matched = switch (rule_eval.evaluate(cf.name, cf.parameter, input, profile)) {
                .decided => |value| value,
                else => false,
            } },
            .regex => |*re| {
                var worker = re.worker();
                defer worker.deinit();
                const outcome = worker.evaluate(input);
                return .{ .matched = outcome.matched, .regex = outcome };
            },
            .phrase => |*p| return .{ .matched = p.matches(input) },
            .ip => |*ip| return .{ .matched = ip.matches(input) },
        }
    }
};

fn normalize(name: []const u8) []const u8 {
    return if (name.len != 0 and name[0] == '@') name[1..] else name;
}

fn eqName(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

test "a compile-free operator routes through rule_eval" {
    var op = try RuntimeOperator.compile(testing.allocator, "@streq", "abc");
    defer op.deinit();
    try testing.expect(op.evaluate("abc", .modsecurity));
    try testing.expect(!op.evaluate("abd", .modsecurity));
}

test "a regex operator compiles once and evaluates many values" {
    var op = try RuntimeOperator.compile(testing.allocator, "@rx", "a[0-9]+z");
    defer op.deinit();
    try testing.expect(op.evaluate("xx a123z yy", .modsecurity));
    try testing.expect(!op.evaluate("abz", .modsecurity));
    try testing.expect(op.evaluate("a7z", .modsecurity));
}

test "a phrase operator matches any of its needles" {
    var op = try RuntimeOperator.compile(testing.allocator, "@pm", "evil attack malware");
    defer op.deinit();
    try testing.expect(op.evaluate("this is an attack", .modsecurity));
    try testing.expect(!op.evaluate("perfectly benign", .modsecurity));
}

test "an ipMatch operator matches inside its CIDR set" {
    var op = try RuntimeOperator.compile(testing.allocator, "@ipMatch", "10.0.0.0/8, 192.168.1.5");
    defer op.deinit();
    try testing.expect(op.evaluate("10.4.5.6", .modsecurity));
    try testing.expect(op.evaluate("192.168.1.5", .modsecurity));
    try testing.expect(!op.evaluate("8.8.8.8", .modsecurity));
}

test "detectSQLi routes through the compile-free path" {
    var op = try RuntimeOperator.compile(testing.allocator, "@detectSQLi", "");
    defer op.deinit();
    try testing.expect(op.evaluate("1' OR '1'='1", .modsecurity));
    try testing.expect(!op.evaluate("just text", .modsecurity));
}

test "random operators, patterns, and inputs never crash or leak" {
    var prng = std.Random.DefaultPrng.init(0x0FEED_0BEC_2210);
    const random = prng.random();
    const names = [_][]const u8{
        "@rx",         "@pm",              "@ipMatch",   "@streq",             "@contains",
        "@beginsWith", "@detectSQLi",      "@detectXSS", "@validateByteRange", "@unknownOp",
        // The from-file operators compile through the newline-delimited
        // compileFromFileBytes / compileIpMatchFromFileBytes paths (the compiler
        // substitutes file bytes for the filename), so feed them arbitrary bytes.
        "@pmFromFile", "@ipMatchFromFile", "@pmf",       "@ipMatchF",
    };
    var pattern_buf: [64]u8 = undefined;
    var input_buf: [128]u8 = undefined;
    var iteration: usize = 0;
    while (iteration < 4000) : (iteration += 1) {
        const name = names[random.uintLessThan(usize, names.len)];
        const pattern_len = random.uintLessThan(usize, pattern_buf.len + 1);
        for (pattern_buf[0..pattern_len]) |*byte| {
            // Bias toward regex/CIDR metacharacters so compilation is exercised.
            byte.* = switch (random.uintLessThan(u8, 8)) {
                0 => '(',
                1 => ')',
                2 => '[',
                3 => '*',
                4 => '.',
                5 => '/',
                else => random.int(u8),
            };
        }
        const input_len = random.uintLessThan(usize, input_buf.len + 1);
        random.bytes(input_buf[0..input_len]);

        // Compilation may fail on a malformed pattern; that must be a clean error,
        // never a crash or leak. Evaluation of a compiled operator must not crash.
        var op = RuntimeOperator.compile(testing.allocator, name, pattern_buf[0..pattern_len]) catch continue;
        defer op.deinit();
        _ = op.evaluate(input_buf[0..input_len], .modsecurity);
        _ = op.match(input_buf[0..input_len], .coraza);
    }
}
