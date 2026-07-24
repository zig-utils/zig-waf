//! Reusable deterministic operator oracle. Scalar operators must never crash
//! and must satisfy the negation and determinism identities; the regex operator
//! must agree between a plain worker, a memo miss, and a memo hit, and must not
//! leak under bounded evaluation.

const std = @import("std");
const operators = @import("operators.zig");

pub fn fuzzOne(allocator: std.mem.Allocator, input: []const u8) !void {
    const mid = input.len / 2;
    const parameter = input[0..mid];
    const value = input[mid..];

    inline for (.{ operators.Profile.modsecurity, operators.Profile.coraza }) |profile| {
        for (operators.specs) |spec| {
            const raw = operators.evaluate(spec.kind, profile, parameter, value);
            // Evaluation is pure, so a repeat must return the same result.
            if (operators.evaluate(spec.kind, profile, parameter, value) != raw)
                return error.OperatorNonDeterministic;
            // Negation is the exact inverse of the raw outcome.
            if (operators.evaluateNegated(spec.kind, profile, parameter, value, true) != !raw)
                return error.OperatorNegationInconsistent;
            if (operators.evaluateNegated(spec.kind, profile, parameter, value, false) != raw)
                return error.OperatorNegationInconsistent;
        }
    }

    // A fixed, always-valid pattern exercises capture extraction and the memo.
    var operator = operators.RegexOperator.compile(allocator, "([a-z0-9]+)[=:]([^&]*)") catch return;
    defer operator.deinit();

    var plain = operator.worker();
    defer plain.deinit();
    var memo = operator.workerWithMemo(allocator, .{});
    defer memo.deinit();

    const fresh = plain.evaluate(value);
    const miss = memo.evaluate(value);
    const hit = memo.evaluate(value);
    if (fresh.matched != miss.matched or miss.matched != hit.matched)
        return error.RegexMemoInconsistent;
    if (fresh.capture_count != miss.capture_count or miss.capture_count != hit.capture_count)
        return error.RegexMemoInconsistent;
    var field: usize = 0;
    while (field < fresh.capture_count) : (field += 1) {
        if (!std.mem.eql(u8, fresh.captures[field], hit.captures[field]))
            return error.RegexMemoInconsistent;
    }

    const global = memo.evaluateGlobal(allocator, value);
    std.mem.doNotOptimizeAway(global.match_count);

    // Aho-Corasick phrase matching must not crash and must stay deterministic.
    var pm = try operators.PhraseOperator.compile(allocator, parameter, .{});
    defer pm.deinit();
    const pm_hit = pm.matches(value);
    if (pm.matches(value) != pm_hit) return error.PhraseNonDeterministic;
    var pm_iter = pm.iterator(value);
    var previous_end: usize = 0;
    while (pm_iter.next()) |m| {
        // Matches are within bounds and advance monotonically.
        if (m.end > value.len or m.start > m.end or m.start < previous_end) return error.PhraseIteratorInvalid;
        previous_end = m.end;
    }

    // IP subnet matching must not crash and must stay deterministic.
    var ip = try operators.compileIpMatch(allocator, parameter, .{});
    defer ip.deinit();
    const ip_hit = ip.matches(value);
    if (ip.matches(value) != ip_hit) return error.IpMatchNonDeterministic;
}

const structured_seed = "id=42&name=alice:token=SELECT../a=b 0x41&&user:admin==";
const marker_alphabet = "=:&+-_.*/ 0123456789abcdefABCDEFghijkl";

fn deriveInput(buffer: []u8, random: std.Random, iteration: usize) []const u8 {
    const length = random.uintLessThan(usize, buffer.len + 1);
    const input = buffer[0..length];
    switch (iteration % 4) {
        0 => random.bytes(input),
        1 => for (input) |*byte| {
            byte.* = marker_alphabet[random.uintLessThan(usize, marker_alphabet.len)];
        },
        2 => for (input, 0..) |*byte, index| {
            byte.* = structured_seed[index % structured_seed.len];
            if (random.uintLessThan(u8, 32) == 0) byte.* = random.int(u8);
        },
        3 => for (input, 0..) |*byte, index| {
            byte.* = @truncate(index);
        },
        else => unreachable,
    }
    return input;
}

pub fn fuzzDeterministic(allocator: std.mem.Allocator, iterations: usize, seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var buffer: [512]u8 = undefined;
    for (0..iterations) |iteration| {
        try fuzzOne(allocator, deriveInput(&buffer, random, iteration));
    }
}

test "operator fuzz oracle holds over deterministic corpus" {
    try fuzzDeterministic(std.testing.allocator, 2000, 0x9e3779b97f4a7c15);
}
