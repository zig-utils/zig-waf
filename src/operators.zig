//! Native operator adapters. Adapters preserve dependency resource-limit and
//! confidence metadata rather than reducing every detector to a boolean.

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
