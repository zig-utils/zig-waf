//! Compiled zig-regex collection-key selectors.

const std = @import("std");
const collections = @import("collections.zig");
const regex = @import("regex");

/// Ruleset-owned compiled selector. `matcher()` borrows this object, so the
/// selector must remain alive and immobile for the duration of selection.
pub const RegexSelector = struct {
    compiled: regex.Regex,

    pub fn compile(allocator: std.mem.Allocator, pattern: []const u8) !RegexSelector {
        return .{ .compiled = try regex.Regex.compile(allocator, pattern) };
    }

    pub fn matcher(self: *RegexSelector) collections.Matcher {
        return .{ .context = self, .matchesFn = matches };
    }

    pub fn deinit(self: *RegexSelector) void {
        self.compiled.deinit();
        self.* = undefined;
    }

    fn matches(context: *anyopaque, key: []const u8) collections.SelectorError!bool {
        const self: *RegexSelector = @ptrCast(@alignCast(context));
        return self.compiled.isMatch(key) catch |err| {
            const widened: anyerror = err;
            return switch (widened) {
                error.Timeout, error.InputTooLong, error.DfaOverflow => error.MatcherLimitExceeded,
                else => error.MatcherFailed,
            };
        };
    }
};

test "zig-regex selectors include and exclude collection keys" {
    var selector = try RegexSelector.compile(std.testing.allocator, "^(user|account)\\.");
    defer selector.deinit();
    var store = collections.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    const source: collections.Source = .{ .origin = .request_target, .offset = 0, .length = 1 };
    try store.add(.args_get, "user.name", "alice", source);
    try store.add(.args_get, "account.id", "7", source);
    try store.add(.args_get, "token", "secret", source);

    const target: collections.Target = .{
        .collection = .args_get,
        .selector = .{ .key_matcher = selector.matcher() },
        .count_only = true,
    };
    try std.testing.expectEqual(@as(usize, 2), try store.countTarget(target, &.{}));
    const exclusions = [_]collections.Target{.{ .collection = .args_get, .selector = .{ .key = "account.id" } }};
    try std.testing.expectEqual(@as(usize, 1), try store.countTarget(target, &exclusions));
}
