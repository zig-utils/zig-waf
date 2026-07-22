//! Compiled zig-regex collection-key selectors.

const std = @import("std");
const collections = @import("collections.zig");
const regex = @import("regex");

/// Ruleset-owned compiled selector. Create one reusable `Worker` per request
/// worker so mutable DFA caches are never shared across threads.
pub const RegexSelector = struct {
    compiled: regex.Regex,

    pub fn compile(allocator: std.mem.Allocator, pattern: []const u8) !RegexSelector {
        return .{ .compiled = try regex.Regex.compile(allocator, pattern) };
    }

    pub fn worker(self: *const RegexSelector) Worker {
        return .{ .state = self.compiled.matcher() };
    }

    pub fn deinit(self: *RegexSelector) void {
        self.compiled.deinit();
        self.* = undefined;
    }

    pub const Worker = struct {
        state: regex.Regex.Matcher,

        pub fn matcher(self: *Worker) collections.Matcher {
            return .{ .context = self, .matchesFn = matches };
        }

        pub fn deinit(self: *Worker) void {
            self.state.deinit();
            self.* = undefined;
        }

        fn matches(context: *anyopaque, key: []const u8) collections.SelectorError!bool {
            const self: *Worker = @ptrCast(@alignCast(context));
            return self.state.isMatch(key) catch |err| {
                const widened: anyerror = err;
                return switch (widened) {
                    error.Timeout, error.InputTooLong, error.DfaOverflow => error.MatcherLimitExceeded,
                    else => error.MatcherFailed,
                };
            };
        }
    };
};

test "zig-regex selectors include and exclude collection keys" {
    var selector = try RegexSelector.compile(std.testing.allocator, "^(user|account)\\.");
    defer selector.deinit();
    var worker = selector.worker();
    defer worker.deinit();
    var store = collections.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    const source: collections.Source = .{ .origin = .request_target, .offset = 0, .length = 1 };
    try store.add(.args_get, "user.name", "alice", source);
    try store.add(.args_get, "account.id", "7", source);
    try store.add(.args_get, "token", "secret", source);

    const target: collections.Target = .{
        .collection = .args_get,
        .selector = .{ .key_matcher = worker.matcher() },
        .count_only = true,
    };
    try std.testing.expectEqual(@as(usize, 2), try store.countTarget(target, &.{}));
    const exclusions = [_]collections.Target{.{ .collection = .args_get, .selector = .{ .key = "account.id" } }};
    try std.testing.expectEqual(@as(usize, 1), try store.countTarget(target, &exclusions));
}
