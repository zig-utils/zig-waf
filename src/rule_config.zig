//! Bounded compile-time selectors and policy primitives for SecLang rule updates.

const std = @import("std");

pub const MissingRulePolicy = enum { strict, compatibility };

pub const IdInterval = struct {
    first: u64,
    last: u64,

    pub fn contains(self: IdInterval, value: u64) bool {
        return value >= self.first and value <= self.last;
    }
};

pub const IdSelectorLimits = struct {
    max_fragments: usize = 4096,
    max_input_bytes: usize = 1024 * 1024,
    max_intervals: usize = 65_536,

    pub fn validate(self: IdSelectorLimits) error{InvalidIdSelectorLimit}!void {
        if (self.max_fragments == 0 or self.max_input_bytes == 0 or self.max_intervals == 0)
            return error.InvalidIdSelectorLimit;
    }
};

pub const IdSelectorError = std.mem.Allocator.Error || error{
    InvalidIdSelectorLimit,
    TooManyIdSelectorFragments,
    IdSelectorInputLimitExceeded,
    TooManyIdIntervals,
    EmptyIdSelector,
    InvalidIdInterval,
    IdIntervalOverflow,
    ReversedIdInterval,
};

pub const IdSelectorFailure = struct {
    fragment: u32,
    start: u32,
    end: u32,
};

pub const IdSelector = struct {
    allocator: std.mem.Allocator,
    requested: []const IdInterval,
    intervals: []const IdInterval,

    pub fn parse(
        allocator: std.mem.Allocator,
        fragments: []const []const u8,
        limits: IdSelectorLimits,
        failure: ?*?IdSelectorFailure,
    ) IdSelectorError!IdSelector {
        try limits.validate();
        if (fragments.len > limits.max_fragments) return error.TooManyIdSelectorFragments;
        var parsed: std.ArrayList(IdInterval) = .empty;
        defer parsed.deinit(allocator);
        var total_bytes: usize = 0;
        for (fragments, 0..) |fragment, fragment_index| {
            if (fragment.len > limits.max_input_bytes -| total_bytes)
                return error.IdSelectorInputLimitExceeded;
            total_bytes += fragment.len;
            var cursor: usize = 0;
            while (cursor < fragment.len) {
                while (cursor < fragment.len and isSeparator(fragment[cursor])) cursor += 1;
                if (cursor == fragment.len) break;
                const start = cursor;
                while (cursor < fragment.len and !isSeparator(fragment[cursor])) cursor += 1;
                const token = fragment[start..cursor];
                if (parsed.items.len == limits.max_intervals) return error.TooManyIdIntervals;
                const interval = parseInterval(token) catch |cause| {
                    setFailure(failure, fragment_index, start, cursor);
                    return cause;
                };
                try parsed.append(allocator, interval);
            }
        }
        if (parsed.items.len == 0) return error.EmptyIdSelector;
        const requested = try allocator.dupe(IdInterval, parsed.items);
        errdefer allocator.free(requested);
        std.mem.sort(IdInterval, parsed.items, {}, lessThanInterval);
        var write: usize = 0;
        for (parsed.items) |interval| {
            if (write == 0) {
                parsed.items[0] = interval;
                write = 1;
                continue;
            }
            const prior = &parsed.items[write - 1];
            const touches = interval.first <= prior.last or
                (prior.last != std.math.maxInt(u64) and interval.first == prior.last + 1);
            if (touches) {
                prior.last = @max(prior.last, interval.last);
            } else {
                parsed.items[write] = interval;
                write += 1;
            }
        }
        const owned = try allocator.dupe(IdInterval, parsed.items[0..write]);
        return .{ .allocator = allocator, .requested = requested, .intervals = owned };
    }

    pub fn deinit(self: *IdSelector) void {
        self.allocator.free(self.intervals);
        self.allocator.free(self.requested);
        self.* = undefined;
    }

    pub fn matches(self: IdSelector, value: u64) bool {
        var low: usize = 0;
        var high = self.intervals.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            const interval = self.intervals[middle];
            if (value < interval.first) {
                high = middle;
            } else if (value > interval.last) {
                low = middle + 1;
            } else {
                return true;
            }
        }
        return false;
    }
};

fn parseInterval(token: []const u8) IdSelectorError!IdInterval {
    const separator = std.mem.indexOfScalar(u8, token, '-');
    if (separator) |index| {
        if (index == 0 or index + 1 == token.len or
            std.mem.indexOfScalar(u8, token[index + 1 ..], '-') != null)
        {
            return error.InvalidIdInterval;
        }
        const first = parseId(token[0..index]) catch |cause| return cause;
        const last = parseId(token[index + 1 ..]) catch |cause| return cause;
        if (first > last) return error.ReversedIdInterval;
        return .{ .first = first, .last = last };
    }
    const value = parseId(token) catch |cause| return cause;
    return .{ .first = value, .last = value };
}

fn parseId(value: []const u8) IdSelectorError!u64 {
    if (value.len == 0) return error.InvalidIdInterval;
    var result: u64 = 0;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidIdInterval;
        result = std.math.mul(u64, result, 10) catch return error.IdIntervalOverflow;
        result = std.math.add(u64, result, byte - '0') catch return error.IdIntervalOverflow;
    }
    return result;
}

fn isSeparator(byte: u8) bool {
    return byte == ',' or std.ascii.isWhitespace(byte);
}

fn lessThanInterval(_: void, left: IdInterval, right: IdInterval) bool {
    return left.first < right.first or (left.first == right.first and left.last < right.last);
}

fn setFailure(output: ?*?IdSelectorFailure, fragment: usize, start: usize, end: usize) void {
    if (output) |value| value.* = .{
        .fragment = @intCast(fragment),
        .start = @intCast(start),
        .end = @intCast(end),
    };
}

test "id selectors canonicalize lists ranges duplicates and adjacency" {
    var failure: ?IdSelectorFailure = null;
    var selector = try IdSelector.parse(
        std.testing.allocator,
        &.{ "30,10-20", "21 30 18446744073709551615" },
        .{},
        &failure,
    );
    defer selector.deinit();
    try std.testing.expectEqual(@as(?IdSelectorFailure, null), failure);
    try std.testing.expectEqual(@as(usize, 5), selector.requested.len);
    try std.testing.expectEqualSlices(IdInterval, &.{
        .{ .first = 10, .last = 21 },
        .{ .first = 30, .last = 30 },
        .{ .first = std.math.maxInt(u64), .last = std.math.maxInt(u64) },
    }, selector.intervals);
    try std.testing.expect(selector.matches(10));
    try std.testing.expect(selector.matches(19));
    try std.testing.expect(selector.matches(21));
    try std.testing.expect(!selector.matches(22));
    try std.testing.expect(selector.matches(std.math.maxInt(u64)));
}

test "id selector syntax failures report the exact fragment token" {
    const cases = [_]struct { input: []const u8, expected: IdSelectorError }{
        .{ .input = "-1", .expected = error.InvalidIdInterval },
        .{ .input = "1-", .expected = error.InvalidIdInterval },
        .{ .input = "1-2-3", .expected = error.InvalidIdInterval },
        .{ .input = "20-10", .expected = error.ReversedIdInterval },
        .{ .input = "nope", .expected = error.InvalidIdInterval },
        .{ .input = "18446744073709551616", .expected = error.IdIntervalOverflow },
    };
    for (cases) |case| {
        var failure: ?IdSelectorFailure = null;
        try std.testing.expectError(case.expected, IdSelector.parse(std.testing.allocator, &.{ "1", case.input }, .{}, &failure));
        try std.testing.expectEqual(@as(u32, 1), failure.?.fragment);
        try std.testing.expectEqual(@as(u32, 0), failure.?.start);
        try std.testing.expectEqual(@as(u32, @intCast(case.input.len)), failure.?.end);
    }
}

test "id selector resource limits fail independently" {
    try std.testing.expectError(error.InvalidIdSelectorLimit, IdSelector.parse(std.testing.allocator, &.{"1"}, .{ .max_intervals = 0 }, null));
    try std.testing.expectError(error.TooManyIdSelectorFragments, IdSelector.parse(std.testing.allocator, &.{ "1", "2" }, .{ .max_fragments = 1 }, null));
    try std.testing.expectError(error.IdSelectorInputLimitExceeded, IdSelector.parse(std.testing.allocator, &.{"123"}, .{ .max_input_bytes = 2 }, null));
    try std.testing.expectError(error.TooManyIdIntervals, IdSelector.parse(std.testing.allocator, &.{"1 2"}, .{ .max_intervals = 1 }, null));
    try std.testing.expectError(error.EmptyIdSelector, IdSelector.parse(std.testing.allocator, &.{" , \t"}, .{}, null));
}

test "id selector parsing is allocation failure safe" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var selector = try IdSelector.parse(allocator, &.{"1 5-10 20,30-40"}, .{}, null);
            defer selector.deinit();
            try std.testing.expect(selector.matches(35));
        }
    }.run, .{});
}
