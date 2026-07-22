//! Bounded physical-to-logical SecLang line normalization.

const std = @import("std");
const source = @import("source.zig");

pub const Limits = struct {
    max_logical_line_bytes: usize = 1024 * 1024,
    max_segments_per_line: usize = 1024,

    pub fn validate(self: Limits) error{InvalidLexerLimit}!void {
        if (self.max_logical_line_bytes == 0 or self.max_segments_per_line == 0) return error.InvalidLexerLimit;
    }
};

pub const Segment = struct {
    logical_start: u32,
    physical: source.Span,
};

pub const LogicalLine = struct {
    allocator: std.mem.Allocator,
    text: []u8,
    segments: []Segment,
    physical: source.Span,

    pub fn deinit(self: *LogicalLine) void {
        self.allocator.free(self.text);
        self.allocator.free(self.segments);
        self.* = undefined;
    }

    pub fn physicalOffset(self: *const LogicalLine, logical_offset: u32) ?u32 {
        if (logical_offset > self.text.len) return null;
        var selected: ?Segment = null;
        for (self.segments) |segment| {
            if (segment.logical_start > logical_offset) break;
            selected = segment;
        }
        const segment = selected orelse return self.physical.start;
        const relative = logical_offset - segment.logical_start;
        return @min(segment.physical.end, segment.physical.start + relative);
    }
};

pub const LexerError = std.mem.Allocator.Error || error{
    LogicalLineTooLarge,
    TooManyLineSegments,
    DanglingContinuation,
};

pub const LogicalLineIterator = struct {
    input: *const source.Source,
    limits: Limits,
    offset: usize = 0,

    pub fn init(input: *const source.Source, limits: Limits) error{InvalidLexerLimit}!LogicalLineIterator {
        try limits.validate();
        return .{ .input = input, .limits = limits };
    }

    pub fn next(self: *LogicalLineIterator, allocator: std.mem.Allocator) LexerError!?LogicalLine {
        if (self.offset == self.input.bytes.len) return null;
        const physical_start = self.offset;
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(allocator);
        var segments: std.ArrayList(Segment) = .empty;
        defer segments.deinit(allocator);
        var continuing = false;

        while (self.offset < self.input.bytes.len) {
            const line_start = self.offset;
            const newline = std.mem.indexOfScalarPos(u8, self.input.bytes, line_start, '\n');
            const next_offset = if (newline) |index| index + 1 else self.input.bytes.len;
            var content_end = newline orelse self.input.bytes.len;
            if (content_end > line_start and self.input.bytes[content_end - 1] == '\r') content_end -= 1;
            var content_start = line_start;
            if (continuing) {
                while (content_start < content_end and isHorizontalSpace(self.input.bytes[content_start])) content_start += 1;
            }

            var trimmed_end = content_end;
            while (trimmed_end > content_start and isHorizontalSpace(self.input.bytes[trimmed_end - 1])) trimmed_end -= 1;
            const has_continuation = trimmed_end > content_start and self.input.bytes[trimmed_end - 1] == '\\';
            var append_end = content_end;
            if (has_continuation) {
                append_end = trimmed_end - 1;
                while (append_end > content_start and isHorizontalSpace(self.input.bytes[append_end - 1])) append_end -= 1;
            }

            if (append_end > content_start) {
                if (segments.items.len == self.limits.max_segments_per_line) return error.TooManyLineSegments;
                const length = append_end - content_start;
                if (length > self.limits.max_logical_line_bytes -| text.items.len) return error.LogicalLineTooLarge;
                try segments.append(allocator, .{
                    .logical_start = @intCast(text.items.len),
                    .physical = .{
                        .source = self.input.id,
                        .start = @intCast(content_start),
                        .end = @intCast(append_end),
                    },
                });
                try text.appendSlice(allocator, self.input.bytes[content_start..append_end]);
            }
            self.offset = next_offset;
            if (!has_continuation) break;
            if (newline == null) return error.DanglingContinuation;
            continuing = true;
        }

        const owned_text = try text.toOwnedSlice(allocator);
        errdefer allocator.free(owned_text);
        const owned_segments = try segments.toOwnedSlice(allocator);
        return .{
            .allocator = allocator,
            .text = owned_text,
            .segments = owned_segments,
            .physical = .{
                .source = self.input.id,
                .start = @intCast(physical_start),
                .end = @intCast(self.offset),
            },
        };
    }
};

fn isHorizontalSpace(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

test "logical lines normalize CRLF and baseline continuation whitespace" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const id = try registry.add(
        "rules.conf",
        "SecRule ARGS \\\r\n    \"@rx attack\"   \\\n\t\"id:1,deny\"\r\nSecAction pass",
        null,
    );
    var iterator = try LogicalLineIterator.init(registry.get(id).?, .{});
    var first = (try iterator.next(std.testing.allocator)).?;
    defer first.deinit();
    try std.testing.expectEqualStrings("SecRule ARGS\"@rx attack\"\"id:1,deny\"", first.text);
    try std.testing.expectEqual(@as(usize, 3), first.segments.len);
    try std.testing.expectEqual(@as(u32, 0), first.physicalOffset(0).?);
    try std.testing.expectEqual(@as(u32, 20), first.physicalOffset(12).?);
    var second = (try iterator.next(std.testing.allocator)).?;
    defer second.deinit();
    try std.testing.expectEqualStrings("SecAction pass", second.text);
    try std.testing.expect((try iterator.next(std.testing.allocator)) == null);
}

test "logical line limits and dangling continuation are explicit" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const long = try registry.add("long.conf", "abcd", null);
    var limited = try LogicalLineIterator.init(registry.get(long).?, .{ .max_logical_line_bytes = 3 });
    try std.testing.expectError(error.LogicalLineTooLarge, limited.next(std.testing.allocator));
    const dangling = try registry.add("dangling.conf", "SecAction \\", null);
    var dangling_iterator = try LogicalLineIterator.init(registry.get(dangling).?, .{});
    try std.testing.expectError(error.DanglingContinuation, dangling_iterator.next(std.testing.allocator));
}
