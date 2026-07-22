//! Owned configuration sources, stable spans, and physical line lookup.

const std = @import("std");

pub const SourceId = enum(u32) { _ };

pub const Span = struct {
    source: SourceId,
    start: u32,
    end: u32,

    pub fn length(self: Span) u32 {
        return self.end - self.start;
    }
};

pub const Location = struct {
    line: u32,
    column: u32,
    offset: u32,
};

pub const IncludeOrigin = struct {
    parent: SourceId,
    directive: Span,
};

pub const Limits = struct {
    max_sources: usize = 1024,
    max_source_bytes: usize = 16 * 1024 * 1024,
    max_total_bytes: usize = 64 * 1024 * 1024,
    max_path_bytes: usize = 4096,
    max_lines_per_source: usize = 1_000_000,

    pub fn validate(self: Limits) error{InvalidSourceLimit}!void {
        if (self.max_sources == 0 or
            self.max_source_bytes == 0 or
            self.max_total_bytes < self.max_source_bytes or
            self.max_path_bytes == 0 or
            self.max_lines_per_source == 0)
        {
            return error.InvalidSourceLimit;
        }
    }
};

pub const RegistryError = std.mem.Allocator.Error || error{
    TooManySources,
    SourceTooLarge,
    AggregateSourceLimitExceeded,
    PathTooLarge,
    TooManySourceLines,
    InvalidUtf8,
    InvalidSourceId,
    InvalidSpan,
    InvalidIncludeOrigin,
};

pub const Source = struct {
    id: SourceId,
    path: []const u8,
    bytes: []const u8,
    line_starts: []const u32,
    included_from: ?IncludeOrigin,

    pub fn fullSpan(self: Source) Span {
        return .{ .source = self.id, .start = 0, .end = @intCast(self.bytes.len) };
    }
};

pub const Registry = struct {
    arena: std.heap.ArenaAllocator,
    limits: Limits,
    sources: std.ArrayList(Source) = .empty,
    total_bytes: usize = 0,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) error{InvalidSourceLimit}!Registry {
        try limits.validate();
        return .{ .arena = .init(allocator), .limits = limits };
    }

    pub fn add(
        self: *Registry,
        path: []const u8,
        bytes: []const u8,
        included_from: ?IncludeOrigin,
    ) RegistryError!SourceId {
        if (self.sources.items.len == self.limits.max_sources) return error.TooManySources;
        if (path.len == 0 or path.len > self.limits.max_path_bytes) return error.PathTooLarge;
        if (bytes.len > self.limits.max_source_bytes or bytes.len > std.math.maxInt(u32)) return error.SourceTooLarge;
        if (bytes.len > self.limits.max_total_bytes -| self.total_bytes) return error.AggregateSourceLimitExceeded;
        if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidUtf8;
        if (included_from) |origin| {
            _ = self.get(origin.parent) orelse return error.InvalidIncludeOrigin;
            try self.validateSpan(origin.directive);
            if (origin.directive.source != origin.parent) return error.InvalidIncludeOrigin;
        }

        var line_count: usize = 1;
        for (bytes) |byte| line_count += @intFromBool(byte == '\n');
        if (line_count > self.limits.max_lines_per_source) return error.TooManySourceLines;

        const allocator = self.arena.allocator();
        const owned_path = try allocator.dupe(u8, path);
        const owned_bytes = try allocator.dupe(u8, bytes);
        const line_starts = try allocator.alloc(u32, line_count);
        line_starts[0] = 0;
        var line_index: usize = 1;
        for (owned_bytes, 0..) |byte, index| {
            if (byte != '\n') continue;
            line_starts[line_index] = @intCast(index + 1);
            line_index += 1;
        }

        const id: SourceId = @fromBackingInt(@intCast(@as(u32, @intCast(self.sources.items.len))));
        try self.sources.append(allocator, .{
            .id = id,
            .path = owned_path,
            .bytes = owned_bytes,
            .line_starts = line_starts,
            .included_from = included_from,
        });
        self.total_bytes += bytes.len;
        return id;
    }

    pub fn get(self: *const Registry, id: SourceId) ?*const Source {
        const index: usize = @backingInt(id);
        if (index >= self.sources.items.len) return null;
        return &self.sources.items[index];
    }

    pub fn slice(self: *const Registry, span: Span) RegistryError![]const u8 {
        try self.validateSpan(span);
        const source = self.get(span.source).?;
        return source.bytes[span.start..span.end];
    }

    pub fn location(self: *const Registry, source_id: SourceId, offset: u32) RegistryError!Location {
        const source = self.get(source_id) orelse return error.InvalidSourceId;
        if (offset > source.bytes.len) return error.InvalidSpan;
        var low: usize = 0;
        var high: usize = source.line_starts.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (source.line_starts[middle] <= offset)
                low = middle + 1
            else
                high = middle;
        }
        const line_index = low - 1;
        return .{
            .line = @intCast(line_index + 1),
            .column = offset - source.line_starts[line_index] + 1,
            .offset = offset,
        };
    }

    pub fn validateSpan(self: *const Registry, span: Span) RegistryError!void {
        const source = self.get(span.source) orelse return error.InvalidSourceId;
        if (span.start > span.end or span.end > source.bytes.len) return error.InvalidSpan;
    }

    pub fn deinit(self: *Registry) void {
        self.sources.deinit(self.arena.allocator());
        self.arena.deinit();
        self.* = undefined;
    }
};

test "registry owns paths bytes lines and include ancestry" {
    var registry = try Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    var root_bytes = [_]u8{ 'a', '\r', '\n', 'b', '\n' };
    const root = try registry.add("root.conf", &root_bytes, null);
    root_bytes[0] = 'x';
    try std.testing.expectEqualStrings("a\r\nb\n", registry.get(root).?.bytes);
    try std.testing.expectEqual(Location{ .line = 2, .column = 1, .offset = 3 }, try registry.location(root, 3));
    const directive: Span = .{ .source = root, .start = 3, .end = 4 };
    const child = try registry.add("rules/child.conf", "SecAction pass", .{ .parent = root, .directive = directive });
    try std.testing.expectEqual(root, registry.get(child).?.included_from.?.parent);
    try std.testing.expectEqualStrings("b", try registry.slice(directive));
}

test "registry rejects invalid ownership and aggregate inputs atomically" {
    var registry = try Registry.init(std.testing.allocator, .{
        .max_sources = 1,
        .max_source_bytes = 4,
        .max_total_bytes = 4,
        .max_path_bytes = 4,
        .max_lines_per_source = 2,
    });
    defer registry.deinit();
    try std.testing.expectError(error.PathTooLarge, registry.add("long-path", "x", null));
    try std.testing.expectError(error.InvalidUtf8, registry.add("a", "\xff", null));
    const source = try registry.add("a", "x\n", null);
    try std.testing.expectError(error.TooManySources, registry.add("b", "x", null));
    try std.testing.expectError(error.InvalidSpan, registry.slice(.{ .source = source, .start = 2, .end = 1 }));
}
