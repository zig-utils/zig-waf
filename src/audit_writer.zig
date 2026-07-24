//! Audit-log delivery.
//!
//! The engine produces formatted audit records (`Transaction.serializeAuditLog`);
//! a writer delivers them. Following zig-waf's I/O-free-core design, the writers
//! here never touch a file, socket, or the clock: they push bytes across a
//! `Sink` boundary that the embedder/connector owns (a file in production, an
//! in-memory buffer in tests), so the core stays non-blocking and portable.
//!
//! `SerialWriter` mirrors Coraza's serial writer — every record is appended to
//! a single destination followed by a newline. `CallbackWriter` hands each
//! record to a caller-supplied callback, for connectors that ship logs over
//! their own transport (syslog, an HTTPS batch, a channel).

const std = @import("std");
const audit = @import("audit.zig");

pub const WriteError = error{SinkWriteFailed};

/// A non-blocking, embedder-owned destination for record bytes.
pub const Sink = struct {
    context: *anyopaque,
    writeFn: *const fn (context: *anyopaque, bytes: []const u8) WriteError!void,

    pub fn write(self: Sink, bytes: []const u8) WriteError!void {
        return self.writeFn(self.context, bytes);
    }
};

/// Appends each formatted record to a single destination, one record per line
/// (Coraza's serialWriter: the formatted bytes followed by a newline). An empty
/// record is skipped, matching Coraza.
pub const SerialWriter = struct {
    sink: Sink,

    pub fn write(self: SerialWriter, record: []const u8) WriteError!void {
        if (record.len == 0) return;
        try self.sink.write(record);
        try self.sink.write("\n");
    }
};

/// Delivers each formatted record to a caller-supplied callback, for connectors
/// that own their transport. The callback runs synchronously and must not block
/// the request path; a connector that needs durability should enqueue.
pub const CallbackWriter = struct {
    context: *anyopaque,
    callback: *const fn (context: *anyopaque, record: []const u8) WriteError!void,

    pub fn write(self: CallbackWriter, record: []const u8) WriteError!void {
        if (record.len == 0) return;
        return self.callback(self.context, record);
    }
};

/// The per-record file path and audit-index line for the ModSecurity
/// "concurrent" layout. The core produces this metadata; the connector writes
/// the formatted record to `<storage_dir>/<path>` and appends `index_line` to
/// the audit index file. Both slices are owned by the caller.
pub const ConcurrentEntry = struct {
    path: []const u8,
    index_line: []const u8,

    pub fn deinit(self: ConcurrentEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.index_line);
    }
};

/// Build the concurrent-layout path and index line for `record`. The path is
/// the time-bucketed `YYYYMMDD/YYYYMMDD-HHMM/YYYYMMDD-HHMMSS-<id>` (UTC), and
/// the index line is ModSecurity's combined-log-style audit index entry;
/// `file_size` and `md5_hex` describe the written record and are the caller's.
pub fn concurrentEntry(
    allocator: std.mem.Allocator,
    record: audit.AuditRecord,
    file_size: usize,
    md5_hex: []const u8,
) std.mem.Allocator.Error!ConcurrentEntry {
    const c = audit.civil(record.timestamp);
    const path = try std.fmt.allocPrint(
        allocator,
        "{d:0>4}{d:0>2}{d:0>2}/{d:0>4}{d:0>2}{d:0>2}-{d:0>2}{d:0>2}/{d:0>4}{d:0>2}{d:0>2}-{d:0>2}{d:0>2}{d:0>2}-{s}",
        .{
            c.year,   c.month,  c.day,
            c.year,   c.month,  c.day,
            c.hour,   c.minute, c.year,
            c.month,  c.day,    c.hour,
            c.minute, c.second, record.unique_id,
        },
    );
    errdefer allocator.free(path);

    var timestamp: std.ArrayList(u8) = .empty;
    defer timestamp.deinit(allocator);
    try audit.writeTimestamp(&timestamp, allocator, record.timestamp);

    const host = dashOpt(findHeader(record.request_headers, "host"));
    const referer = dashOpt(findHeader(record.request_headers, "referer"));
    const user_agent = dashOpt(findHeader(record.request_headers, "user-agent"));
    const response_size = if (record.response_body) |body| body.len else 0;

    const index_line = try std.fmt.allocPrint(
        allocator,
        "{s} {s} - {s} \"{s} {s} HTTP/{s}\" {d} {d} {s} \"{s}\" {s} {s} {s} 0 {d} md5:{s}\n",
        .{
            host,                   dash(record.client_ip), timestamp.items,
            record.method,          record.uri,             record.http_version,
            record.response_status, response_size,          referer,
            user_agent,             record.unique_id,       referer,
            path,                   file_size,              md5_hex,
        },
    );
    return .{ .path = path, .index_line = index_line };
}

fn dash(value: []const u8) []const u8 {
    return if (value.len == 0) "-" else value;
}

fn dashOpt(value: ?[]const u8) []const u8 {
    return if (value) |v| dash(v) else "-";
}

fn findHeader(headers: []const audit.Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

const BufferSink = struct {
    bytes: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,
    fail: bool = false,

    fn sink(self: *BufferSink) Sink {
        return .{ .context = self, .writeFn = write };
    }
    fn write(context: *anyopaque, bytes: []const u8) WriteError!void {
        const self: *BufferSink = @ptrCast(@alignCast(context));
        if (self.fail) return error.SinkWriteFailed;
        self.bytes.appendSlice(self.allocator, bytes) catch return error.SinkWriteFailed;
    }
    fn deinit(self: *BufferSink) void {
        self.bytes.deinit(self.allocator);
    }
};

test "the serial writer appends each record with a trailing newline" {
    var buffer = BufferSink{ .allocator = testing.allocator };
    defer buffer.deinit();
    const writer = SerialWriter{ .sink = buffer.sink() };
    try writer.write("record one");
    try writer.write("record two");
    try testing.expectEqualStrings("record one\nrecord two\n", buffer.bytes.items);
}

test "the serial writer skips an empty record" {
    var buffer = BufferSink{ .allocator = testing.allocator };
    defer buffer.deinit();
    const writer = SerialWriter{ .sink = buffer.sink() };
    try writer.write("");
    try testing.expectEqual(@as(usize, 0), buffer.bytes.items.len);
}

test "a sink failure surfaces to the caller" {
    var buffer = BufferSink{ .allocator = testing.allocator, .fail = true };
    defer buffer.deinit();
    const writer = SerialWriter{ .sink = buffer.sink() };
    try testing.expectError(error.SinkWriteFailed, writer.write("record"));
}

const CallbackState = struct {
    count: usize = 0,
    last: []const u8 = "",

    fn record(context: *anyopaque, bytes: []const u8) WriteError!void {
        const self: *CallbackState = @ptrCast(@alignCast(context));
        self.count += 1;
        self.last = bytes;
    }
};

test "the callback writer forwards non-empty records" {
    var state = CallbackState{};
    const writer = CallbackWriter{ .context = &state, .callback = CallbackState.record };
    try writer.write("first");
    try writer.write("");
    try writer.write("second");
    try testing.expectEqual(@as(usize, 2), state.count);
    try testing.expectEqualStrings("second", state.last);
}

test "concurrentEntry builds the time-bucketed path and index line" {
    const record: audit.AuditRecord = .{
        .boundary = "zigwaf-abc",
        .timestamp = 1626354855, // 2021-07-15 13:14:15 UTC
        .unique_id = "zigwaf-abc",
        .client_ip = "192.0.2.10",
        .client_port = 5000,
        .server_ip = "198.51.100.5",
        .server_port = 443,
        .method = "GET",
        .uri = "/p",
        .http_version = "1.1",
        .request_headers = &.{
            .{ .name = "Host", .value = "example.com" },
            .{ .name = "User-Agent", .value = "curl/8" },
        },
        .response_status = 200,
        .response_body = "abcd",
    };
    const entry = try concurrentEntry(testing.allocator, record, 512, "deadbeef");
    defer entry.deinit(testing.allocator);

    try testing.expectEqualStrings("20210715/20210715-1314/20210715-131415-zigwaf-abc", entry.path);
    const expected =
        "example.com 192.0.2.10 - [15/Jul/2021:13:14:15 +0000] " ++
        "\"GET /p HTTP/1.1\" 200 4 - \"curl/8\" zigwaf-abc - " ++
        "20210715/20210715-1314/20210715-131415-zigwaf-abc 0 512 md5:deadbeef\n";
    try testing.expectEqualStrings(expected, entry.index_line);
}

test "concurrentEntry dashes absent headers" {
    const record: audit.AuditRecord = .{
        .boundary = "id",
        .timestamp = 0,
        .unique_id = "id",
        .client_ip = "",
        .client_port = 0,
        .server_ip = "2.2.2.2",
        .server_port = 2,
        .method = "GET",
        .uri = "/",
        .http_version = "1.1",
        .response_status = 200,
    };
    const entry = try concurrentEntry(testing.allocator, record, 0, "x");
    defer entry.deinit(testing.allocator);
    // No Host/client-ip/referer/user-agent → dashes.
    try testing.expect(std.mem.startsWith(u8, entry.index_line, "- - - [01/Jan/1970:00:00:00 +0000] \"GET / HTTP/1.1\" 200 0 - \"-\" id -"));
}
