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
