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

/// A bounded queue between record production and delivery (#31).
///
/// The request path must not wait on a log destination — a slow disk or an
/// unreachable collector cannot be allowed to slow down request handling, and a
/// destination that is down must not consume memory without limit either. So
/// records are enqueued (a copy, bounded in count and bytes) and delivered later by
/// whatever the host runs the drain on.
///
/// The queue is explicit about loss. A record that cannot be enqueued is counted,
/// and `dropped()` is a number an operator can alert on, because an audit log with
/// gaps nobody knows about is worse than one that is visibly incomplete.
pub const DeliveryQueue = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    overflow: Overflow,
    records: std.ArrayList([]u8) = .empty,
    bytes: usize = 0,
    stats: Stats = .{},

    pub const Limits = struct {
        /// Records the queue may hold.
        max_records: usize = 4096,
        /// Total bytes the queue may hold, so a few enormous records cannot use the
        /// memory a thousand ordinary ones were budgeted.
        max_bytes: usize = 16 * 1024 * 1024,
    };

    /// What a full queue does with a new record.
    pub const Overflow = enum {
        /// Refuse the new record. The most recent events are lost, but an
        /// investigation already in progress keeps the history it was reading.
        reject_new,
        /// Discard the oldest record. History is lost, but what is happening now is
        /// kept — which is what an incident in progress needs.
        drop_oldest,
    };

    /// Delivery accounting. Every record is in exactly one of these outcomes, so the
    /// numbers add up and a gap cannot hide.
    pub const Stats = struct {
        enqueued: usize = 0,
        delivered: usize = 0,
        /// Records dropped because the queue was full.
        dropped: usize = 0,
        /// Delivery attempts that failed. A record whose attempt fails stays queued,
        /// so this counts attempts and not lost records.
        failed_attempts: usize = 0,
        /// Consecutive failed drains, for a caller's backoff. Reset by any success.
        consecutive_failures: usize = 0,
    };

    pub fn init(allocator: std.mem.Allocator, limits: Limits, overflow: Overflow) DeliveryQueue {
        return .{ .allocator = allocator, .limits = limits, .overflow = overflow };
    }

    pub fn deinit(self: *DeliveryQueue) void {
        for (self.records.items) |record| self.allocator.free(record);
        self.records.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const DeliveryQueue) usize {
        return self.records.items.len;
    }

    pub fn accounting(self: *const DeliveryQueue) Stats {
        return self.stats;
    }

    /// Copy a record into the queue. Returns false when the record could not be
    /// held — which is counted, never silent.
    pub fn enqueue(self: *DeliveryQueue, record: []const u8) error{OutOfMemory}!bool {
        if (record.len == 0) return true;
        // A record larger than the whole budget can never be held, whatever the
        // policy: dropping older records to make room would empty the queue and
        // still fail.
        if (record.len > self.limits.max_bytes) {
            self.stats.dropped += 1;
            return false;
        }
        while (self.records.items.len >= self.limits.max_records or
            self.bytes + record.len > self.limits.max_bytes)
        {
            switch (self.overflow) {
                .reject_new => {
                    self.stats.dropped += 1;
                    return false;
                },
                .drop_oldest => {
                    if (self.records.items.len == 0) {
                        self.stats.dropped += 1;
                        return false;
                    }
                    const oldest = self.records.orderedRemove(0);
                    self.bytes -= oldest.len;
                    self.allocator.free(oldest);
                    self.stats.dropped += 1;
                },
            }
        }
        const owned = try self.allocator.dupe(u8, record);
        errdefer self.allocator.free(owned);
        try self.records.append(self.allocator, owned);
        self.bytes += owned.len;
        self.stats.enqueued += 1;
        return true;
    }

    /// Deliver queued records through `writer`, stopping at the first failure and
    /// keeping everything from that record onward for the next attempt. Returns how
    /// many were delivered.
    ///
    /// Stopping rather than skipping is deliberate: an audit log that reorders or
    /// silently omits records is not an audit log, so a failing destination delays
    /// delivery instead of scattering it.
    pub fn drain(self: *DeliveryQueue, writer: SerialWriter) usize {
        var delivered: usize = 0;
        while (self.records.items.len != 0) {
            const record = self.records.items[0];
            writer.write(record) catch {
                self.stats.failed_attempts += 1;
                self.stats.consecutive_failures += 1;
                return delivered;
            };
            _ = self.records.orderedRemove(0);
            self.bytes -= record.len;
            self.allocator.free(record);
            delivered += 1;
            self.stats.delivered += 1;
        }
        if (delivered != 0) self.stats.consecutive_failures = 0;
        return delivered;
    }

    /// How long to wait before retrying, doubling per consecutive failure up to
    /// `max_delay_ms`. A destination that is down should be retried, not hammered.
    pub fn backoffMilliseconds(self: *const DeliveryQueue, base_ms: u64, max_delay_ms: u64) u64 {
        if (self.stats.consecutive_failures == 0) return 0;
        const shift: u6 = @intCast(@min(self.stats.consecutive_failures - 1, 16));
        const scaled = std.math.shlExact(u64, base_ms, shift) catch return max_delay_ms;
        return @min(scaled, max_delay_ms);
    }

    /// Deliver everything still queued at shutdown, reporting what could not be
    /// delivered. A caller that ignores the return value loses records knowingly;
    /// one that logs it can say exactly how many.
    pub fn shutdown(self: *DeliveryQueue, writer: SerialWriter) usize {
        _ = self.drain(writer);
        return self.records.items.len;
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

/// A sink that can be told to fail, for exercising delivery failure.
const FlakySink = struct {
    buffer: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,
    failing: bool = false,

    fn write(context: *anyopaque, bytes: []const u8) WriteError!void {
        const self: *FlakySink = @ptrCast(@alignCast(context));
        if (self.failing) return error.SinkWriteFailed;
        self.buffer.appendSlice(self.allocator, bytes) catch return error.SinkWriteFailed;
    }

    fn sink(self: *FlakySink) Sink {
        return .{ .context = self, .writeFn = write };
    }

    fn deinit(self: *FlakySink) void {
        self.buffer.deinit(self.allocator);
    }
};

test "the delivery queue holds records, drains them, and accounts for every one" {
    var destination = FlakySink{ .allocator = std.testing.allocator };
    defer destination.deinit();
    const writer = SerialWriter{ .sink = destination.sink() };

    var queue = DeliveryQueue.init(std.testing.allocator, .{ .max_records = 3, .max_bytes = 64 }, .reject_new);
    defer queue.deinit();

    try std.testing.expect(try queue.enqueue("first"));
    try std.testing.expect(try queue.enqueue("second"));
    try std.testing.expectEqual(@as(usize, 2), queue.len());

    try std.testing.expectEqual(@as(usize, 2), queue.drain(writer));
    try std.testing.expectEqualStrings("first\nsecond\n", destination.buffer.items);
    try std.testing.expectEqual(@as(usize, 0), queue.len());

    const accounting = queue.accounting();
    try std.testing.expectEqual(@as(usize, 2), accounting.enqueued);
    try std.testing.expectEqual(@as(usize, 2), accounting.delivered);
    try std.testing.expectEqual(@as(usize, 0), accounting.dropped);
}

test "a failing destination delays delivery rather than scattering it" {
    var destination = FlakySink{ .allocator = std.testing.allocator };
    defer destination.deinit();
    const writer = SerialWriter{ .sink = destination.sink() };

    var queue = DeliveryQueue.init(std.testing.allocator, .{}, .reject_new);
    defer queue.deinit();
    _ = try queue.enqueue("a");
    _ = try queue.enqueue("b");

    // Nothing is delivered while the destination is down, and nothing is lost.
    destination.failing = true;
    try std.testing.expectEqual(@as(usize, 0), queue.drain(writer));
    try std.testing.expectEqual(@as(usize, 2), queue.len());
    try std.testing.expectEqual(@as(usize, 1), queue.accounting().consecutive_failures);

    // Backoff grows with consecutive failures and stops at the ceiling, so a
    // destination that is down is retried rather than hammered.
    try std.testing.expectEqual(@as(u64, 100), queue.backoffMilliseconds(100, 5_000));
    _ = queue.drain(writer);
    try std.testing.expectEqual(@as(u64, 200), queue.backoffMilliseconds(100, 5_000));
    _ = queue.drain(writer);
    try std.testing.expectEqual(@as(u64, 400), queue.backoffMilliseconds(100, 5_000));
    try std.testing.expectEqual(@as(u64, 300), queue.backoffMilliseconds(100, 300));

    // When it recovers, the records arrive in the order they were produced — an
    // audit log that reordered or skipped records would not be one.
    destination.failing = false;
    try std.testing.expectEqual(@as(usize, 2), queue.drain(writer));
    try std.testing.expectEqualStrings("a\nb\n", destination.buffer.items);
    try std.testing.expectEqual(@as(usize, 0), queue.accounting().consecutive_failures);
    try std.testing.expectEqual(@as(usize, 3), queue.accounting().failed_attempts);
}

test "a full queue loses records visibly, by whichever policy was chosen" {
    // Rejecting the new record keeps the history an investigation is already
    // reading; dropping the oldest keeps what is happening now. Both are defensible,
    // and both are counted — an audit log with gaps nobody knows about is worse than
    // one that is visibly incomplete.
    var rejecting = DeliveryQueue.init(std.testing.allocator, .{ .max_records = 2, .max_bytes = 1024 }, .reject_new);
    defer rejecting.deinit();
    try std.testing.expect(try rejecting.enqueue("one"));
    try std.testing.expect(try rejecting.enqueue("two"));
    try std.testing.expect(!try rejecting.enqueue("three"));
    try std.testing.expectEqual(@as(usize, 2), rejecting.len());
    try std.testing.expectEqual(@as(usize, 1), rejecting.accounting().dropped);

    var shedding = DeliveryQueue.init(std.testing.allocator, .{ .max_records = 2, .max_bytes = 1024 }, .drop_oldest);
    defer shedding.deinit();
    _ = try shedding.enqueue("one");
    _ = try shedding.enqueue("two");
    try std.testing.expect(try shedding.enqueue("three"));
    try std.testing.expectEqual(@as(usize, 2), shedding.len());
    try std.testing.expectEqual(@as(usize, 1), shedding.accounting().dropped);

    var destination = FlakySink{ .allocator = std.testing.allocator };
    defer destination.deinit();
    _ = shedding.drain(.{ .sink = destination.sink() });
    try std.testing.expectEqualStrings("two\nthree\n", destination.buffer.items);

    // The byte budget bounds the queue independently of the record count, so a few
    // enormous records cannot consume what a thousand ordinary ones were budgeted.
    var bounded = DeliveryQueue.init(std.testing.allocator, .{ .max_records = 100, .max_bytes = 8 }, .reject_new);
    defer bounded.deinit();
    try std.testing.expect(try bounded.enqueue("12345678"));
    try std.testing.expect(!try bounded.enqueue("x"));
    // And a record larger than the whole budget is refused rather than emptying the
    // queue in a doomed attempt to fit it.
    try std.testing.expect(!try bounded.enqueue("123456789"));
}

test "shutdown reports what could not be delivered" {
    var destination = FlakySink{ .allocator = std.testing.allocator };
    defer destination.deinit();
    const writer = SerialWriter{ .sink = destination.sink() };

    var queue = DeliveryQueue.init(std.testing.allocator, .{}, .reject_new);
    defer queue.deinit();
    _ = try queue.enqueue("final");

    // A destination that is still down at shutdown: the count is the answer to
    // "how many did we lose", which a caller can log rather than discover later.
    destination.failing = true;
    try std.testing.expectEqual(@as(usize, 1), queue.shutdown(writer));

    destination.failing = false;
    try std.testing.expectEqual(@as(usize, 0), queue.shutdown(writer));
    try std.testing.expectEqualStrings("final\n", destination.buffer.items);
}
