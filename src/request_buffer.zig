//! Bounded request-body buffering with disk spooling.
//!
//! Bytes accumulate in a transaction-owned in-memory buffer up to
//! `in_memory_limit`; beyond it the overflow is streamed to a caller-provided
//! `Sink` (the engine backs this with a temp file, tests with memory), so a
//! large body never forces an unbounded allocation. A hard `total_limit` caps
//! the whole body; on overflow the configured `Policy` either rejects the
//! request or truncates and processes the partial body. The buffer never blocks
//! and performs no I/O of its own — the sink owns any file handles and cleanup.

const std = @import("std");

pub const Policy = enum {
    /// Reject the request when the total limit is exceeded.
    reject,
    /// Truncate at the limit and inspect the partial body.
    process_partial,
};

pub const Limits = struct {
    /// Bytes kept in memory before overflow spills to the sink.
    in_memory_limit: usize = 128 * 1024,
    /// Hard cap on total accepted body bytes.
    total_limit: usize = 16 * 1024 * 1024,

    pub fn validate(self: Limits) error{InvalidLimits}!void {
        // in_memory_limit may exceed total_limit; the total cap simply triggers
        // first, keeping the whole (small) body in memory.
        if (self.total_limit == 0) return error.InvalidLimits;
    }
};

pub const SinkError = error{ SinkWriteFailed, DiskExhausted };

/// Overflow destination for spilled bytes (a temp file in production).
pub const Sink = struct {
    context: *anyopaque,
    writeFn: *const fn (context: *anyopaque, bytes: []const u8) SinkError!void,

    fn write(self: Sink, bytes: []const u8) SinkError!void {
        return self.writeFn(self.context, bytes);
    }
};

pub const Status = enum {
    /// Entirely in memory.
    buffering,
    /// Overflow has spilled to the sink.
    spooled,
    /// The total limit was hit and the request is rejected.
    rejected,
    /// The total limit was hit and the body was truncated for partial inspection.
    truncated,
};

pub const WriteError = std.mem.Allocator.Error || SinkError || error{ InvalidLimits, BodyLimitRejected };

/// A `Sink` backed by a file the caller opened, for spooling an oversized body or
/// an uploaded file to disk (#25).
///
/// The engine never opens this itself. Spooling is deliberately the connector's
/// job: the request path must not block on a filesystem, and where uploads may be
/// written (`SecUploadDir`/`SecTmpDir`), with what permissions, and whether they
/// survive the transaction (`SecUploadKeepFiles`) are deployment decisions the WAF
/// core has no business making. This type exists so a connector does not have to
/// reimplement the boundary — it owns the handle, counts what it wrote, and
/// reports disk exhaustion as such rather than as a generic failure.
pub const FileSink = struct {
    io: std.Io,
    file: std.Io.File,
    written: u64 = 0,
    /// A ceiling of its own, so a body that slipped past the buffer's limits — or a
    /// misconfigured limit — cannot fill the disk.
    max_bytes: u64,

    pub fn init(io: std.Io, file: std.Io.File, max_bytes: u64) FileSink {
        return .{ .io = io, .file = file, .max_bytes = max_bytes };
    }

    pub fn sink(self: *FileSink) Sink {
        return .{ .context = self, .writeFn = writeThrough };
    }

    fn writeThrough(context: *anyopaque, bytes: []const u8) SinkError!void {
        const self: *FileSink = @ptrCast(@alignCast(context));
        if (bytes.len > self.max_bytes - self.written) return error.DiskExhausted;
        // Positional writes at the running offset: the sink owns the file's
        // position, so a caller sharing the handle cannot interleave into the body.
        self.file.writePositionalAll(self.io, bytes, self.written) catch |err| return switch (err) {
            // A full filesystem is the failure worth naming: it is operational, not
            // a bug in the request, and an operator needs to tell them apart.
            error.NoSpaceLeft, error.DiskQuota => error.DiskExhausted,
            else => error.SinkWriteFailed,
        };
        self.written += bytes.len;
    }
};

pub const Buffer = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    policy: Policy,
    sink: ?Sink,
    memory: std.ArrayList(u8) = .empty,
    /// Bytes handed to the sink (spilled beyond the in-memory limit).
    spilled_bytes: usize = 0,
    /// Total bytes accepted into the body (memory + spilled), never exceeding
    /// `total_limit`.
    total_bytes: usize = 0,
    status: Status = .buffering,

    pub fn init(allocator: std.mem.Allocator, limits: Limits, policy: Policy, sink: ?Sink) error{InvalidLimits}!Buffer {
        try limits.validate();
        return .{ .allocator = allocator, .limits = limits, .policy = policy, .sink = sink };
    }

    pub fn deinit(self: *Buffer) void {
        self.memory.deinit(self.allocator);
        self.* = undefined;
    }

    /// Append one body chunk. Returns `error.BodyLimitRejected` under the reject
    /// policy once the total limit would be exceeded; under process-partial it
    /// truncates silently and reports `truncated` via `status`.
    pub fn write(self: *Buffer, chunk: []const u8) WriteError!void {
        if (self.status == .rejected) return error.BodyLimitRejected;
        if (self.status == .truncated) return;

        var remaining = chunk;
        // Enforce the hard total limit.
        const capacity = self.limits.total_limit - self.total_bytes;
        if (remaining.len > capacity) {
            switch (self.policy) {
                .reject => {
                    self.status = .rejected;
                    return error.BodyLimitRejected;
                },
                .process_partial => {
                    remaining = remaining[0..capacity];
                    self.status = .truncated;
                },
            }
        }
        if (remaining.len == 0) return;

        // Fill the in-memory portion first, then spill the rest to the sink.
        const memory_capacity = self.limits.in_memory_limit - self.memory.items.len;
        const to_memory = @min(remaining.len, memory_capacity);
        if (to_memory != 0) {
            try self.memory.appendSlice(self.allocator, remaining[0..to_memory]);
        }
        const overflow = remaining[to_memory..];
        if (overflow.len != 0) {
            const sink = self.sink orelse return error.SinkWriteFailed;
            try sink.write(overflow);
            self.spilled_bytes += overflow.len;
            if (self.status != .truncated) self.status = .spooled;
        }
        self.total_bytes += remaining.len;
    }

    /// The in-memory portion of the body. When `isSpooled()` is false this is
    /// the complete body; otherwise it is the leading `in_memory_limit` bytes.
    pub fn inMemory(self: *const Buffer) []const u8 {
        return self.memory.items;
    }

    pub fn isSpooled(self: *const Buffer) bool {
        return self.spilled_bytes != 0;
    }

    pub fn wasTruncated(self: *const Buffer) bool {
        return self.status == .truncated;
    }
};

// ---- tests --------------------------------------------------------------

const MemorySink = struct {
    bytes: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,
    fail_after: ?usize = null,
    written: usize = 0,

    fn sink(self: *MemorySink) Sink {
        return .{ .context = self, .writeFn = write };
    }
    fn write(context: *anyopaque, bytes: []const u8) SinkError!void {
        const self: *MemorySink = @ptrCast(@alignCast(context));
        if (self.fail_after) |limit| {
            if (self.written + bytes.len > limit) return error.DiskExhausted;
        }
        self.bytes.appendSlice(self.allocator, bytes) catch return error.SinkWriteFailed;
        self.written += bytes.len;
    }
    fn deinit(self: *MemorySink) void {
        self.bytes.deinit(self.allocator);
    }
};

test "small body stays entirely in memory" {
    var buffer = try Buffer.init(std.testing.allocator, .{ .in_memory_limit = 64, .total_limit = 1024 }, .reject, null);
    defer buffer.deinit();
    try buffer.write("hello ");
    try buffer.write("world");
    try std.testing.expect(!buffer.isSpooled());
    try std.testing.expectEqualStrings("hello world", buffer.inMemory());
    try std.testing.expectEqual(@as(usize, 11), buffer.total_bytes);
}

test "overflow beyond the in-memory limit spills to the sink" {
    var mem_sink = MemorySink{ .allocator = std.testing.allocator };
    defer mem_sink.deinit();
    var buffer = try Buffer.init(std.testing.allocator, .{ .in_memory_limit = 4, .total_limit = 1024 }, .reject, mem_sink.sink());
    defer buffer.deinit();

    try buffer.write("abcdefgh");
    try std.testing.expect(buffer.isSpooled());
    try std.testing.expectEqualStrings("abcd", buffer.inMemory());
    try std.testing.expectEqualStrings("efgh", mem_sink.bytes.items);
    try std.testing.expectEqual(@as(usize, 8), buffer.total_bytes);
    try std.testing.expectEqual(Status.spooled, buffer.status);
}

test "reject policy rejects at the total limit" {
    var buffer = try Buffer.init(std.testing.allocator, .{ .in_memory_limit = 16, .total_limit = 8 }, .reject, null);
    defer buffer.deinit();
    try buffer.write("1234");
    try std.testing.expectError(error.BodyLimitRejected, buffer.write("567890"));
    try std.testing.expectEqual(Status.rejected, buffer.status);
    // Further writes keep rejecting.
    try std.testing.expectError(error.BodyLimitRejected, buffer.write("x"));
}

test "process-partial policy truncates at the total limit" {
    var buffer = try Buffer.init(std.testing.allocator, .{ .in_memory_limit = 16, .total_limit = 8 }, .process_partial, null);
    defer buffer.deinit();
    try buffer.write("1234");
    try buffer.write("567890"); // only "5678" is accepted
    try std.testing.expect(buffer.wasTruncated());
    try std.testing.expectEqualStrings("12345678", buffer.inMemory());
    try std.testing.expectEqual(@as(usize, 8), buffer.total_bytes);
    // Post-truncation writes are ignored, not errors.
    try buffer.write("more");
    try std.testing.expectEqual(@as(usize, 8), buffer.total_bytes);
}

test "disk exhaustion surfaces as a distinct error" {
    var mem_sink = MemorySink{ .allocator = std.testing.allocator, .fail_after = 2 };
    defer mem_sink.deinit();
    var buffer = try Buffer.init(std.testing.allocator, .{ .in_memory_limit = 2, .total_limit = 1024 }, .reject, mem_sink.sink());
    defer buffer.deinit();
    try std.testing.expectError(error.DiskExhausted, buffer.write("abcdef"));
}

test "random write sequences never leak or exceed the total limit" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE1234);
    const random = prng.random();
    var chunk: [128]u8 = undefined;
    var iteration: usize = 0;
    while (iteration < 3000) : (iteration += 1) {
        const policy: Policy = if (iteration % 2 == 0) .reject else .process_partial;
        const in_memory = random.uintLessThan(usize, 64) + 1;
        const total = random.uintLessThan(usize, 256) + 1;
        var mem_sink = MemorySink{ .allocator = std.testing.allocator };
        defer mem_sink.deinit();
        var buffer = try Buffer.init(std.testing.allocator, .{ .in_memory_limit = in_memory, .total_limit = total }, policy, mem_sink.sink());
        defer buffer.deinit();

        var writes: usize = 0;
        while (writes < 20) : (writes += 1) {
            const len = random.uintLessThan(usize, chunk.len + 1);
            random.bytes(chunk[0..len]);
            buffer.write(chunk[0..len]) catch |err| switch (err) {
                error.BodyLimitRejected => break, // reject policy terminates the body
                else => return err,
            };
        }
        // The invariant: total accepted bytes never exceed the total limit, and
        // the in-memory portion never exceeds the in-memory limit.
        try std.testing.expect(buffer.total_bytes <= total);
        try std.testing.expect(buffer.inMemory().len <= in_memory);
        try std.testing.expectEqual(buffer.total_bytes, buffer.inMemory().len + mem_sink.written);
    }
}

test "a zero total limit is rejected" {
    try std.testing.expectError(error.InvalidLimits, Buffer.init(std.testing.allocator, .{ .total_limit = 0 }, .reject, null));
    // in_memory_limit above total_limit is valid — the total cap triggers first.
    var buffer = try Buffer.init(std.testing.allocator, .{ .in_memory_limit = 100, .total_limit = 50 }, .reject, null);
    buffer.deinit();
}

test "a file sink spools the overflow and bounds what it writes" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile(io, "spool.bin", .{ .read = true });
    defer file.close(io);
    var file_sink = FileSink.init(io, file, 1024);

    var buffer = try Buffer.init(std.testing.allocator, .{ .in_memory_limit = 8, .total_limit = 64 }, .process_partial, file_sink.sink());
    defer buffer.deinit();

    try buffer.write("0123456789ABCDEF");
    // The first eight bytes stay in memory; the rest went to the file, and the body
    // is marked spooled so a processor knows it is not looking at the whole thing.
    try std.testing.expectEqualStrings("01234567", buffer.inMemory());
    try std.testing.expect(buffer.isSpooled());
    try std.testing.expectEqual(@as(usize, 8), buffer.spilled_bytes);
    try std.testing.expectEqual(@as(u64, 8), file_sink.written);

    const spooled = try tmp.dir.readFileAlloc(io, "spool.bin", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(spooled);
    try std.testing.expectEqualStrings("89ABCDEF", spooled);

    // The sink has a ceiling of its own, so a misconfigured buffer limit cannot
    // fill the disk through it.
    var small = try tmp.dir.createFile(io, "small.bin", .{});
    defer small.close(io);
    var bounded = FileSink.init(io, small, 4);
    var bounded_buffer = try Buffer.init(std.testing.allocator, .{ .in_memory_limit = 0, .total_limit = 64 }, .process_partial, bounded.sink());
    defer bounded_buffer.deinit();
    try bounded_buffer.write("abcd");
    try std.testing.expectError(error.DiskExhausted, bounded_buffer.write("efgh"));
}
