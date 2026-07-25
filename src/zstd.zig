//! Zstandard compression for the event-ingestion path (#55): a node's durable
//! queue holds every event it has not yet handed to PostgreSQL, and during an
//! outage that queue is the only copy. Compressed, the same disk budget buys an
//! order of magnitude more retained events, and security events compress well —
//! they repeat node ids, actions, and URI prefixes.
//!
//! Both directions are one-shot over a slice: the snapshot is written and read
//! whole, so there is nothing to stream, and a single frame keeps the on-disk
//! format simple enough to bound every read.

const std = @import("std");
const c = @import("zstd_c");

pub const Error = error{
    OutOfMemory,
    /// The input is not a valid zstd frame, or its declared content size does not
    /// match what it holds — a truncated or tampered snapshot.
    CorruptFrame,
    /// The frame declares more content than the caller is willing to allocate.
    FrameTooLarge,
    /// The frame does not declare its content size, so decompressing it would
    /// need an unbounded loop. `compress` always writes the size.
    UnknownContentSize,
};

/// zstd signals "size not known" and "not a valid frame" through sentinel
/// content sizes. Their C definitions are `0ULL - 1` and `0ULL - 2`, which
/// translate-c renders as overflowing arithmetic that will not compile, so they
/// are restated here as the wrapped values the library actually returns.
const contentsize_unknown: c_ulonglong = std.math.maxInt(c_ulonglong);
const contentsize_error: c_ulonglong = std.math.maxInt(c_ulonglong) - 1;

/// zstd's default level: the ratio is close to the higher levels' on data this
/// repetitive, and it stays fast enough to sit in the ingestion path.
pub const default_level = 3;

/// Compress `input` into a single frame. The caller owns the result.
pub fn compress(allocator: std.mem.Allocator, input: []const u8, level: c_int) Error![]u8 {
    const bound = c.ZSTD_compressBound(input.len);
    const buffer = try allocator.alloc(u8, bound);
    errdefer allocator.free(buffer);
    const written = c.ZSTD_compress(buffer.ptr, buffer.len, input.ptr, input.len, level);
    if (c.ZSTD_isError(written) != 0) return error.CorruptFrame;
    // Hand back only what the frame occupies; the bound is generous.
    return allocator.realloc(buffer, written) catch buffer[0..written];
}

/// Decompress a single frame, refusing one that declares more than `max_bytes` of
/// content so a corrupt or hostile header cannot drive a huge allocation. The
/// caller owns the result.
pub fn decompress(allocator: std.mem.Allocator, frame: []const u8, max_bytes: usize) Error![]u8 {
    const declared = c.ZSTD_getFrameContentSize(frame.ptr, frame.len);
    if (declared == contentsize_error) return error.CorruptFrame;
    if (declared == contentsize_unknown) return error.UnknownContentSize;
    if (declared > max_bytes) return error.FrameTooLarge;

    const size: usize = @intCast(declared);
    const buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(buffer);
    const written = c.ZSTD_decompress(buffer.ptr, buffer.len, frame.ptr, frame.len);
    if (c.ZSTD_isError(written) != 0) return error.CorruptFrame;
    // A frame whose content is shorter than it declared is not the frame it
    // claims to be, so it is rejected rather than partially trusted.
    if (written != size) return error.CorruptFrame;
    return buffer;
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

test "compression round-trips and shrinks repetitive event data" {
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(testing.allocator);
    // Shaped like a spooled batch: the same node, action, and URI prefix over and
    // over, which is exactly the redundancy compression is here to remove.
    for (0..500) |index| {
        try raw.print(testing.allocator, "11111111-1111-1111-1111-111111111111\tdeny\t/search?q={d}\tSQL injection detected\n", .{index});
    }

    const frame = try compress(testing.allocator, raw.items, default_level);
    defer testing.allocator.free(frame);
    try testing.expect(frame.len * 10 < raw.items.len);

    const restored = try decompress(testing.allocator, frame, 1 << 20);
    defer testing.allocator.free(restored);
    try testing.expectEqualStrings(raw.items, restored);
}

test "empty input round-trips" {
    const frame = try compress(testing.allocator, "", default_level);
    defer testing.allocator.free(frame);
    const restored = try decompress(testing.allocator, frame, 1 << 20);
    defer testing.allocator.free(restored);
    try testing.expectEqual(@as(usize, 0), restored.len);
}

test "a corrupt, truncated, or oversized frame is rejected" {
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(testing.allocator);
    for (0..50) |index| try raw.print(testing.allocator, "deny /search?q={d}\n", .{index});
    const frame = try compress(testing.allocator, raw.items, default_level);
    defer testing.allocator.free(frame);

    // Not a zstd frame at all.
    try testing.expectError(error.CorruptFrame, decompress(testing.allocator, "not a frame", 1 << 20));
    // A truncated frame: the header still declares the full content size.
    try testing.expectError(error.CorruptFrame, decompress(testing.allocator, frame[0 .. frame.len - 4], 1 << 20));
    // A frame declaring more than the caller will allocate is refused before the
    // allocation, not after it.
    try testing.expectError(error.FrameTooLarge, decompress(testing.allocator, frame, 8));

    // A flipped byte in the payload fails the frame's own checksum rather than
    // decoding to something plausible.
    const tampered = try testing.allocator.dupe(u8, frame);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0xff;
    try testing.expectError(error.CorruptFrame, decompress(testing.allocator, tampered, 1 << 20));
}
