//! W3C Trace Context for correlating a WAF decision with the request it belongs to
//! (#32).
//!
//! A blocked request is one event in a system that produced many. What makes the WAF's
//! record useful is that it names the same trace as the proxy's access log and the
//! application's error — so "why did this user's checkout fail" is one query rather
//! than three timestamps and a guess.
//!
//! The trace context arrives in a request header, which means it arrives from the
//! client. That single fact shapes everything here:
//!
//! - **Parsing is strict.** A `traceparent` is 55 bytes in one exact shape. Anything
//!   else is rejected rather than repaired, because a lenient parser turns attacker
//!   input into trace identifiers that reach a tracing backend.
//! - **All-zero identifiers are invalid**, per the specification. They are the one
//!   value a naive generator produces on failure, and accepting them would collapse
//!   unrelated requests into a single trace that appears to be one operation.
//! - **A rejected header is not propagated.** When the incoming context is unusable
//!   the WAF starts a new trace instead of forwarding something malformed, so a client
//!   cannot inject a trace id of its choosing into the backend that collects them.
//!
//! This module carries and validates identifiers. It does not export them: OTLP is a
//! network protocol, and a blocking export in the request path is exactly the cost a
//! WAF must not add. The host drains spans and ships them.

const std = @import("std");

/// A 16-byte trace identifier, shared by every span in one trace.
pub const TraceId = [16]u8;
/// An 8-byte span identifier, unique within a trace.
pub const SpanId = [8]u8;

/// The length of a rendered `traceparent`: `00-<32 hex>-<16 hex>-<2 hex>`.
pub const traceparent_len = 55;

pub const Error = error{
    /// The header is not a well-formed version-00 traceparent.
    MalformedTraceparent,
    RandomFailed,
};

/// A trace context: which trace, which span within it, and whether it is sampled.
pub const Context = struct {
    trace_id: TraceId,
    span_id: SpanId,
    /// The `traceparent` flags byte. Bit 0 is "sampled"; the rest are reserved and
    /// carried through unchanged, because a receiver that understands a future flag
    /// should still see it.
    flags: u8 = 0,

    pub fn sampled(self: Context) bool {
        return self.flags & 0x01 != 0;
    }

    /// Render as a `traceparent` header value.
    pub fn writeTraceparent(self: Context, out: *[traceparent_len]u8) void {
        out[0] = '0';
        out[1] = '0';
        out[2] = '-';
        writeHex(out[3..35], &self.trace_id);
        out[35] = '-';
        writeHex(out[36..52], &self.span_id);
        out[52] = '-';
        writeHex(out[53..55], &[_]u8{self.flags});
    }

    /// A child span in the same trace: same trace id, a fresh span id, same flags.
    ///
    /// Sampling is inherited rather than re-decided. A WAF that sampled independently
    /// would produce spans whose parents are missing, which is worse than not tracing:
    /// a trace with holes reads as a system that lost the request.
    pub fn child(self: Context, io: std.Io) Error!Context {
        return .{
            .trace_id = self.trace_id,
            .span_id = try generateSpanId(io),
            .flags = self.flags,
        };
    }
};

/// Parse a `traceparent` header value.
///
/// Only version `00` is accepted. The specification says a future version's extra
/// fields may be ignored, but a WAF has no reason to guess at a format it does not
/// know: refusing means starting a fresh trace, which is correct and traceable, while
/// guessing means emitting identifiers that may not mean what they appear to.
pub fn parseTraceparent(header: []const u8) Error!Context {
    if (header.len != traceparent_len) return error.MalformedTraceparent;
    if (header[0] != '0' or header[1] != '0') return error.MalformedTraceparent;
    if (header[2] != '-' or header[35] != '-' or header[52] != '-') return error.MalformedTraceparent;

    var context: Context = .{ .trace_id = undefined, .span_id = undefined };
    try readHex(&context.trace_id, header[3..35]);
    try readHex(&context.span_id, header[36..52]);
    var flags: [1]u8 = undefined;
    try readHex(&flags, header[53..55]);
    context.flags = flags[0];

    // An all-zero identifier is invalid per the specification. It is also what a
    // broken generator emits, so accepting it would merge unrelated requests into one
    // trace that looks like a single operation.
    if (isZero(&context.trace_id) or isZero(&context.span_id)) return error.MalformedTraceparent;
    return context;
}

/// The context to use for a request: the incoming one when it is valid, otherwise a
/// fresh trace.
///
/// `inherited` reports which happened. A caller needs to know: a span whose parent was
/// discarded is a root span, and reporting it as a child would leave a dangling parent
/// reference in the backend.
pub const Resolution = struct {
    context: Context,
    inherited: bool,
};

/// Continue the incoming trace, or start a new one when the header is absent or
/// unusable.
///
/// This is the function a connector calls. It never fails on bad input — a malformed
/// header is a reason to start a new trace, not to fail the request, because a WAF
/// that rejects traffic over a tracing header has turned observability into an outage.
pub fn resolve(header: ?[]const u8, io: std.Io) Error!Resolution {
    if (header) |value| {
        if (parseTraceparent(value)) |parent| {
            return .{ .context = try parent.child(io), .inherited = true };
        } else |_| {
            // Deliberately falls through to a new trace: the alternative is
            // propagating a value a client chose the shape of.
        }
    }
    return .{ .context = try newTrace(io), .inherited = false };
}

/// A brand-new trace with a fresh trace and span id.
pub fn newTrace(io: std.Io) Error!Context {
    var context: Context = .{
        .trace_id = undefined,
        .span_id = undefined,
        // Sampled: a WAF that starts a trace does so because something happened worth
        // recording, and an unsampled decision is one nobody can look up afterwards.
        .flags = 0x01,
    };
    io.randomSecure(&context.trace_id) catch return error.RandomFailed;
    context.span_id = try generateSpanId(io);
    // Astronomically unlikely, but an all-zero id is invalid and silently emitting one
    // would be worse than the retry costs.
    if (isZero(&context.trace_id)) context.trace_id[0] = 1;
    return context;
}

fn generateSpanId(io: std.Io) Error!SpanId {
    var span: SpanId = undefined;
    io.randomSecure(&span) catch return error.RandomFailed;
    if (isZero(&span)) span[0] = 1;
    return span;
}

fn isZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

fn writeHex(out: []u8, bytes: []const u8) void {
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        out[index * 2] = digits[byte >> 4];
        out[index * 2 + 1] = digits[byte & 0x0f];
    }
}

/// Decode lowercase hex. Uppercase is refused: the specification requires lowercase,
/// and accepting both would make two spellings of one identifier compare unequal
/// wherever the raw header text is used as a key.
fn readHex(out: []u8, text: []const u8) Error!void {
    if (text.len != out.len * 2) return error.MalformedTraceparent;
    for (out, 0..) |*byte, index| {
        const high = try hexDigit(text[index * 2]);
        const low = try hexDigit(text[index * 2 + 1]);
        byte.* = (high << 4) | low;
    }
}

fn hexDigit(character: u8) Error!u8 {
    return switch (character) {
        '0'...'9' => character - '0',
        'a'...'f' => character - 'a' + 10,
        else => error.MalformedTraceparent,
    };
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

test "a well-formed traceparent round-trips" {
    const header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const context = try parseTraceparent(header);
    try testing.expect(context.sampled());
    try testing.expectEqual(@as(u8, 0x4b), context.trace_id[0]);
    try testing.expectEqual(@as(u8, 0x36), context.trace_id[15]);
    try testing.expectEqual(@as(u8, 0x00), context.span_id[0]);
    try testing.expectEqual(@as(u8, 0xb7), context.span_id[7]);

    var rendered: [traceparent_len]u8 = undefined;
    context.writeTraceparent(&rendered);
    try testing.expectEqualStrings(header, &rendered);
}

test "a malformed traceparent is refused rather than repaired" {
    // Every one of these is something a client can send. A parser that salvaged them
    // would be turning attacker input into identifiers a tracing backend indexes.
    const rejected = [_][]const u8{
        "", // absent
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7", // truncated
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra", // trailing junk
        "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // unknown version
        "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", // uppercase
        "00:4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:01", // wrong separators
        "00-4bf92f3577b34da6a3ce929d0e0e473g-00f067aa0ba902b7-01", // non-hex
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01", // all-zero trace id
        "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // all-zero span id
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0", // short flags
    };
    for (rejected) |header| {
        try testing.expectError(error.MalformedTraceparent, parseTraceparent(header));
    }
}

test "reserved flag bits survive, and sampling is inherited rather than re-decided" {
    // Bit 0 is sampled; the rest are reserved. Carrying them through unchanged is what
    // lets a receiver that understands a future flag still see it.
    const context = try parseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-ff");
    try testing.expectEqual(@as(u8, 0xff), context.flags);
    try testing.expect(context.sampled());

    const unsampled = try parseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00");
    try testing.expect(!unsampled.sampled());

    // A child keeps the trace and the sampling decision, and takes a new span id. A
    // WAF that re-decided sampling would emit spans whose parents are missing, and a
    // trace with holes reads as a system that lost the request.
    const io = std.testing.io;
    const descendant = try unsampled.child(io);
    try testing.expectEqualSlices(u8, &unsampled.trace_id, &descendant.trace_id);
    try testing.expectEqual(unsampled.flags, descendant.flags);
    try testing.expect(!std.mem.eql(u8, &unsampled.span_id, &descendant.span_id));
    try testing.expect(!isZero(&descendant.span_id));
}

test "resolving continues a valid trace and starts a fresh one otherwise" {
    const io = std.testing.io;
    const header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    const continued = try resolve(header, io);
    try testing.expect(continued.inherited);
    const parent = try parseTraceparent(header);
    try testing.expectEqualSlices(u8, &parent.trace_id, &continued.context.trace_id);
    // The WAF's span is its own, not the caller's.
    try testing.expect(!std.mem.eql(u8, &parent.span_id, &continued.context.span_id));

    // An absent header starts a new trace, and says so — a span whose parent was
    // discarded is a root span, and reporting it as a child would leave a dangling
    // parent reference.
    const fresh = try resolve(null, io);
    try testing.expect(!fresh.inherited);
    try testing.expect(!isZero(&fresh.context.trace_id));
    try testing.expect(fresh.context.sampled());

    // A malformed header is a reason to start a new trace, not to fail the request:
    // rejecting traffic over a tracing header would turn observability into an outage.
    const poisoned = try resolve("00-00000000000000000000000000000000-0000000000000000-00", io);
    try testing.expect(!poisoned.inherited);
    try testing.expect(!isZero(&poisoned.context.trace_id));
    // And nothing the client sent survives into the new context.
    try testing.expect(!isZero(&poisoned.context.span_id));

    // Two fresh traces differ, so requests are not correlated with each other.
    const other = try resolve(null, io);
    try testing.expect(!std.mem.eql(u8, &fresh.context.trace_id, &other.context.trace_id));
}
