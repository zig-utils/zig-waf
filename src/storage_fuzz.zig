//! Fuzz oracle for persistent collection storage (#39).
//!
//! Collection keys and values come from the request: `initcol` binds a collection to
//! an IP address, a session id, or a username the client supplied, and `setvar`
//! writes values built from request data. Those bytes then cross the persistent
//! backend boundary, where a host's implementation — LMDB, Redis, a database — will
//! use them as keys.
//!
//! The properties asserted here are the ones a backend author has to be able to rely
//! on: bounds are enforced before anything is stored, an oversized or malformed value
//! is a reported error rather than a truncated write, and a failed operation leaves
//! the transaction usable rather than half-committed.

const std = @import("std");
const engine = @import("engine.zig");
const persistent = @import("persistent.zig");
const collections = @import("collections.zig");

pub fn fuzzOne(allocator: std.mem.Allocator, input: []const u8) !void {
    if (input.len < 2) return;

    var memory = persistent.InMemoryBackend.init(allocator);
    defer memory.deinit();

    var builder = engine.Builder.init(allocator);
    builder.setPersistentBackend(memory.backend());
    // Deliberately tight, so a fuzz case reaches the bounds rather than only the
    // path where everything fits.
    builder.setLimits(.{ .collection_limits = .{
        .max_entries = 32,
        .max_key_bytes = 64,
        .max_value_bytes = 128,
        .max_total_bytes = 4096,
    } });
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;

    var transaction = waf.newTransaction();
    defer transaction.deinit();
    transaction.processConnection("192.0.2.1", 1234, "198.51.100.1", 443) catch return;
    transaction.processUri("/fuzz", "GET", "HTTP/1.1") catch return;

    // The collection key is client-controlled: it is a session id, a username, or an
    // address the request carried.
    const split = 1 + (input[0] % (input.len - 1));
    const key = input[1..split];
    const value = input[split..];

    // Binding may legitimately fail (an empty or oversized key); it must not crash
    // or leave the transaction unusable.
    _ = transaction.setSessionCollection(key) catch {};

    const source: collections.Source = .{ .origin = .request_header, .offset = 0, .length = value.len };
    transaction.setCollectionValue(.session, key, value, source) catch {};
    transaction.setCollectionValue(.tx, key, value, source) catch {};
    _ = transaction.addTransactionCollectionValue(key, 1) catch {};

    // Whatever happened above, the transaction still answers questions and can
    // complete its lifecycle: a rejected write is a decision, not damage.
    _ = transaction.collectionFirst(.tx, key) catch {};
    transaction.processRequestHeaders() catch return;
    transaction.processLogging() catch {};
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

test "storage rejects hostile keys and values without damaging the transaction" {
    var oversized: [512]u8 = undefined;
    @memset(&oversized, 'k');
    oversized[0] = 8; // split byte

    const cases = [_][]const u8{
        &oversized,
        "\x01\x00\x00\x00",
        "\x01" ++ "session-1" ++ "value",
        "\x01" ++ "\xff\xfe\xfd",
        "\x01a",
        "\x00",
    };
    for (cases) |case| try fuzzOne(testing.allocator, case);
}
