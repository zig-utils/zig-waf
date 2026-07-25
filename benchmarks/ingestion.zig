//! Compares the two event-ingestion paths (#55) at the batch sizes a node
//! actually drains: a statement per event against a single COPY stream. This is
//! the evidence behind `EventSpool`'s choice between them.
//!
//! Needs a live PostgreSQL: `PG_TEST_DSN=… zig build bench-ingestion`. Each
//! measurement runs against its own schema, dropped afterwards, so it never
//! touches a real fleet database.

const std = @import("std");
const fleet = @import("fleet");
const pg = fleet.pg;

const batch_sizes = [_]usize{ 1, 4, 16, 24, 32, 48, 64, 256, 1024 };
/// Enough repetitions that a single slow commit does not decide the result.
const repeats = 20;

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const raw = std.c.getenv("PG_TEST_DSN") orelse {
        std.debug.print("ingestion benchmark skipped: PG_TEST_DSN is unset\n", .{});
        return;
    };
    const dsn_value = std.mem.span(raw);
    const schema = "waf_bench_ingestion";
    const dsn = try allocator.printSentinel(
        "{s} options='-csearch_path={s} -cclient_min_messages=warning'",
        .{ dsn_value, schema },
        0,
    );

    var conn = try pg.Conn.open(dsn);
    defer conn.close();
    try conn.exec("DROP SCHEMA IF EXISTS " ++ schema ++ " CASCADE");
    try conn.exec("CREATE SCHEMA " ++ schema);
    defer conn.exec("DROP SCHEMA IF EXISTS " ++ schema ++ " CASCADE") catch {};
    _ = try fleet.apply(&conn, allocator);

    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const events = fleet.EventRepository{ .conn = &conn };
    for (batch_sizes) |size| {
        const per_statement = try measure(allocator, io, events, size, .per_statement);
        const copied = try measure(allocator, io, events, size, .copy);
        std.debug.print(
            "ingestion batch={d:>4} repeats={d} per_statement_us_per_event={d:>6} copy_us_per_event={d:>6} speedup={d:.2}x\n",
            .{
                size,
                repeats,
                per_statement / (size * repeats * std.time.ns_per_us),
                copied / (size * repeats * std.time.ns_per_us),
                @as(f64, @floatFromInt(per_statement)) / @as(f64, @floatFromInt(copied)),
            },
        );
    }
}

const Path = enum { per_statement, copy };

/// Total nanoseconds to ingest `repeats` batches of `size` events. Keys are
/// unique per batch and path, so no measurement is shortened by deduplication.
fn measure(
    allocator: std.mem.Allocator,
    io: std.Io,
    events: fleet.EventRepository,
    size: usize,
    path: Path,
) !u64 {
    const batch = try allocator.alloc(fleet.Event, size);
    defer allocator.free(batch);

    var elapsed: u64 = 0;
    for (0..repeats) |repeat| {
        for (batch, 0..) |*slot, index| {
            // Distinct timestamps and keys keep every event a new row.
            const second = (repeat * size + index) % 60;
            const minute = ((repeat * size + index) / 60) % 60;
            slot.* = .{
                .node_id = "88888888-8888-8888-8888-888888888888",
                .occurred_at = try allocator.printSentinel("2024-06-01T00:{d:0>2}:{d:0>2}Z", .{ minute, second }, 0),
                .action = "deny",
                .uri = "/benchmark?id=1",
                .message = "SQL injection detected",
                .key = try allocator.printSentinel("{s}-{d}-{d}-{d}", .{ @tagName(path), size, repeat, index }, 0),
            };
        }

        const start = std.Io.Clock.now(.awake, io);
        switch (path) {
            .per_statement => _ = try events.recordBatch(batch),
            .copy => _ = try events.recordBatchCopy(allocator, batch),
        }
        elapsed += @intCast(start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    }
    return elapsed;
}
