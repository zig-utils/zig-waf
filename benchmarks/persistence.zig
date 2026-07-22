const std = @import("std");
const waf = @import("waf");

const iterations = 20_000;

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var plain_builder = waf.Waf.Builder.init(std.heap.page_allocator);
    plain_builder.setIo(io);
    const plain = try plain_builder.build();
    defer plain.deinit() catch unreachable;

    var memory = waf.persistent.InMemoryBackend.init(std.heap.page_allocator);
    defer memory.deinit();
    var persistent_builder = waf.Waf.Builder.init(std.heap.page_allocator);
    persistent_builder.setIo(io);
    persistent_builder.setPersistentBackend(memory.backend());
    persistent_builder.setPersistentLimits(.{ .max_retry_attempts = 64 });
    const persisted = try persistent_builder.build();
    defer persisted.deinit() catch unreachable;

    const plain_start = std.Io.Clock.now(.awake, io);
    for (0..iterations) |_| {
        var tx = plain.newTransaction();
        try lifecycle(&tx);
        try tx.processLogging();
        tx.deinit();
    }
    const plain_elapsed: u64 = @intCast(plain_start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);

    const persistent_start = std.Io.Clock.now(.awake, io);
    for (0..iterations) |_| {
        var tx = persisted.newTransaction();
        try lifecycle(&tx);
        _ = try tx.initializePersistentCollection(.ip, "192.0.2.1");
        try tx.addPersistentCollectionValue(.ip, "counter", 1);
        try tx.processLogging();
        tx.deinit();
    }
    const persistent_elapsed: u64 = @intCast(persistent_start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);

    var result = try memory.backend().load(std.heap.page_allocator, .ip, "192.0.2.1", std.math.maxInt(i64), .{ .max_retry_attempts = 64 });
    defer result.deinit();
    std.debug.print(
        "persistence iterations={d} transaction_bytes={d} no_persistence_ns_per_tx={d} initialized_in_memory_ns_per_tx={d} final_counter={s}\n",
        .{
            iterations,
            @sizeOf(waf.Transaction),
            plain_elapsed / iterations,
            persistent_elapsed / iterations,
            result.values.items[0].value,
        },
    );
}

fn lifecycle(tx: *waf.Transaction) !void {
    try tx.processConnection("192.0.2.1", 54321, "198.51.100.10", 443);
    try tx.processUri("/bench", "GET", "HTTP/1.1");
    try tx.addRequestHeader("host", "waf.example");
    try tx.processRequestHeaders();
}
