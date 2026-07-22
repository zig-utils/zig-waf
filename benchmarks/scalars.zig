const std = @import("std");
const waf = @import("waf");

const iterations = 100_000;

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var builder = waf.Waf.Builder.init(std.heap.page_allocator);
    builder.setIo(io);
    const engine = try builder.build();
    defer engine.deinit() catch unreachable;

    const start = std.Io.Clock.now(.awake, io);
    for (0..iterations) |_| {
        var tx = engine.newTransaction();
        try tx.processConnection("192.0.2.1", 54321, "198.51.100.10", 443);
        try tx.processUri("/api/search?q=zig", "POST", "HTTP/1.1");
        try tx.addRequestHeader("host", "waf.example");
        try tx.addRequestHeader("authorization", "Bearer token");
        try tx.addRequestHeader("content-type", "application/json");
        try tx.processRequestHeaders();
        try tx.recordMatch("ARGS:q", "zig", 2);
        try tx.writeRequestBody("{\"q\":\"zig\"}");
        try tx.processRequestBody();
        try tx.addResponseHeader("content-type", "application/json");
        try tx.processResponseHeaders(200, "HTTP/1.1");
        try tx.writeResponseBody("{\"ok\":true}");
        try tx.processResponseBody();
        try tx.processLogging();
        std.mem.doNotOptimizeAway((try tx.scalar(.request_line)).?.value);
        std.mem.doNotOptimizeAway((try tx.scalar(.highest_severity)).?.value);
        std.mem.doNotOptimizeAway((try tx.scalar(.duration)).?.value);
        tx.deinit();
    }
    const elapsed: u64 = @intCast(start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);

    std.debug.print(
        "scalar iterations={d} transaction_bytes={d} full_scalar_lifecycle_ns_per_tx={d}\n",
        .{ iterations, @sizeOf(waf.Transaction), elapsed / iterations },
    );
}
