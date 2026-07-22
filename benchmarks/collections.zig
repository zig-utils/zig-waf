const std = @import("std");
const waf = @import("waf");

const iterations = 50_000;

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var builder = waf.Waf.Builder.init(std.heap.page_allocator);
    builder.setIo(io);
    const engine = try builder.build();
    defer engine.deinit() catch unreachable;
    var selector = try waf.selectors.RegexSelector.compile(std.heap.page_allocator, "^(x-request-|content-type$)");
    defer selector.deinit();
    var selector_worker = selector.worker();
    defer selector_worker.deinit();
    var runtime_string = try waf.macros.Compiled.compile(std.heap.page_allocator, "%{REQUEST_METHOD} %{TX.tenant}", .{});
    defer runtime_string.deinit();

    const start = std.Io.Clock.now(.awake, io);
    for (0..iterations) |_| {
        var tx = engine.newTransaction();
        try tx.processConnection("192.0.2.1", 54321, "198.51.100.10", 443);
        try tx.processUri("/api/search?q=zig", "POST", "HTTP/1.1");
        try tx.addRequestHeader("host", "waf.example");
        try tx.addRequestHeader("x-request-id", "request-123");
        try tx.addRequestHeader("content-type", "application/json");
        try tx.processRequestHeaders();
        try tx.setCollectionValue(.tx, "tenant", "north", .{ .origin = .rule, .offset = 0, .length = 5 });
        const target: waf.collections.Target = .{
            .collection = .request_headers,
            .selector = .{ .key_matcher = selector_worker.matcher() },
            .count_only = true,
        };
        std.mem.doNotOptimizeAway((try tx.collectionCount(target, &.{})).?);
        const expanded = try tx.expandMacro(&runtime_string, std.heap.page_allocator);
        std.mem.doNotOptimizeAway(expanded);
        std.heap.page_allocator.free(expanded);
        tx.deinit();
    }
    const elapsed: u64 = @intCast(start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    std.debug.print(
        "collection iterations={d} transaction_bytes={d} target_and_macro_ns_per_tx={d}\n",
        .{ iterations, @sizeOf(waf.Transaction), elapsed / iterations },
    );
}
