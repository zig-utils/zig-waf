const std = @import("std");
const waf = @import("waf");

const iterations = 100_000;

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var builder = waf.Waf.Builder.init(std.heap.page_allocator);
    const direct = try builder.build();

    const direct_start = std.Io.Clock.now(.awake, io);
    for (0..iterations) |_| {
        var transaction = direct.newTransaction();
        transaction.deinit();
    }
    const direct_ns: u64 = @intCast(direct_start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    try direct.deinit();

    const runtime = try builder.buildRuntime();
    const runtime_start = std.Io.Clock.now(.awake, io);
    for (0..iterations) |_| {
        var transaction = try runtime.newTransaction();
        transaction.deinit();
    }
    const runtime_ns: u64 = @intCast(runtime_start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    try runtime.deinit();

    std.debug.print(
        "ownership iterations={d} direct_ns_per_tx={d} runtime_pin_ns_per_tx={d}\n",
        .{ iterations, direct_ns / iterations, runtime_ns / iterations },
    );
}
