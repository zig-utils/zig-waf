const std = @import("std");
const waf = @import("waf");
const request = waf.request;

const iterations = 1_000_000;

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var scratch: [256]u8 = undefined;

    // A representative CRS-style query string with encoded and plain arguments.
    const query = "q=zig+lang&id=42&path=%2Fetc%2Fpasswd&name=%41lice&flag&empty=";
    const query_start = std.Io.Clock.now(.awake, io);
    var query_pairs: usize = 0;
    for (0..iterations) |_| {
        var it = request.parseQuery(query, request.default_separator);
        while (it.next()) |pair| {
            const key = request.queryUnescape(&scratch, pair.key);
            const value = request.queryUnescape(scratch[key.len..], pair.value);
            std.mem.doNotOptimizeAway(key.ptr);
            std.mem.doNotOptimizeAway(value.ptr);
            query_pairs += 1;
        }
    }
    const query_elapsed: u64 = @intCast(query_start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    const query_ns = query_elapsed / iterations;

    // A Cookie header with several pairs.
    const cookie = "SESSION=abcdef0123456789; theme=dark; consent=1; _ga=GA1.2.3.4; flag";
    const cookie_start = std.Io.Clock.now(.awake, io);
    var cookie_pairs: usize = 0;
    for (0..iterations) |_| {
        var it = request.parseCookies(cookie);
        while (it.next()) |pair| {
            std.mem.doNotOptimizeAway(pair.key.ptr);
            std.mem.doNotOptimizeAway(pair.value.ptr);
            cookie_pairs += 1;
        }
    }
    const cookie_elapsed: u64 = @intCast(cookie_start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    const cookie_ns = cookie_elapsed / iterations;

    std.debug.print(
        "request iterations={d} query_parse_ns={d} query_pairs={d} cookie_parse_ns={d} cookie_pairs={d}\n",
        .{ iterations, query_ns, query_pairs / iterations, cookie_ns, cookie_pairs / iterations },
    );
}
