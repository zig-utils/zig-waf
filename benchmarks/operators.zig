const std = @import("std");
const waf = @import("waf");
const operators = waf.operators;

const iterations = 500_000;

fn timeScalar(io: std.Io, kind: operators.Kind, parameter: []const u8, input: []const u8) u64 {
    const start = std.Io.Clock.now(.awake, io);
    for (0..iterations) |_| {
        std.mem.doNotOptimizeAway(operators.evaluate(kind, .coraza, parameter, input));
    }
    const elapsed: u64 = @intCast(start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    return elapsed / iterations;
}

fn timeRx(io: std.Io, worker: *operators.RegexOperator.Worker, input: []const u8) u64 {
    const start = std.Io.Clock.now(.awake, io);
    for (0..iterations) |_| {
        const outcome = worker.evaluate(input);
        std.mem.doNotOptimizeAway(outcome.matched);
        std.mem.doNotOptimizeAway(outcome.captures[0].ptr);
    }
    const elapsed: u64 = @intCast(start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    return elapsed / iterations;
}

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // A fast, thread-safe general-purpose allocator models the shared compiled
    // program's transient capture storage; page_allocator would mmap per match.
    const allocator = std.heap.smp_allocator;

    // Scalar comparison operators over representative CRS-style values.
    const eq_ns = timeScalar(io, .eq, "400", "404");
    const ge_ns = timeScalar(io, .ge, "5", "12");
    const contains_ns = timeScalar(io, .contains, "../", "/var/www/../../etc/passwd");
    const begins_ns = timeScalar(io, .begins_with, "/api/", "/api/v1/search");
    const within_ns = timeScalar(io, .within, "GET POST PUT DELETE HEAD OPTIONS", "GET");
    const word_ns = timeScalar(io, .contains_word, "select", "1 union select password from users");

    // Regex match and capture over a CRS-like argument.
    var rx = try operators.RegexOperator.compile(allocator, "(?:union|select|insert)\\s+([a-z*]+)");
    defer rx.deinit();
    var rx_worker = rx.worker();
    defer rx_worker.deinit();
    const rx_match_ns = timeRx(io, &rx_worker, "1 union select password from users");
    const rx_miss_ns = timeRx(io, &rx_worker, "a perfectly ordinary sentence with words");

    // rxGlobal over an input with several matches.
    var rxg_worker = rx.worker();
    defer rxg_worker.deinit();
    const rxg_start = std.Io.Clock.now(.awake, io);
    for (0..iterations) |_| {
        const outcome = rxg_worker.evaluateGlobal(allocator, "select a union select b insert c");
        std.mem.doNotOptimizeAway(outcome.match_count);
    }
    const rxg_elapsed: u64 = @intCast(rxg_start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    const rxg_ns = rxg_elapsed / iterations;

    // Memoized rx: the same input repeats, so all but the first are cache hits.
    var memo_worker = rx.workerWithMemo(allocator, .{});
    defer memo_worker.deinit();
    const memo_ns = timeRx(io, &memo_worker, "1 union select password from users");
    const memo_stats = memo_worker.memoStats();

    std.debug.print(
        "operators iterations={d}" ++
            " eq_ns={d} ge_ns={d} contains_ns={d} begins_with_ns={d} within_ns={d} contains_word_ns={d}" ++
            " rx_match_ns={d} rx_miss_ns={d} rx_global_ns={d}" ++
            " rx_memoized_ns={d} memo_hits={d} memo_entries={d}\n",
        .{
            iterations,
            eq_ns,
            ge_ns,
            contains_ns,
            begins_ns,
            within_ns,
            word_ns,
            rx_match_ns,
            rx_miss_ns,
            rxg_ns,
            memo_ns,
            memo_stats.hits,
            memo_stats.entries,
        },
    );
}
