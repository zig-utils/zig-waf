//! Request-path release gate: throughput, tail latency, and peak RSS (#40).
//!
//! A WAF's cost is paid on every request, so the numbers that matter are not an
//! average but the tail — the request that waited behind the slow one — and the
//! memory a process holds after serving traffic. Both are measured here against a
//! real compiled rule set, and both are *gates*: the run fails when a threshold is
//! exceeded, so a regression stops a release rather than being noticed later in a
//! dashboard.
//!
//! Thresholds are supplied by the caller and deliberately generous. A runner's speed
//! varies by several times between a laptop and shared CI, so a tight bound would
//! fail for reasons that have nothing to do with the change under test — and a gate
//! that cries wolf gets disabled. These catch an order-of-magnitude regression: a
//! rule set that started recompiling per request, an allocation that became a leak,
//! a matcher that lost its cache.

const std = @import("std");
const waf = @import("waf");

const rules =
    \\SecRuleEngine On
    \\SecDefaultAction "phase:1,pass,nolog"
    \\SecRule REQUEST_URI "@rx (?i)(union[\s\x0b]+select|drop[\s\x0b]+table)" "id:1,phase:1,deny,status:403,msg:'sqli'"
    \\SecRule ARGS "@detectSQLi" "id:2,phase:1,deny,status:403,msg:'libinjection'"
    \\SecRule ARGS "@pm evil attack malware" "id:3,phase:1,deny,status:403,msg:'phrase'"
    \\SecRule REQUEST_HEADERS:User-Agent "@contains curl" "id:4,phase:1,pass,nolog,setvar:'tx.tool=1'"
    \\SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8,192.168.0.0/16" "id:5,phase:1,pass,nolog"
;

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const iterations = try std.fmt.parseInt(usize, arguments.next() orelse "20000", 10);
    // Zero disables a gate, so the same binary serves both "measure" and "enforce".
    const max_p99_ns = try std.fmt.parseInt(u64, arguments.next() orelse "0", 10);
    const min_throughput = try std.fmt.parseInt(u64, arguments.next() orelse "0", 10);
    const max_rss_bytes = try std.fmt.parseInt(u64, arguments.next() orelse "0", 10);

    const gpa = init.gpa;
    var parsed = try waf.seclang.parser.parseBytes(gpa, "gate.conf", rules, .{}, .{});
    defer parsed.deinit();
    var documents = [_]waf.seclang.parser.Document{parsed.document};
    const plan = try waf.plan.compile(gpa, &parsed.registry, &documents, .{});
    defer plan.deinit();

    var builder = waf.engine.Builder.init(gpa);
    builder.setRetainedPlan(plan);
    const engine = try builder.build();
    defer engine.deinit() catch unreachable;

    const samples = try gpa.alloc(u64, iterations);
    defer gpa.free(samples);

    // A mix of requests: mostly benign, with attacks interleaved, because a gate run
    // on clean traffic alone would not measure the paths that matter — the ones that
    // match, capture, and build an intervention.
    const targets = [_][]const u8{
        "/index.html?page=2",
        "/search?q=hello+world&lang=en",
        "/api/v1/items?id=42&sort=name",
        "/search?q=1%20UNION%20SELECT%20password%20FROM%20users",
        "/profile?name=attack",
    };

    var blocked: usize = 0;
    const started = std.Io.Clock.now(.awake, init.io);
    for (0..iterations) |index| {
        const target = targets[index % targets.len];
        const iteration_start = std.Io.Clock.now(.awake, init.io);

        var transaction = engine.newTransaction();
        defer transaction.deinit();
        try transaction.processConnection("203.0.113.7", 51234, "198.51.100.1", 443);
        try transaction.processUri(target, "GET", "HTTP/1.1");
        try transaction.addRequestHeader("Host", "example.com");
        try transaction.addRequestHeader("User-Agent", "curl/8.4.0");
        try transaction.addRequestHeader("Accept", "*/*");
        try transaction.processRequestHeaders();
        try transaction.evaluatePhase(gpa, .request_headers);
        if ((try transaction.intervention()) != null) blocked += 1;

        samples[index] = @intCast(iteration_start.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);
    }
    const elapsed: u64 = @intCast(started.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);

    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    const p50 = samples[iterations / 2];
    const p99 = samples[(iterations * 99) / 100];
    const p999 = samples[@min((iterations * 999) / 1000, iterations - 1)];
    const throughput = if (elapsed == 0) 0 else (@as(u64, iterations) * std.time.ns_per_s) / elapsed;
    const rss = peakResidentBytes();

    std.debug.print(
        "request path iterations={d} blocked={d} p50_ns={d} p99_ns={d} p999_ns={d} throughput_rps={d} peak_rss_bytes={d}\n",
        .{ iterations, blocked, p50, p99, p999, throughput, rss },
    );

    // A gate run that inspected nothing would pass every threshold, so the mix is
    // checked too: if no request was blocked, the rule set did not run.
    if (blocked == 0) {
        std.debug.print("gate: no request was blocked, so the rule set did not evaluate\n", .{});
        std.process.exit(1);
    }

    var failed = false;
    if (max_p99_ns != 0 and p99 > max_p99_ns) {
        std.debug.print("gate: p99 {d}ns exceeds {d}ns\n", .{ p99, max_p99_ns });
        failed = true;
    }
    if (min_throughput != 0 and throughput < min_throughput) {
        std.debug.print("gate: throughput {d}rps below {d}rps\n", .{ throughput, min_throughput });
        failed = true;
    }
    if (max_rss_bytes != 0 and rss > max_rss_bytes) {
        std.debug.print("gate: peak RSS {d} bytes exceeds {d}\n", .{ rss, max_rss_bytes });
        failed = true;
    }
    if (failed) std.process.exit(1);
}

/// Peak resident set size in bytes. `ru_maxrss` is bytes on Darwin and kilobytes on
/// Linux, which is a difference worth normalizing here rather than in a threshold
/// that would then mean different things on different runners.
fn peakResidentBytes() u64 {
    const usage = std.posix.getrusage(std.posix.rusage.SELF);
    const raw: u64 = @intCast(@max(usage.maxrss, 0));
    return switch (@import("builtin").os.tag) {
        .macos, .ios, .tvos, .watchos => raw,
        else => raw * 1024,
    };
}
