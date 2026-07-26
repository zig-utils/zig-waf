//! Request-path metrics in the Prometheus text exposition format (#32).
//!
//! These are the engine's own counters — how much traffic it inspected, how much it
//! acted on, and what it could not do. They are deliberately independent of the
//! control-plane metrics in `fleet_metrics.zig`: a WAF whose database is unreachable
//! must still be able to say what it is doing, and a scrape that depends on a
//! database is a scrape that goes dark exactly when it is needed.
//!
//! Rendering is allocation-bounded and I/O-free: the caller supplies the buffer and
//! decides where the bytes go, so exposing metrics never blocks a request.

const std = @import("std");

/// A snapshot of the engine's counters. Taken as a value so a scrape reads a
/// coherent set rather than a mix of moments.
pub const Snapshot = struct {
    /// Transactions created since start.
    transactions_total: u64 = 0,
    /// Transactions currently alive.
    transactions_active: u64 = 0,
    /// Rules that matched, across all transactions.
    rule_matches_total: u64 = 0,
    /// Transactions that ended in a disruptive action.
    interventions_total: u64 = 0,
    /// Times a host plugin could not answer (#23). Counted separately from a
    /// no-match, because a data source that failed to load would otherwise read as
    /// clean traffic.
    plugin_unavailable_total: u64 = 0,
    /// Bodies a processor refused: malformed, too deep, or past a limit. A body that
    /// was never inspected is not the same as a body with nothing in it.
    body_processor_errors_total: u64 = 0,
};

/// The largest document `render` can produce, so a caller can size a buffer once.
/// The series set is fixed, so this is a constant rather than a guess.
pub const max_document_bytes = 2048;

/// Render `snapshot` as a Prometheus exposition document into `out`, returning the
/// written slice. `out` must be at least `max_document_bytes`.
pub fn render(snapshot: Snapshot, out: []u8) []const u8 {
    std.debug.assert(out.len >= max_document_bytes);
    var written: usize = 0;

    const series = [_]struct {
        name: []const u8,
        help: []const u8,
        kind: []const u8,
        value: u64,
    }{
        .{
            .name = "waf_transactions_total",
            .help = "Transactions the engine has inspected.",
            .kind = "counter",
            .value = snapshot.transactions_total,
        },
        .{
            .name = "waf_transactions_active",
            .help = "Transactions currently in flight.",
            .kind = "gauge",
            .value = snapshot.transactions_active,
        },
        .{
            .name = "waf_rule_matches_total",
            .help = "Rules that matched.",
            .kind = "counter",
            .value = snapshot.rule_matches_total,
        },
        .{
            .name = "waf_interventions_total",
            .help = "Transactions ended by a disruptive action.",
            .kind = "counter",
            .value = snapshot.interventions_total,
        },
        .{
            .name = "waf_plugin_unavailable_total",
            .help = "Times a host plugin could not answer an operator.",
            .kind = "counter",
            .value = snapshot.plugin_unavailable_total,
        },
        .{
            .name = "waf_body_processor_errors_total",
            .help = "Bodies a processor refused as malformed, too deep, or oversized.",
            .kind = "counter",
            .value = snapshot.body_processor_errors_total,
        },
    };

    for (series) |entry| {
        written += (std.fmt.bufPrint(out[written..], "# HELP {s} {s}\n# TYPE {s} {s}\n{s} {d}\n", .{
            entry.name,
            entry.help,
            entry.name,
            entry.kind,
            entry.name,
            entry.value,
        }) catch return out[0..written]).len;
    }
    return out[0..written];
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

test "a snapshot renders every series with its help and type" {
    var buffer: [max_document_bytes]u8 = undefined;
    const document = render(.{
        .transactions_total = 1234,
        .transactions_active = 7,
        .rule_matches_total = 88,
        .interventions_total = 12,
        .plugin_unavailable_total = 3,
        .body_processor_errors_total = 5,
    }, &buffer);

    try testing.expect(std.mem.indexOf(u8, document, "# TYPE waf_transactions_total counter\nwaf_transactions_total 1234\n") != null);
    try testing.expect(std.mem.indexOf(u8, document, "# TYPE waf_transactions_active gauge\nwaf_transactions_active 7\n") != null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_rule_matches_total 88") != null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_interventions_total 12") != null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_plugin_unavailable_total 3") != null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_body_processor_errors_total 5") != null);

    // Every sample is preceded by its HELP and TYPE, as the format requires.
    var lines = std.mem.tokenizeScalar(u8, document, '\n');
    var declared = false;
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "# HELP")) declared = true;
        if (!std.mem.startsWith(u8, line, "#")) try testing.expect(declared);
    }
}

test "an engine that has done nothing still reports every series" {
    // Zero is a measurement: a scrape that omitted quiet counters would make a WAF
    // seeing no traffic indistinguishable from one that is not running.
    var buffer: [max_document_bytes]u8 = undefined;
    const document = render(.{}, &buffer);
    try testing.expect(std.mem.indexOf(u8, document, "waf_transactions_total 0") != null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_interventions_total 0") != null);
    try testing.expect(document.len < max_document_bytes);
}
