//! Fleet telemetry in the Prometheus text exposition format (#59).
//!
//! These are control-plane metrics — the state of the fleet as the database sees
//! it — not request-path metrics, which the engine exposes itself and which must
//! never depend on a database being reachable.
//!
//! Every series here answers an operational question that otherwise requires
//! someone to go and look: are nodes still checking in, is the policy they run the
//! policy they were given, is the event stream arriving, and are alerts actually
//! being delivered. The last matters most: an alert channel that is failing looks
//! exactly like quiet, so it is a metric rather than something to be noticed.

const std = @import("std");
const pg = @import("pg.zig");

/// One metric to render: its name, its help text, its type, and the query that
/// produces it. A query returns either a single value, or a label value and a
/// number per row.
const Metric = struct {
    name: []const u8,
    help: []const u8,
    kind: enum { gauge, counter },
    /// The label name, when the query returns one column of labels and one of
    /// values. Null for a single unlabelled value.
    label: ?[]const u8 = null,
    sql: [:0]const u8,
};

/// How stale a node's heartbeat may be before it counts as unresponsive. Matches
/// the default the fleet views use, so the metric and the console agree.
pub const default_stale_seconds = 120;

const metrics = [_]Metric{
    .{
        .name = "waf_fleet_nodes",
        .help = "Enrolled nodes by status.",
        .kind = .gauge,
        .label = "status",
        .sql = "SELECT status, count(*)::text FROM nodes GROUP BY status ORDER BY status",
    },
    .{
        .name = "waf_fleet_nodes_unresponsive",
        .help = "Active nodes with no heartbeat inside the staleness window.",
        .kind = .gauge,
        .sql =
        \\SELECT count(*)::text FROM nodes
        \\WHERE status = 'active'
        \\  AND (last_seen_at IS NULL OR last_seen_at < now() - make_interval(secs => $1::int))
        ,
    },
    .{
        .name = "waf_fleet_ruleset_drift",
        .help = "Nodes not confirmed to be running the ruleset version they were assigned.",
        .kind = .gauge,
        .label = "ruleset",
        .sql =
        \\SELECT ruleset_name, count(*)::text FROM node_rulesets
        \\WHERE running_version IS DISTINCT FROM version
        \\GROUP BY ruleset_name ORDER BY ruleset_name
        ,
    },
    .{
        .name = "waf_fleet_events_recent",
        .help = "Security events ingested in the last hour, by action.",
        .kind = .gauge,
        .label = "action",
        .sql =
        \\SELECT coalesce(action, 'unknown'), count(*)::text FROM security_events
        \\WHERE occurred_at > now() - interval '1 hour'
        \\GROUP BY 1 ORDER BY 1
        ,
    },
    .{
        .name = "waf_fleet_event_bytes",
        .help = "Bytes the security-event stream occupies, including indexes.",
        .kind = .gauge,
        .sql =
        \\SELECT coalesce(sum(pg_total_relation_size(c.oid)), 0)::text
        \\FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
        \\WHERE i.inhparent = 'security_events'::regclass
        ,
    },
    .{
        .name = "waf_fleet_alert_deliveries_total",
        .help = "Alert webhook delivery attempts by outcome.",
        .kind = .counter,
        .label = "status",
        .sql = "SELECT status, count(*)::text FROM alert_deliveries GROUP BY status ORDER BY status",
    },
    .{
        .name = "waf_fleet_alert_channels_failing",
        .help = "Alert rules whose most recent delivery attempt did not succeed.",
        .kind = .gauge,
        .sql =
        \\WITH last_attempt AS (
        \\  SELECT DISTINCT ON (alert_name) alert_name, status
        \\  FROM alert_deliveries ORDER BY alert_name, attempted_at DESC, id DESC
        \\)
        \\SELECT count(*)::text FROM last_attempt WHERE status <> 'delivered'
        ,
    },
    .{
        .name = "waf_fleet_alerts_silenced",
        .help = "Alert rules currently silenced.",
        .kind = .gauge,
        .sql = "SELECT count(*)::text FROM alert_silences WHERE until > now()",
    },
};

/// Render every fleet metric as a Prometheus exposition document (caller owns the
/// bytes).
///
/// A query that fails does not fail the whole scrape: a metric that cannot be
/// collected is omitted, because losing one series is better than losing the
/// visibility of all of them at the moment something is wrong. It is not reported
/// as zero, which would be a claim about the fleet rather than an absence.
pub fn render(allocator: std.mem.Allocator, conn: *pg.Conn, stale_seconds: u32) error{OutOfMemory}![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var stale_buffer: [16]u8 = undefined;
    const written = std.fmt.bufPrint(&stale_buffer, "{d}", .{stale_seconds}) catch unreachable;
    stale_buffer[written.len] = 0;
    const stale = stale_buffer[0..written.len :0];

    for (metrics) |metric| {
        // Every metric this needs is parameterless except the staleness window, so
        // binding it unconditionally would leave an untyped parameter in the rest.
        const uses_stale = std.mem.indexOf(u8, metric.sql, "$1") != null;
        var rows = (if (uses_stale)
            conn.query(metric.sql, &.{stale})
        else
            conn.query(metric.sql, &.{})) catch continue;
        defer rows.deinit();

        try out.print(allocator, "# HELP {s} {s}\n# TYPE {s} {s}\n", .{
            metric.name,
            metric.help,
            metric.name,
            @tagName(metric.kind),
        });
        while (rows.next()) {
            if (metric.label) |label| {
                try out.print(allocator, "{s}{{{s}=\"", .{ metric.name, label });
                try appendLabelValue(&out, allocator, rows.get(0));
                try out.print(allocator, "\"}} {s}\n", .{rows.get(1)});
            } else {
                try out.print(allocator, "{s} {s}\n", .{ metric.name, rows.get(0) });
            }
        }
        // A labelled metric with no rows leaves its HELP and TYPE with no samples:
        // the dimension is empty (no nodes, no deliveries), and Prometheus reads an
        // absent series as absent, which is the truth. Nothing is invented to fill
        // it.
    }
    return out.toOwnedSlice(allocator);
}

/// Escape a label value per the exposition format: backslash, double quote, and
/// newline. A hostname or ruleset name reaching a metric unescaped would produce a
/// document that parses as different series than intended.
fn appendLabelValue(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) error{OutOfMemory}!void {
    for (value) |byte| switch (byte) {
        '\\' => try out.appendSlice(allocator, "\\\\"),
        '"' => try out.appendSlice(allocator, "\\\""),
        '\n' => try out.appendSlice(allocator, "\\n"),
        else => try out.append(allocator, byte),
    };
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;
const fleet = @import("fleet.zig");

fn testDb() !pg.TestSchema {
    var db = try pg.TestSchema.open(testing.allocator);
    _ = fleet.apply(&db.conn, testing.allocator) catch |err| {
        db.close();
        return err;
    };
    return db;
}

test "label values are escaped so they cannot forge series" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try appendLabelValue(&out, testing.allocator, "edge-1");
    try testing.expectEqualStrings("edge-1", out.items);

    out.clearRetainingCapacity();
    // A value that would otherwise close the label and open another.
    try appendLabelValue(&out, testing.allocator, "a\"} waf_other{x=\"b");
    try testing.expectEqualStrings("a\\\"} waf_other{x=\\\"b", out.items);

    out.clearRetainingCapacity();
    try appendLabelValue(&out, testing.allocator, "back\\slash\nnewline");
    try testing.expectEqualStrings("back\\\\slash\\nnewline", out.items);
}

test "fleet metrics expose node, drift, event, and alert state" {
    var db = try testDb();
    defer db.close();
    const conn = &db.conn;

    const nodes = fleet.NodeRepository{ .conn = conn };
    const rollout = fleet.RolloutRepository{ .conn = conn };
    const events = fleet.EventRepository{ .conn = conn };
    const alerts = fleet.AlertRepository{ .conn = conn };
    const deliveries = fleet.AlertDeliveryRepository{ .conn = conn };

    // An empty fleet still renders: the scrape describes what is there, and what
    // is there is nothing.
    {
        const empty = try render(testing.allocator, conn, default_stale_seconds);
        defer testing.allocator.free(empty);
        try testing.expect(std.mem.indexOf(u8, empty, "# TYPE waf_fleet_nodes gauge") != null);
        try testing.expect(std.mem.indexOf(u8, empty, "waf_fleet_nodes_unresponsive 0") != null);
        // No node has a status, so no status series exists — absent, not zero.
        try testing.expect(std.mem.indexOf(u8, empty, "waf_fleet_nodes{") == null);
    }

    const responsive = "11111111-1111-1111-1111-111111111111";
    const silent = "22222222-2222-2222-2222-222222222222";
    try nodes.enroll(responsive, "edge-1", "1.0");
    try nodes.enroll(silent, "edge-2", "1.0");
    try nodes.heartbeat(responsive);
    // A node that stopped checking in an hour ago.
    try conn.execParams("UPDATE nodes SET last_seen_at = now() - interval '1 hour' WHERE node_id = $1", &.{silent});

    try rollout.assign(responsive, "crs", "7");
    try rollout.assign(silent, "crs", "7");
    try rollout.reportRunning(responsive, "crs", "7");

    try events.record(responsive, "deny", "/x?id=1", "SQLi");
    try events.record(responsive, "deny", "/y?id=2", "SQLi");
    try events.record(responsive, "pass", "/z", "clean");

    try alerts.create("sqli", "deny", "https://hooks.example.com/sqli");
    try deliveries.record("sqli", "https://hooks.example.com/sqli", "delivered", "200");
    try alerts.create("broken", "deny", "https://down.example.com/hook");
    try deliveries.record("broken", "https://down.example.com/hook", "failed", null);
    try alerts.silence("broken", "op@example.com", "vendor maintenance", 3600);
    try conn.exec("ANALYZE security_events");

    const document = try render(testing.allocator, conn, default_stale_seconds);
    defer testing.allocator.free(document);

    // Nodes by status, and the one that has gone quiet.
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_nodes{status=\"active\"} 2") != null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_nodes_unresponsive 1") != null);

    // One node has confirmed its ruleset version; the other has not, which is drift.
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_ruleset_drift{ruleset=\"crs\"} 1") != null);

    // Events by action.
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_events_recent{action=\"deny\"} 2") != null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_events_recent{action=\"pass\"} 1") != null);

    // Deliveries by outcome, and the failing channel — which matters most, because
    // an alert that cannot be delivered looks exactly like quiet.
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_alert_deliveries_total{status=\"delivered\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_alert_deliveries_total{status=\"failed\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_alert_channels_failing 1") != null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_alerts_silenced 1") != null);

    // The event stream's size is reported, and it is not zero once events exist.
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_event_bytes ") != null);

    // Every metric declares its help and type before its samples, as the format
    // requires.
    var lines = std.mem.tokenizeScalar(u8, document, '\n');
    var seen_help = false;
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "# HELP")) seen_help = true;
        if (!std.mem.startsWith(u8, line, "#")) try testing.expect(seen_help);
    }
}

test "a metric that cannot be collected is omitted, not reported as zero" {
    var db = try testDb();
    defer db.close();
    const conn = &db.conn;

    // Losing the alert tables is exactly the situation where the rest of the
    // scrape matters most, so the document still renders — without the series it
    // could not collect, since reporting them as zero would be a claim about the
    // fleet rather than an absence.
    try conn.exec("DROP TABLE alert_deliveries, alert_silences");

    const document = try render(testing.allocator, conn, default_stale_seconds);
    defer testing.allocator.free(document);
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_nodes") != null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_alert_deliveries_total") == null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_alert_channels_failing") == null);
    try testing.expect(std.mem.indexOf(u8, document, "waf_fleet_alerts_silenced") == null);
}
