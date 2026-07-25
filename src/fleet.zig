//! The fleet control-plane's PostgreSQL schema, expressed as ordered migrations
//! applied by `pg.migrate`. This is the initial schema (#52): enrolled nodes,
//! signed rule-set bundles, and the security-event stream. Later migrations
//! append; existing ones are never edited (each is recorded by version).

const std = @import("std");
const pg = @import("pg.zig");

/// Every fleet migration, in version order. Append-only.
pub const migrations = [_]pg.Migration{
    .{
        .version = 1,
        .name = "initial_schema",
        .sql =
        \\CREATE TABLE nodes (
        \\  id            bigserial PRIMARY KEY,
        \\  node_id       uuid NOT NULL UNIQUE,
        \\  hostname      text NOT NULL,
        \\  version       text NOT NULL DEFAULT '',
        \\  status        text NOT NULL DEFAULT 'pending',
        \\  labels        jsonb NOT NULL DEFAULT '{}',
        \\  enrolled_at   timestamptz NOT NULL DEFAULT now(),
        \\  last_seen_at  timestamptz
        \\);
        \\CREATE INDEX nodes_status_idx ON nodes (status);
        \\
        \\CREATE TABLE rulesets (
        \\  id          bigserial PRIMARY KEY,
        \\  name        text NOT NULL,
        \\  version     integer NOT NULL,
        \\  content     text NOT NULL,
        \\  signature   bytea,
        \\  created_at  timestamptz NOT NULL DEFAULT now(),
        \\  UNIQUE (name, version)
        \\);
        \\
        \\CREATE TABLE security_events (
        \\  id           bigserial PRIMARY KEY,
        \\  node_id      uuid NOT NULL,
        \\  occurred_at  timestamptz NOT NULL,
        \\  rule_id      bigint,
        \\  phase        smallint,
        \\  action       text,
        \\  severity     smallint,
        \\  client_ip    inet,
        \\  method       text,
        \\  uri          text,
        \\  message      text
        \\);
        \\CREATE INDEX security_events_occurred_idx ON security_events (occurred_at);
        \\CREATE INDEX security_events_node_idx ON security_events (node_id, occurred_at);
        ,
    },
};

/// Bring `conn`'s database up to the latest fleet schema. Returns the number of
/// migrations applied (0 when already current).
pub fn apply(conn: *pg.Conn, allocator: std.mem.Allocator) pg.Error!usize {
    return pg.migrate(conn, allocator, &migrations);
}

/// Enrollment, heartbeat, and status for fleet nodes (#50). All values are
/// bound as parameters, so node ids and hostnames are never interpolated.
pub const NodeRepository = struct {
    conn: *pg.Conn,

    /// Enroll a node or, if it already exists, refresh its hostname/version and
    /// mark it active (idempotent re-enrollment).
    pub fn enroll(self: NodeRepository, node_id: [:0]const u8, hostname: [:0]const u8, version: [:0]const u8) pg.Error!void {
        try self.conn.execParams(
            \\INSERT INTO nodes (node_id, hostname, version, status) VALUES ($1, $2, $3, 'active')
            \\ON CONFLICT (node_id) DO UPDATE SET hostname = EXCLUDED.hostname, version = EXCLUDED.version, status = 'active'
        , &.{ node_id, hostname, version });
    }

    pub fn heartbeat(self: NodeRepository, node_id: [:0]const u8) pg.Error!void {
        try self.conn.execParams("UPDATE nodes SET last_seen_at = now() WHERE node_id = $1", &.{node_id});
    }

    /// The node's status (caller frees), or null if it is not enrolled.
    pub fn statusOf(self: NodeRepository, allocator: std.mem.Allocator, node_id: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(allocator, "SELECT status FROM nodes WHERE node_id = $1", &.{node_id});
    }

    /// How many nodes are in a given status — for the fleet inventory (#50).
    pub fn countByStatus(self: NodeRepository, allocator: std.mem.Allocator, status: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(allocator, "SELECT count(*) FROM nodes WHERE status = $1", &.{status});
    }

    /// How many active nodes have not sent a heartbeat within `max_age_seconds`
    /// (or have never been seen) — the "stale/unhealthy" count for fleet
    /// telemetry and alerting (#59).
    pub fn staleCount(self: NodeRepository, allocator: std.mem.Allocator, max_age_seconds: u32) pg.Error!?[]u8 {
        var seconds_buffer: [16]u8 = undefined;
        const seconds = std.fmt.bufPrint(&seconds_buffer, "{d}", .{max_age_seconds}) catch return error.QueryFailed;
        seconds_buffer[seconds.len] = 0;
        return self.conn.queryScalarParams(
            allocator,
            \\SELECT count(*) FROM nodes
            \\WHERE status = 'active'
            \\  AND (last_seen_at IS NULL OR last_seen_at < now() - make_interval(secs => $1::int))
        ,
            &.{seconds_buffer[0..seconds.len :0]},
        );
    }
};

/// One security event to ingest. All fields are libpq text values.
pub const Event = struct {
    node_id: [:0]const u8,
    occurred_at: [:0]const u8,
    action: [:0]const u8,
    uri: [:0]const u8,
    message: [:0]const u8,
};

/// Ingestion and per-node counts for the security-event stream (#55/#56).
pub const EventRepository = struct {
    conn: *pg.Conn,

    /// Ingest a batch of events in a single transaction (#55): one COMMIT (and
    /// fsync) covers the whole batch, which is how a drained event queue reaches
    /// PostgreSQL efficiently. The batch is all-or-nothing — any failure rolls
    /// the whole batch back.
    pub fn recordBatch(self: EventRepository, batch: []const Event) pg.Error!void {
        try self.conn.exec("BEGIN");
        for (batch) |event| {
            self.conn.execParams(
                "INSERT INTO security_events (node_id, occurred_at, action, uri, message) VALUES ($1, $2, $3, $4, $5)",
                &.{ event.node_id, event.occurred_at, event.action, event.uri, event.message },
            ) catch |err| {
                self.conn.exec("ROLLBACK") catch {};
                return err;
            };
        }
        try self.conn.exec("COMMIT");
    }

    pub fn record(self: EventRepository, node_id: [:0]const u8, action: [:0]const u8, uri: [:0]const u8, message: [:0]const u8) pg.Error!void {
        try self.conn.execParams(
            "INSERT INTO security_events (node_id, occurred_at, action, uri, message) VALUES ($1, now(), $2, $3, $4)",
            &.{ node_id, action, uri, message },
        );
    }

    /// Record an event at an explicit time — used by ingestion replay and by
    /// retention tests. `occurred_at` is any value libpq accepts for timestamptz
    /// (e.g. "2020-01-01T00:00:00Z" or "now() - interval '40 days'" is NOT valid
    /// here — pass a literal timestamp).
    pub fn recordAt(self: EventRepository, node_id: [:0]const u8, occurred_at: [:0]const u8, action: [:0]const u8, uri: [:0]const u8, message: [:0]const u8) pg.Error!void {
        try self.conn.execParams(
            "INSERT INTO security_events (node_id, occurred_at, action, uri, message) VALUES ($1, $2, $3, $4, $5)",
            &.{ node_id, occurred_at, action, uri, message },
        );
    }

    /// How many events a node has recorded (caller frees the text count).
    pub fn countForNode(self: EventRepository, allocator: std.mem.Allocator, node_id: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(allocator, "SELECT count(*) FROM security_events WHERE node_id = $1", &.{node_id});
    }

    /// The most recent events for a node, newest first, up to `limit` — the
    /// event-search / transaction-detail view (#56/#66). The row cursor yields
    /// columns (0) occurred_at, (1) action, (2) uri; the caller `deinit`s it.
    pub fn recentForNode(self: EventRepository, node_id: [:0]const u8, limit: [:0]const u8) pg.Error!pg.Rows {
        return self.conn.query(
            "SELECT occurred_at, action, uri FROM security_events WHERE node_id = $1 ORDER BY occurred_at DESC LIMIT $2::int",
            &.{ node_id, limit },
        );
    }

    /// Delete events older than `retention_days` (retention policy #56). Returns
    /// the number of rows deleted (caller frees the text count).
    pub fn pruneOlderThan(self: EventRepository, allocator: std.mem.Allocator, retention_days: u32) pg.Error!?[]u8 {
        var days_buffer: [16]u8 = undefined;
        const days = std.fmt.bufPrint(&days_buffer, "{d}", .{retention_days}) catch return error.QueryFailed;
        days_buffer[days.len] = 0;
        // make_interval(days => $1::int) keeps the interval parameterized.
        return self.conn.queryScalarParams(
            allocator,
            \\WITH deleted AS (
            \\  DELETE FROM security_events
            \\  WHERE occurred_at < now() - make_interval(days => $1::int)
            \\  RETURNING 1
            \\) SELECT count(*) FROM deleted
        ,
            &.{days_buffer[0..days.len :0]},
        );
    }
};

/// Store and retrieve versioned rule-set bundles that are rolled out to nodes
/// (#54). Each (name, version) is immutable once published; nodes fetch the
/// latest, and a rollback re-selects an earlier version.
pub const RulesetRepository = struct {
    conn: *pg.Conn,

    /// Publish a new immutable bundle version. Re-publishing an existing
    /// (name, version) is a conflict (QueryFailed) — versions never change.
    pub fn publish(self: RulesetRepository, name: [:0]const u8, version: [:0]const u8, content: [:0]const u8) pg.Error!void {
        try self.conn.execParams(
            "INSERT INTO rulesets (name, version, content) VALUES ($1, $2, $3)",
            &.{ name, version, content },
        );
    }

    /// The content of the highest-numbered version of `name` (caller frees), or
    /// null if the ruleset has never been published.
    pub fn latest(self: RulesetRepository, allocator: std.mem.Allocator, name: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            "SELECT content FROM rulesets WHERE name = $1 ORDER BY version DESC LIMIT 1",
            &.{name},
        );
    }

    /// The content of a specific version (for rollout/rollback), or null.
    pub fn atVersion(self: RulesetRepository, allocator: std.mem.Allocator, name: [:0]const u8, version: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            "SELECT content FROM rulesets WHERE name = $1 AND version = $2",
            &.{ name, version },
        );
    }
};

// ---- tests --------------------------------------------------------------

const testing = std.testing;

test "the fleet schema applies to a clean database and is idempotent" {
    const raw = std.c.getenv("PG_TEST_DSN") orelse return error.SkipZigTest;
    const dsn_slice = std.mem.span(raw);
    if (dsn_slice.len == 0) return error.SkipZigTest;
    const dsn = try testing.allocator.allocSentinel(u8, dsn_slice.len, 0);
    defer testing.allocator.free(dsn);
    @memcpy(dsn, dsn_slice);

    var conn = try pg.Conn.open(dsn);
    defer conn.close();

    // Start from a clean slate so the migration exercises real DDL. The
    // schema_migrations table may not exist yet, so tolerate that delete.
    try conn.exec("DROP TABLE IF EXISTS security_events, rulesets, nodes CASCADE");
    conn.exec("DELETE FROM schema_migrations WHERE version = 1") catch {};

    try testing.expectEqual(@as(usize, 1), try apply(&conn, testing.allocator));
    try testing.expectEqual(@as(usize, 0), try apply(&conn, testing.allocator)); // idempotent

    // The three core tables exist and are usable.
    for ([_][:0]const u8{ "nodes", "rulesets", "security_events" }) |table_name| {
        var buffer: [128]u8 = undefined;
        const query = std.fmt.bufPrint(&buffer, "SELECT to_regclass('{s}') IS NOT NULL", .{table_name}) catch unreachable;
        buffer[query.len] = 0;
        const present = (try conn.queryScalar(testing.allocator, buffer[0..query.len :0])).?;
        defer testing.allocator.free(present);
        try testing.expectEqualStrings("t", present);
    }

    // An event round-trips through the schema.
    try conn.exec(
        \\INSERT INTO nodes (node_id, hostname, status) VALUES
        \\  ('11111111-1111-1111-1111-111111111111', 'edge-1', 'active')
    );
    try conn.exec(
        \\INSERT INTO security_events (node_id, occurred_at, rule_id, action, severity, client_ip, method, uri, message)
        \\VALUES ('11111111-1111-1111-1111-111111111111', now(), 942100, 'deny', 2, '203.0.113.7', 'GET', '/x?id=1', 'SQLi')
    );
    const count = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM security_events WHERE action = 'deny'")).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("1", count);

    try conn.exec("DROP TABLE IF EXISTS security_events, rulesets, nodes CASCADE");
    try conn.exec("DELETE FROM schema_migrations WHERE version = 1");
}

test "event retention prunes only events past the window" {
    const raw = std.c.getenv("PG_TEST_DSN") orelse return error.SkipZigTest;
    const dsn_slice = std.mem.span(raw);
    if (dsn_slice.len == 0) return error.SkipZigTest;
    const dsn = try testing.allocator.allocSentinel(u8, dsn_slice.len, 0);
    defer testing.allocator.free(dsn);
    @memcpy(dsn, dsn_slice);

    var conn = try pg.Conn.open(dsn);
    defer conn.close();
    try conn.exec("DROP TABLE IF EXISTS security_events, rulesets, nodes CASCADE");
    conn.exec("DELETE FROM schema_migrations WHERE version = 1") catch {};
    _ = try apply(&conn, testing.allocator);

    const events = EventRepository{ .conn = &conn };
    const node_id = "33333333-3333-3333-3333-333333333333";
    try events.record(node_id, "deny", "/recent", "kept"); // occurred now()
    try events.recordAt(node_id, "2020-01-01T00:00:00Z", "deny", "/old", "aged out");

    // Prune everything older than 30 days: the 2020 event goes, the recent stays.
    const deleted = (try events.pruneOlderThan(testing.allocator, 30)).?;
    defer testing.allocator.free(deleted);
    try testing.expectEqualStrings("1", deleted);
    const remaining = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(remaining);
    try testing.expectEqualStrings("1", remaining);

    try conn.exec("DROP TABLE IF EXISTS security_events, rulesets, nodes CASCADE");
    try conn.exec("DELETE FROM schema_migrations WHERE version = 1");
}

test "batched event ingestion commits the whole batch atomically" {
    const raw = std.c.getenv("PG_TEST_DSN") orelse return error.SkipZigTest;
    const dsn_slice = std.mem.span(raw);
    if (dsn_slice.len == 0) return error.SkipZigTest;
    const dsn = try testing.allocator.allocSentinel(u8, dsn_slice.len, 0);
    defer testing.allocator.free(dsn);
    @memcpy(dsn, dsn_slice);

    var conn = try pg.Conn.open(dsn);
    defer conn.close();
    try conn.exec("DROP TABLE IF EXISTS security_events, rulesets, nodes CASCADE");
    conn.exec("DELETE FROM schema_migrations WHERE version = 1") catch {};
    _ = try apply(&conn, testing.allocator);

    const events = EventRepository{ .conn = &conn };
    const node_id = "44444444-4444-4444-4444-444444444444";
    const batch = [_]Event{
        .{ .node_id = node_id, .occurred_at = "2024-01-01T00:00:00Z", .action = "deny", .uri = "/a", .message = "1" },
        .{ .node_id = node_id, .occurred_at = "2024-01-01T00:00:01Z", .action = "deny", .uri = "/b", .message = "2" },
        .{ .node_id = node_id, .occurred_at = "2024-01-01T00:00:02Z", .action = "pass", .uri = "/c", .message = "3" },
    };
    try events.recordBatch(&batch);
    const count = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("3", count);

    // A batch with a bad row rolls the whole batch back (nothing is ingested).
    const bad = [_]Event{
        .{ .node_id = node_id, .occurred_at = "2024-02-01T00:00:00Z", .action = "deny", .uri = "/ok", .message = "4" },
        .{ .node_id = node_id, .occurred_at = "not-a-timestamp", .action = "deny", .uri = "/bad", .message = "5" },
    };
    try testing.expectError(error.QueryFailed, events.recordBatch(&bad));
    const after = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(after);
    try testing.expectEqualStrings("3", after); // unchanged — the good row rolled back too

    try conn.exec("DROP TABLE IF EXISTS security_events, rulesets, nodes CASCADE");
    try conn.exec("DELETE FROM schema_migrations WHERE version = 1");
}

test "ruleset repository publishes immutable versions and rolls back" {
    const raw = std.c.getenv("PG_TEST_DSN") orelse return error.SkipZigTest;
    const dsn_slice = std.mem.span(raw);
    if (dsn_slice.len == 0) return error.SkipZigTest;
    const dsn = try testing.allocator.allocSentinel(u8, dsn_slice.len, 0);
    defer testing.allocator.free(dsn);
    @memcpy(dsn, dsn_slice);

    var conn = try pg.Conn.open(dsn);
    defer conn.close();
    try conn.exec("DROP TABLE IF EXISTS security_events, rulesets, nodes CASCADE");
    conn.exec("DELETE FROM schema_migrations WHERE version = 1") catch {};
    _ = try apply(&conn, testing.allocator);

    const rulesets = RulesetRepository{ .conn = &conn };
    try rulesets.publish("crs", "1", "SecRuleEngine On # v1");
    try rulesets.publish("crs", "2", "SecRuleEngine On # v2");

    // latest() returns the highest version.
    const latest = (try rulesets.latest(testing.allocator, "crs")).?;
    defer testing.allocator.free(latest);
    try testing.expectEqualStrings("SecRuleEngine On # v2", latest);

    // A specific earlier version is retrievable (rollback).
    const v1 = (try rulesets.atVersion(testing.allocator, "crs", "1")).?;
    defer testing.allocator.free(v1);
    try testing.expectEqualStrings("SecRuleEngine On # v1", v1);

    // Versions are immutable: re-publishing (name, version) conflicts.
    try testing.expectError(error.QueryFailed, rulesets.publish("crs", "2", "tampered"));
    try testing.expect((try rulesets.latest(testing.allocator, "absent")) == null);

    try conn.exec("DROP TABLE IF EXISTS security_events, rulesets, nodes CASCADE");
    try conn.exec("DELETE FROM schema_migrations WHERE version = 1");
}

test "node and event repositories enroll, heartbeat, and ingest safely" {
    const raw = std.c.getenv("PG_TEST_DSN") orelse return error.SkipZigTest;
    const dsn_slice = std.mem.span(raw);
    if (dsn_slice.len == 0) return error.SkipZigTest;
    const dsn = try testing.allocator.allocSentinel(u8, dsn_slice.len, 0);
    defer testing.allocator.free(dsn);
    @memcpy(dsn, dsn_slice);

    var conn = try pg.Conn.open(dsn);
    defer conn.close();
    try conn.exec("DROP TABLE IF EXISTS security_events, rulesets, nodes CASCADE");
    conn.exec("DELETE FROM schema_migrations WHERE version = 1") catch {};
    _ = try apply(&conn, testing.allocator);

    const nodes = NodeRepository{ .conn = &conn };
    const events = EventRepository{ .conn = &conn };
    const node_id = "22222222-2222-2222-2222-222222222222";

    // Enrollment is idempotent; heartbeat and status work.
    try nodes.enroll(node_id, "edge-7", "1.2.3");
    try nodes.enroll(node_id, "edge-7-renamed", "1.2.4"); // re-enroll updates, no error
    try nodes.heartbeat(node_id);
    const status = (try nodes.statusOf(testing.allocator, node_id)).?;
    defer testing.allocator.free(status);
    try testing.expectEqualStrings("active", status);
    try testing.expect((try nodes.statusOf(testing.allocator, "00000000-0000-0000-0000-000000000000")) == null);

    // Inventory: one active node, and it is fresh (heartbeat just now) within a
    // 60-second staleness window.
    const active_count = (try nodes.countByStatus(testing.allocator, "active")).?;
    defer testing.allocator.free(active_count);
    try testing.expectEqualStrings("1", active_count);
    const stale = (try nodes.staleCount(testing.allocator, 60)).?;
    defer testing.allocator.free(stale);
    try testing.expectEqualStrings("0", stale);

    // Ingest events, including an SQL-injection-shaped URI that must be stored
    // literally (parameter binding), not executed.
    try events.record(node_id, "deny", "/x?id=1", "SQLi");
    try events.record(node_id, "pass", "/'; DROP TABLE nodes; --", "attempted injection");
    const count = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("2", count);

    // Event search returns rows newest-first, bounded by the limit. The second
    // insert ("pass") is the most recent, so it comes first.
    var rows = try events.recentForNode(node_id, "5");
    defer rows.deinit();
    try testing.expectEqual(@as(usize, 2), rows.len());
    try testing.expect(rows.next());
    try testing.expectEqualStrings("pass", rows.get(1)); // action of the newest event
    try testing.expect(rows.next());
    try testing.expectEqualStrings("deny", rows.get(1));
    try testing.expect(!rows.next());

    // The nodes table still exists — the injection did not execute.
    const still_active = (try nodes.statusOf(testing.allocator, node_id)).?;
    defer testing.allocator.free(still_active);
    try testing.expectEqualStrings("active", still_active);

    try conn.exec("DROP TABLE IF EXISTS security_events, rulesets, nodes CASCADE");
    try conn.exec("DELETE FROM schema_migrations WHERE version = 1");
}
