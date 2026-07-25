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
};

/// Ingestion and per-node counts for the security-event stream (#55/#56).
pub const EventRepository = struct {
    conn: *pg.Conn,

    pub fn record(self: EventRepository, node_id: [:0]const u8, action: [:0]const u8, uri: [:0]const u8, message: [:0]const u8) pg.Error!void {
        try self.conn.execParams(
            "INSERT INTO security_events (node_id, occurred_at, action, uri, message) VALUES ($1, now(), $2, $3, $4)",
            &.{ node_id, action, uri, message },
        );
    }

    /// How many events a node has recorded (caller frees the text count).
    pub fn countForNode(self: EventRepository, allocator: std.mem.Allocator, node_id: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(allocator, "SELECT count(*) FROM security_events WHERE node_id = $1", &.{node_id});
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

    // Ingest events, including an SQL-injection-shaped URI that must be stored
    // literally (parameter binding), not executed.
    try events.record(node_id, "deny", "/x?id=1", "SQLi");
    try events.record(node_id, "pass", "/'; DROP TABLE nodes; --", "attempted injection");
    const count = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("2", count);
    // The nodes table still exists — the injection did not execute.
    const still_active = (try nodes.statusOf(testing.allocator, node_id)).?;
    defer testing.allocator.free(still_active);
    try testing.expectEqualStrings("active", still_active);

    try conn.exec("DROP TABLE IF EXISTS security_events, rulesets, nodes CASCADE");
    try conn.exec("DELETE FROM schema_migrations WHERE version = 1");
}
