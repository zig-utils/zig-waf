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
