//! The fleet control-plane's schema and repositories on the embedded SQLite
//! backend (#57) — a serverless mirror of the PostgreSQL repositories in
//! `fleet.zig`, for the demo profile and for exercising control-plane logic in
//! tests without a PostgreSQL server. The SQL is SQLite-flavored (upserts,
//! CURRENT_TIMESTAMP, JSON1) but the repository shapes match their PostgreSQL
//! counterparts.

const std = @import("std");
const sqlite = @import("sqlite.zig");

/// The demo/test schema, as ordered migrations applied by `sqlite.migrate`.
/// A subset of the PostgreSQL schema sufficient for the node-inventory and
/// event-stream flows the demo exercises.
pub const migrations = [_]sqlite.Migration{
    .{
        .version = 1,
        .name = "initial_schema",
        .sql =
        \\CREATE TABLE nodes (
        \\  id            INTEGER PRIMARY KEY AUTOINCREMENT,
        \\  node_id       TEXT NOT NULL UNIQUE,
        \\  hostname      TEXT NOT NULL,
        \\  version       TEXT NOT NULL DEFAULT '',
        \\  status        TEXT NOT NULL DEFAULT 'pending',
        \\  labels        TEXT NOT NULL DEFAULT '{}',
        \\  enrolled_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        \\  last_seen_at  TEXT
        \\);
        \\CREATE INDEX nodes_status_idx ON nodes (status);
        \\
        \\CREATE TABLE security_events (
        \\  id           INTEGER PRIMARY KEY AUTOINCREMENT,
        \\  node_id      TEXT NOT NULL,
        \\  occurred_at  TEXT NOT NULL,
        \\  action       TEXT,
        \\  uri          TEXT,
        \\  message      TEXT
        \\);
        \\CREATE INDEX security_events_node_idx ON security_events (node_id, occurred_at);
        ,
    },
};

/// Bring `conn` up to the latest demo schema. Returns the number applied.
pub fn apply(conn: *sqlite.Conn, allocator: std.mem.Allocator) sqlite.Error!usize {
    return sqlite.migrate(conn, allocator, &migrations);
}

/// Enrollment, heartbeat, and status/inventory for fleet nodes on SQLite (#57),
/// mirroring `fleet.NodeRepository`. All values are bound parameters.
pub const NodeRepository = struct {
    conn: *sqlite.Conn,

    /// Enroll a node, or refresh and re-activate it if already enrolled.
    pub fn enroll(self: NodeRepository, node_id: [:0]const u8, hostname: [:0]const u8, version: [:0]const u8) sqlite.Error!void {
        try self.conn.execParams(
            \\INSERT INTO nodes (node_id, hostname, version, status) VALUES (?1, ?2, ?3, 'active')
            \\ON CONFLICT (node_id) DO UPDATE SET hostname = excluded.hostname, version = excluded.version, status = 'active'
        , &.{ node_id, hostname, version });
    }

    pub fn heartbeat(self: NodeRepository, node_id: [:0]const u8) sqlite.Error!void {
        try self.conn.execParams("UPDATE nodes SET last_seen_at = CURRENT_TIMESTAMP WHERE node_id = ?1", &.{node_id});
    }

    /// The node's status (caller frees), or null if it is not enrolled.
    pub fn statusOf(self: NodeRepository, allocator: std.mem.Allocator, node_id: [:0]const u8) sqlite.Error!?[]u8 {
        return self.conn.queryScalarParams(allocator, "SELECT status FROM nodes WHERE node_id = ?1", &.{node_id});
    }

    /// How many nodes are in a given status — fleet inventory (caller frees).
    pub fn countByStatus(self: NodeRepository, allocator: std.mem.Allocator, status: [:0]const u8) sqlite.Error!?[]u8 {
        return self.conn.queryScalarParams(allocator, "SELECT count(*) FROM nodes WHERE status = ?1", &.{status});
    }

    /// Set (or overwrite) a label on a node, preserving other keys (JSON1).
    pub fn setLabel(self: NodeRepository, node_id: [:0]const u8, key: [:0]const u8, value: [:0]const u8) sqlite.Error!void {
        try self.conn.execParams(
            "UPDATE nodes SET labels = json_set(labels, '$.' || ?2, ?3) WHERE node_id = ?1",
            &.{ node_id, key, value },
        );
    }

    /// The value of a node's label (caller frees), or null if absent.
    pub fn labelOf(self: NodeRepository, allocator: std.mem.Allocator, node_id: [:0]const u8, key: [:0]const u8) sqlite.Error!?[]u8 {
        return self.conn.queryScalarParams(allocator, "SELECT json_extract(labels, '$.' || ?2) FROM nodes WHERE node_id = ?1", &.{ node_id, key });
    }
};

/// Ingestion and per-node counts for the event stream on SQLite (#57),
/// mirroring `fleet.EventRepository`.
pub const EventRepository = struct {
    conn: *sqlite.Conn,

    pub fn record(self: EventRepository, node_id: [:0]const u8, action: [:0]const u8, uri: [:0]const u8, message: [:0]const u8) sqlite.Error!void {
        try self.conn.execParams(
            "INSERT INTO security_events (node_id, occurred_at, action, uri, message) VALUES (?1, CURRENT_TIMESTAMP, ?2, ?3, ?4)",
            &.{ node_id, action, uri, message },
        );
    }

    /// How many events a node has recorded (caller frees the text count).
    pub fn countForNode(self: EventRepository, allocator: std.mem.Allocator, node_id: [:0]const u8) sqlite.Error!?[]u8 {
        return self.conn.queryScalarParams(allocator, "SELECT count(*) FROM security_events WHERE node_id = ?1", &.{node_id});
    }

    /// The most recent events for a node, newest first, up to `limit`. The row
    /// cursor yields columns (0) occurred_at, (1) action, (2) uri; caller
    /// `deinit`s it.
    pub fn recentForNode(self: EventRepository, node_id: [:0]const u8, limit: [:0]const u8) sqlite.Error!sqlite.Rows {
        return self.conn.query(
            "SELECT occurred_at, action, uri FROM security_events WHERE node_id = ?1 ORDER BY id DESC LIMIT ?2",
            &.{ node_id, limit },
        );
    }
};

// ---- tests ----------------------------------------------------------------
// A private in-memory database — no server, runs under `zig build sqlite-test`.

const testing = std.testing;

test "sqlite fleet: node enrollment, inventory, and labels" {
    var conn = try sqlite.Conn.openMemory();
    defer conn.close();
    try testing.expectEqual(migrations.len, try apply(&conn, testing.allocator));

    const nodes = NodeRepository{ .conn = &conn };
    const node_id = "11111111-1111-1111-1111-111111111111";

    // Enrollment is idempotent; heartbeat and status work.
    try nodes.enroll(node_id, "edge-1", "1.0.0");
    try nodes.enroll(node_id, "edge-1-renamed", "1.0.1"); // re-enroll updates
    try nodes.heartbeat(node_id);
    const status = (try nodes.statusOf(testing.allocator, node_id)).?;
    defer testing.allocator.free(status);
    try testing.expectEqualStrings("active", status);
    try testing.expect((try nodes.statusOf(testing.allocator, "00000000-0000-0000-0000-000000000000")) == null);

    const active = (try nodes.countByStatus(testing.allocator, "active")).?;
    defer testing.allocator.free(active);
    try testing.expectEqualStrings("1", active);

    // Labels merge and read back (JSON1); a missing key is null.
    try testing.expect((try nodes.labelOf(testing.allocator, node_id, "region")) == null);
    try nodes.setLabel(node_id, "region", "west");
    try nodes.setLabel(node_id, "tier", "canary");
    const region = (try nodes.labelOf(testing.allocator, node_id, "region")).?;
    defer testing.allocator.free(region);
    try testing.expectEqualStrings("west", region);
    const tier = (try nodes.labelOf(testing.allocator, node_id, "tier")).?;
    defer testing.allocator.free(tier);
    try testing.expectEqualStrings("canary", tier);
}

test "sqlite fleet: event ingestion, counts, and recent search" {
    var conn = try sqlite.Conn.openMemory();
    defer conn.close();
    _ = try apply(&conn, testing.allocator);

    const events = EventRepository{ .conn = &conn };
    const node_id = "22222222-2222-2222-2222-222222222222";

    // Ingest events, including an SQLi-shaped URI stored literally via binding.
    try events.record(node_id, "deny", "/x?id=1", "SQLi");
    try events.record(node_id, "pass", "/'; DROP TABLE nodes; --", "attempted injection");
    const count = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("2", count);

    // recentForNode returns newest first.
    var rows = try events.recentForNode(node_id, "10");
    defer rows.deinit();
    try testing.expect(rows.next());
    try testing.expectEqualStrings("/'; DROP TABLE nodes; --", rows.get(2));
    try testing.expect(rows.next());
    try testing.expectEqualStrings("/x?id=1", rows.get(2));
    try testing.expect(!rows.next());
}
