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
    .{
        .version = 2,
        .name = "rulesets_and_rollout",
        // Policy versions and their assignment to nodes, so a single-node demo can
        // publish a ruleset and roll it out the way a fleet does.
        .sql =
        \\CREATE TABLE rulesets (
        \\  id          INTEGER PRIMARY KEY AUTOINCREMENT,
        \\  name        TEXT NOT NULL,
        \\  version     INTEGER NOT NULL,
        \\  content     TEXT NOT NULL,
        \\  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        \\  UNIQUE (name, version)
        \\);
        \\
        \\CREATE TABLE node_rulesets (
        \\  node_id          TEXT NOT NULL,
        \\  ruleset_name     TEXT NOT NULL,
        \\  version          INTEGER NOT NULL,
        \\  running_version  INTEGER,
        \\  assigned_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        \\  PRIMARY KEY (node_id, ruleset_name)
        \\);
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

/// Immutable policy versions on SQLite (#57), mirroring `fleet.RulesetRepository`
/// minus signing: the demo profile has no fleet to distribute a bundle to, and a
/// signature nobody verifies would suggest a guarantee this backend does not make.
pub const RulesetRepository = struct {
    conn: *sqlite.Conn,

    /// Publish a version. Versions are immutable, so re-publishing one fails
    /// rather than rewriting what a node may already be running.
    pub fn publish(self: RulesetRepository, name: [:0]const u8, version: [:0]const u8, content: [:0]const u8) sqlite.Error!void {
        try self.conn.execParams(
            "INSERT INTO rulesets (name, version, content) VALUES (?1, ?2, ?3)",
            &.{ name, version, content },
        );
    }

    /// The content of the highest version of a ruleset (caller frees), or null.
    pub fn latest(self: RulesetRepository, allocator: std.mem.Allocator, name: [:0]const u8) sqlite.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            "SELECT content FROM rulesets WHERE name = ?1 ORDER BY version DESC LIMIT 1",
            &.{name},
        );
    }

    /// The content of a specific version (caller frees), or null — the rollback
    /// path, which works because versions are never rewritten.
    pub fn atVersion(self: RulesetRepository, allocator: std.mem.Allocator, name: [:0]const u8, version: [:0]const u8) sqlite.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            "SELECT content FROM rulesets WHERE name = ?1 AND version = ?2",
            &.{ name, version },
        );
    }
};

/// Which version each node is assigned, and which it reports running (#57),
/// mirroring `fleet.RolloutRepository`.
pub const RolloutRepository = struct {
    conn: *sqlite.Conn,

    /// Assign a node to a version; re-assigning updates the target.
    pub fn assign(self: RolloutRepository, node_id: [:0]const u8, ruleset_name: [:0]const u8, version: [:0]const u8) sqlite.Error!void {
        try self.conn.execParams(
            \\INSERT INTO node_rulesets (node_id, ruleset_name, version) VALUES (?1, ?2, ?3)
            \\ON CONFLICT (node_id, ruleset_name) DO UPDATE SET version = excluded.version,
            \\  assigned_at = CURRENT_TIMESTAMP
        , &.{ node_id, ruleset_name, version });
    }

    /// Assign every enrolled node to a version, returning how many were moved.
    pub fn assignAll(self: RolloutRepository, allocator: std.mem.Allocator, ruleset_name: [:0]const u8, version: [:0]const u8) sqlite.Error!?[]u8 {
        try self.conn.execParams(
            \\INSERT INTO node_rulesets (node_id, ruleset_name, version)
            \\SELECT node_id, ?1, ?2 FROM nodes
            \\-- SQLite parses a bare ON after a SELECT as a join, so the upsert clause
            \\-- needs a WHERE to disambiguate it.
            \\WHERE true
            \\ON CONFLICT (node_id, ruleset_name) DO UPDATE SET version = excluded.version,
            \\  assigned_at = CURRENT_TIMESTAMP
        , &.{ ruleset_name, version });
        return self.countOnVersion(allocator, ruleset_name, version);
    }

    /// The version a node is assigned (caller frees), or null if unassigned.
    pub fn assignedVersion(self: RolloutRepository, allocator: std.mem.Allocator, node_id: [:0]const u8, ruleset_name: [:0]const u8) sqlite.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            "SELECT version FROM node_rulesets WHERE node_id = ?1 AND ruleset_name = ?2",
            &.{ node_id, ruleset_name },
        );
    }

    /// How many nodes are assigned a version — rollout convergence.
    pub fn countOnVersion(self: RolloutRepository, allocator: std.mem.Allocator, ruleset_name: [:0]const u8, version: [:0]const u8) sqlite.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            "SELECT count(*) FROM node_rulesets WHERE ruleset_name = ?1 AND version = ?2",
            &.{ ruleset_name, version },
        );
    }

    /// A node reports the version it is actually running. A node with no
    /// assignment has nothing to drift from, so the report is ignored.
    pub fn reportRunning(self: RolloutRepository, node_id: [:0]const u8, ruleset_name: [:0]const u8, version: [:0]const u8) sqlite.Error!void {
        try self.conn.execParams(
            "UPDATE node_rulesets SET running_version = ?3 WHERE node_id = ?1 AND ruleset_name = ?2",
            &.{ node_id, ruleset_name, version },
        );
    }

    /// How many nodes are not running the version they were assigned. A node that
    /// has never reported counts as drifted, as in the PostgreSQL repository:
    /// silence is not evidence of compliance.
    pub fn driftCount(self: RolloutRepository, allocator: std.mem.Allocator, ruleset_name: [:0]const u8) sqlite.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            \\SELECT count(*) FROM node_rulesets
            \\WHERE ruleset_name = ?1 AND (running_version IS NULL OR running_version <> version)
        ,
            &.{ruleset_name},
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

test "sqlite fleet: rulesets are immutable and roll out per node" {
    var conn = try sqlite.Conn.openMemory();
    defer conn.close();
    _ = try apply(&conn, testing.allocator);

    const nodes = NodeRepository{ .conn = &conn };
    const rulesets = RulesetRepository{ .conn = &conn };
    const rollout = RolloutRepository{ .conn = &conn };
    const a = "33333333-3333-3333-3333-333333333333";
    const b = "44444444-4444-4444-4444-444444444444";
    try nodes.enroll(a, "edge-a", "1.0");
    try nodes.enroll(b, "edge-b", "1.0");

    try rulesets.publish("crs", "1", "SecRuleEngine On # v1");
    try rulesets.publish("crs", "2", "SecRuleEngine On # v2");
    {
        const latest = (try rulesets.latest(testing.allocator, "crs")).?;
        defer testing.allocator.free(latest);
        try testing.expectEqualStrings("SecRuleEngine On # v2", latest);
        const first = (try rulesets.atVersion(testing.allocator, "crs", "1")).?;
        defer testing.allocator.free(first);
        try testing.expectEqualStrings("SecRuleEngine On # v1", first);
    }
    // A published version is never rewritten — the same guarantee the PostgreSQL
    // repository makes, so a demo cannot behave in a way a fleet would not.
    try testing.expectError(error.QueryFailed, rulesets.publish("crs", "2", "tampered"));
    try testing.expect((try rulesets.latest(testing.allocator, "absent")) == null);

    // Canary one node, then the whole fleet.
    try rollout.assign(a, "crs", "2");
    {
        const assigned = (try rollout.assignedVersion(testing.allocator, a, "crs")).?;
        defer testing.allocator.free(assigned);
        try testing.expectEqualStrings("2", assigned);
        try testing.expect((try rollout.assignedVersion(testing.allocator, b, "crs")) == null);
    }
    {
        const rolled = (try rollout.assignAll(testing.allocator, "crs", "3")).?;
        defer testing.allocator.free(rolled);
        try testing.expectEqualStrings("2", rolled);
    }

    // Drift: neither node has confirmed v3 yet.
    {
        const drifted = (try rollout.driftCount(testing.allocator, "crs")).?;
        defer testing.allocator.free(drifted);
        try testing.expectEqualStrings("2", drifted);
    }
    try rollout.reportRunning(a, "crs", "3");
    try rollout.reportRunning(b, "crs", "2"); // failed to apply
    {
        const drifted = (try rollout.driftCount(testing.allocator, "crs")).?;
        defer testing.allocator.free(drifted);
        try testing.expectEqualStrings("1", drifted);
    }

    // A report for an unassigned ruleset invents no assignment.
    try rollout.reportRunning(a, "other", "1");
    try testing.expect((try rollout.assignedVersion(testing.allocator, a, "other")) == null);
}
