//! The fleet control-plane's PostgreSQL schema, expressed as ordered migrations
//! applied by `pg.migrate`. This is the initial schema (#52): enrolled nodes,
//! signed rule-set bundles, and the security-event stream. Later migrations
//! append; existing ones are never edited (each is recorded by version).

const std = @import("std");
/// The libpq client this schema and its repositories are built on, re-exported
/// so a caller of `fleet` needs only one import.
pub const pg = @import("pg.zig");
const zstd = @import("zstd");

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
    .{
        .version = 2,
        .name = "alert_rules",
        .sql =
        \\CREATE TABLE alert_rules (
        \\  id            bigserial PRIMARY KEY,
        \\  name          text NOT NULL UNIQUE,
        \\  event_action  text NOT NULL,
        \\  webhook_url   text NOT NULL,
        \\  enabled       boolean NOT NULL DEFAULT true,
        \\  created_at    timestamptz NOT NULL DEFAULT now()
        \\);
        \\CREATE INDEX alert_rules_action_idx ON alert_rules (event_action) WHERE enabled;
        ,
    },
    .{
        .version = 3,
        .name = "node_rulesets",
        .sql =
        \\CREATE TABLE node_rulesets (
        \\  node_id       uuid NOT NULL,
        \\  ruleset_name  text NOT NULL,
        \\  version       integer NOT NULL,
        \\  assigned_at   timestamptz NOT NULL DEFAULT now(),
        \\  PRIMARY KEY (node_id, ruleset_name)
        \\);
        \\CREATE INDEX node_rulesets_version_idx ON node_rulesets (ruleset_name, version);
        ,
    },
    .{
        .version = 4,
        .name = "alert_deliveries",
        .sql =
        \\CREATE TABLE alert_deliveries (
        \\  id            bigserial PRIMARY KEY,
        \\  alert_name    text NOT NULL,
        \\  webhook_url   text NOT NULL,
        \\  status        text NOT NULL,
        \\  http_status   smallint,
        \\  attempted_at  timestamptz NOT NULL DEFAULT now()
        \\);
        \\CREATE INDEX alert_deliveries_name_idx ON alert_deliveries (alert_name, attempted_at DESC);
        ,
    },
    .{
        .version = 5,
        .name = "partition_security_events",
        // Convert the security-event stream to a RANGE partition on occurred_at
        // (#56) so retention is an O(1) partition DROP instead of a bulk DELETE.
        // A partitioned table's primary key must include the partition column,
        // so the key becomes (id, occurred_at). Renaming the old table leaves
        // its index/PK names occupying the schema's global index namespace, so
        // those names are freed (renamed) before the new table reclaims them;
        // the old table — and its renamed indexes — are dropped after its rows
        // are copied into the partitioned table.
        .sql =
        \\ALTER TABLE security_events RENAME TO security_events_unpartitioned;
        \\ALTER INDEX security_events_pkey RENAME TO security_events_unpartitioned_pkey;
        \\ALTER INDEX security_events_occurred_idx RENAME TO security_events_unpartitioned_occurred_idx;
        \\ALTER INDEX security_events_node_idx RENAME TO security_events_unpartitioned_node_idx;
        \\
        \\CREATE TABLE security_events (
        \\  id           bigint GENERATED ALWAYS AS IDENTITY,
        \\  node_id      uuid NOT NULL,
        \\  occurred_at  timestamptz NOT NULL,
        \\  rule_id      bigint,
        \\  phase        smallint,
        \\  action       text,
        \\  severity     smallint,
        \\  client_ip    inet,
        \\  method       text,
        \\  uri          text,
        \\  message      text,
        \\  PRIMARY KEY (id, occurred_at)
        \\) PARTITION BY RANGE (occurred_at);
        \\
        \\CREATE TABLE security_events_default PARTITION OF security_events DEFAULT;
        \\
        \\INSERT INTO security_events (node_id, occurred_at, rule_id, phase, action, severity, client_ip, method, uri, message)
        \\  SELECT node_id, occurred_at, rule_id, phase, action, severity, client_ip, method, uri, message
        \\  FROM security_events_unpartitioned;
        \\
        \\DROP TABLE security_events_unpartitioned;
        \\
        \\CREATE INDEX security_events_occurred_idx ON security_events (occurred_at);
        \\CREATE INDEX security_events_node_idx ON security_events (node_id, occurred_at);
        ,
    },
    .{
        .version = 6,
        .name = "alert_rule_secrets",
        // A per-rule signing secret (#59): when set, a webhook payload is
        // delivered with an HMAC-SHA256 signature so the receiver can verify
        // authenticity. NULL means the webhook is delivered unsigned.
        .sql = "ALTER TABLE alert_rules ADD COLUMN secret text",
    },
    .{
        .version = 7,
        .name = "event_idempotency_keys",
        // A node-assigned idempotency key per event (#55). A node that never
        // received the acknowledgement for a drained batch re-sends it; the
        // unique key makes the re-ingestion a no-op instead of a duplicate.
        // A partitioned table's unique index must include the partition column,
        // so the key is (event_key, occurred_at) — which is exactly the identity
        // of a replayed event, since the node stamps occurred_at before queuing.
        // NULL keys are distinct in PostgreSQL, so events without a key (the
        // legacy path) still insert unconditionally.
        .sql =
        \\ALTER TABLE security_events ADD COLUMN event_key text;
        \\CREATE UNIQUE INDEX security_events_key_idx ON security_events (event_key, occurred_at);
        ,
    },
    .{
        .version = 8,
        .name = "node_running_version",
        // What a node reports it is actually running, against the version it was
        // assigned (#54). The two differ whenever a node has not reconciled yet,
        // failed to apply a bundle, or was changed out of band — which is drift,
        // and is invisible if only the desired state is recorded.
        .sql = "ALTER TABLE node_rulesets ADD COLUMN running_version integer",
    },
};

/// The hex HMAC-SHA256 signature of `payload` under `secret` (#59). Receivers
/// recompute this over the raw body to verify a webhook actually came from the
/// fleet control plane and was not tampered with. The 64-char lowercase-hex
/// digest is written to `out`.
pub fn signPayload(secret: []const u8, payload: []const u8, out: *[64]u8) void {
    var mac: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, payload, secret);
    const hex = "0123456789abcdef";
    for (mac, 0..) |byte, index| {
        out[index * 2] = hex[byte >> 4];
        out[index * 2 + 1] = hex[byte & 0x0f];
    }
}

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

    /// Set (or overwrite) a label on a node — the `labels` jsonb map used to
    /// segment the fleet (region, tier, canary) for targeted rollouts (#50).
    /// Merges into any existing labels, so other keys are preserved.
    pub fn setLabel(self: NodeRepository, node_id: [:0]const u8, key: [:0]const u8, value: [:0]const u8) pg.Error!void {
        try self.conn.execParams(
            "UPDATE nodes SET labels = labels || jsonb_build_object($2::text, $3::text) WHERE node_id = $1",
            &.{ node_id, key, value },
        );
    }

    /// The value of a node's label (caller frees), or null if the node or the
    /// label key is absent.
    pub fn labelOf(self: NodeRepository, allocator: std.mem.Allocator, node_id: [:0]const u8, key: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(allocator, "SELECT labels ->> $2 FROM nodes WHERE node_id = $1", &.{ node_id, key });
    }

    /// The node ids carrying `key` = `value`, ordered — a labeled cohort for a
    /// segmented rollout (the row cursor yields column (0) node_id; caller
    /// `deinit`s it).
    pub fn withLabel(self: NodeRepository, key: [:0]const u8, value: [:0]const u8) pg.Error!pg.Rows {
        return self.conn.query(
            "SELECT node_id::text FROM nodes WHERE labels ->> $1 = $2 ORDER BY node_id",
            &.{ key, value },
        );
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
    /// The node's idempotency key for this event (#55) — any value unique to the
    /// event on that node, e.g. a transaction id. When set, re-ingesting the same
    /// key at the same `occurred_at` is silently skipped rather than duplicated,
    /// so a node may safely re-send a batch it never saw acknowledged. null means
    /// "no key": the event is always inserted.
    key: ?[:0]const u8 = null,
};

/// Ingestion and per-node counts for the security-event stream (#55/#56).
pub const EventRepository = struct {
    conn: *pg.Conn,

    /// Ingest a batch of events in a single transaction (#55): one COMMIT (and
    /// fsync) covers the whole batch, which is how a drained event queue reaches
    /// PostgreSQL efficiently. The batch is all-or-nothing — any failure rolls
    /// the whole batch back.
    ///
    /// Ingestion is idempotent: an event carrying a `key` that was already
    /// ingested at the same `occurred_at` is skipped, so a node that re-sends an
    /// unacknowledged batch does not duplicate events. Returns the number of
    /// events actually inserted; `batch.len` minus that is the number deduplicated.
    pub fn recordBatch(self: EventRepository, batch: []const Event) pg.Error!usize {
        try self.conn.exec("BEGIN");
        var inserted: usize = 0;
        for (batch) |event| {
            inserted += self.conn.execParamsOptCount(
                \\INSERT INTO security_events (node_id, occurred_at, action, uri, message, event_key)
                \\VALUES ($1, $2, $3, $4, $5, $6)
                \\ON CONFLICT (event_key, occurred_at) DO NOTHING
            , &.{ event.node_id, event.occurred_at, event.action, event.uri, event.message, event.key }) catch |err| {
                self.conn.exec("ROLLBACK") catch {};
                return err;
            };
        }
        try self.conn.exec("COMMIT");
        return inserted;
    }

    /// Ingest a batch with `COPY` instead of a statement per event (#55) — one
    /// round trip and one parse for the whole batch, which is what a busy node's
    /// drain needs. Same guarantees as `recordBatch`: one transaction, and keys
    /// already ingested are skipped. Returns the number of events inserted.
    ///
    /// COPY cannot upsert, so the batch lands in a transaction-scoped staging
    /// table and is inserted from there with the same conflict handling. Events
    /// are copied in PostgreSQL's *text* format so the server parses timestamps
    /// exactly as it does everywhere else; the binary format would mean
    /// reimplementing its timestamptz encoding on the client, and any drift
    /// between the two would silently mis-date events.
    pub fn recordBatchCopy(self: EventRepository, allocator: std.mem.Allocator, batch: []const Event) pg.Error!usize {
        if (batch.len == 0) return 0;

        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        for (batch) |event| {
            inline for (.{ event.node_id, event.occurred_at, event.action, event.uri, event.message }) |field| {
                try pg.copyEscape(&payload, allocator, field);
                try payload.append(allocator, '\t');
            }
            // An absent key is a SQL NULL, which is COPY's \N — not the two-character
            // text "\N", which is why it is written unescaped.
            if (event.key) |key| try pg.copyEscape(&payload, allocator, key) else try payload.appendSlice(allocator, "\\N");
            try payload.append(allocator, '\n');
        }

        try self.conn.exec("BEGIN");
        errdefer self.conn.exec("ROLLBACK") catch {};
        try self.conn.exec(
            \\CREATE TEMP TABLE event_batch (
            \\  node_id uuid, occurred_at timestamptz, action text, uri text, message text, event_key text
            \\) ON COMMIT DROP
        );
        try self.conn.copyIn(
            "COPY event_batch (node_id, occurred_at, action, uri, message, event_key) FROM STDIN",
            payload.items,
        );
        const inserted = try self.conn.execParamsOptCount(
            \\INSERT INTO security_events (node_id, occurred_at, action, uri, message, event_key)
            \\SELECT node_id, occurred_at, action, uri, message, event_key FROM event_batch
            \\ON CONFLICT (event_key, occurred_at) DO NOTHING
        , &.{});
        try self.conn.exec("COMMIT");
        return inserted;
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

    /// Export a node's events as an RFC 4180 CSV document (#56) — the archival /
    /// download path for audit search. Columns: occurred_at, action, uri,
    /// message, oldest first. Fields are quoted and internal quotes doubled, so
    /// a URI or message containing commas, quotes, or newlines round-trips
    /// intact. The caller owns and frees the returned bytes.
    pub fn exportCsv(self: EventRepository, allocator: std.mem.Allocator, node_id: [:0]const u8) pg.Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try appendCsvRow(&out, allocator, &.{ "occurred_at", "action", "uri", "message" });
        var rows = try self.conn.query(
            \\SELECT occurred_at::text, coalesce(action, ''), coalesce(uri, ''), coalesce(message, '')
            \\FROM security_events WHERE node_id = $1 ORDER BY occurred_at, id
        , &.{node_id});
        defer rows.deinit();
        while (rows.next()) {
            try appendCsvRow(&out, allocator, &.{ rows.get(0), rows.get(1), rows.get(2), rows.get(3) });
        }
        return out.toOwnedSlice(allocator);
    }
};

/// Append one RFC 4180 CSV record (fields joined by commas, terminated by CRLF).
fn appendCsvRow(out: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const []const u8) error{OutOfMemory}!void {
    for (fields, 0..) |field, index| {
        if (index != 0) try out.append(allocator, ',');
        try appendCsvField(out, allocator, field);
    }
    try out.appendSlice(allocator, "\r\n");
}

/// Append a CSV field, quoting it when it contains a comma, quote, CR, or LF and
/// doubling any embedded quotes.
fn appendCsvField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, field: []const u8) error{OutOfMemory}!void {
    const needs_quote = std.mem.indexOfAny(u8, field, ",\"\r\n") != null;
    if (!needs_quote) {
        try out.appendSlice(allocator, field);
        return;
    }
    try out.append(allocator, '"');
    for (field) |byte| {
        if (byte == '"') try out.append(allocator, '"');
        try out.append(allocator, byte);
    }
    try out.append(allocator, '"');
}

/// A bounded queue of events awaiting ingestion (#55). Nodes enqueue events
/// (their fields are copied in, so callers keep no lifetime obligations) and a
/// worker periodically `drain`s the whole queue to PostgreSQL in one batched
/// transaction. On a drain failure the events are kept for the next attempt, so a
/// transient database outage never drops events, and `persist`/`restore` carry the
/// queue across a crash or restart.
///
/// The queue is bounded, so a long enough outage eventually fills it; `overflow`
/// decides whether the node then refuses new events or sheds its oldest.
pub const EventSpool = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    events: std.ArrayList(Owned) = .empty,
    /// What a full queue does with a new event; see `Overflow`.
    overflow: Overflow = .reject,
    /// How many events a full queue discarded under `.drop_oldest`. Monotonic for
    /// the life of the spool, so a node can expose it and an operator can see that
    /// events were shed rather than delivered.
    dropped: usize = 0,

    const Owned = struct {
        node_id: [:0]u8,
        occurred_at: [:0]u8,
        action: [:0]u8,
        uri: [:0]u8,
        message: [:0]u8,
        key: ?[:0]u8,

        fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
            allocator.free(self.node_id);
            allocator.free(self.occurred_at);
            allocator.free(self.action);
            allocator.free(self.uri);
            allocator.free(self.message);
            if (self.key) |key| allocator.free(key);
        }
    };

    pub const EnqueueError = error{ SpoolFull, OutOfMemory };

    /// What a full queue does with a new event (#55).
    pub const Overflow = enum {
        /// Refuse the event and report SpoolFull, leaving the queue untouched.
        /// The caller decides — a node may sample, log, or stop inspecting rather
        /// than have that choice made for it.
        reject,
        /// Discard the oldest queued event to make room. For a fleet console the
        /// newest events are the ones being watched, so a long outage is better
        /// survived by keeping the recent tail than the stale head. The loss is
        /// counted in `dropped`, never silent.
        drop_oldest,
    };

    pub fn init(allocator: std.mem.Allocator, capacity: usize) EventSpool {
        return .{ .allocator = allocator, .capacity = capacity };
    }

    /// A spool that sheds its oldest events instead of refusing new ones.
    pub fn initShedding(allocator: std.mem.Allocator, capacity: usize) EventSpool {
        return .{ .allocator = allocator, .capacity = capacity, .overflow = .drop_oldest };
    }

    pub fn deinit(self: *EventSpool) void {
        for (self.events.items) |*event| event.deinit(self.allocator);
        self.events.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const EventSpool) usize {
        return self.events.items.len;
    }

    /// Copy an event into the queue. Once `capacity` events are queued the
    /// `overflow` policy decides whether the new event is refused or the oldest is
    /// shed, so memory stays bounded when ingestion stalls either way.
    pub fn enqueue(self: *EventSpool, event: Event) EnqueueError!void {
        return self.enqueueRaw(event.node_id, event.occurred_at, event.action, event.uri, event.message, event.key);
    }

    /// The shared allocation path behind `enqueue` and `restore`. Fields are
    /// `[]const u8` (not necessarily sentinel-terminated) so a decoded snapshot
    /// can reuse it; each is copied into a sentinel-terminated Owned.
    fn enqueueRaw(self: *EventSpool, node_id: []const u8, occurred_at: []const u8, action: []const u8, uri: []const u8, message: []const u8, key: ?[]const u8) EnqueueError!void {
        if (self.events.items.len >= self.capacity) switch (self.overflow) {
            .reject => return error.SpoolFull,
            .drop_oldest => {
                // A zero-capacity spool has nothing to shed, so it can only refuse.
                if (self.capacity == 0) return error.SpoolFull;
                var oldest = self.events.orderedRemove(0);
                oldest.deinit(self.allocator);
                self.dropped += 1;
            },
        };
        const owned_node = try dup(self.allocator, node_id);
        errdefer self.allocator.free(owned_node);
        const owned_occurred = try dup(self.allocator, occurred_at);
        errdefer self.allocator.free(owned_occurred);
        const owned_action = try dup(self.allocator, action);
        errdefer self.allocator.free(owned_action);
        const owned_uri = try dup(self.allocator, uri);
        errdefer self.allocator.free(owned_uri);
        const owned_message = try dup(self.allocator, message);
        errdefer self.allocator.free(owned_message);
        const owned_key = if (key) |value| try dup(self.allocator, value) else null;
        errdefer if (owned_key) |value| self.allocator.free(value);
        try self.events.append(self.allocator, .{
            .node_id = owned_node,
            .occurred_at = owned_occurred,
            .action = owned_action,
            .uri = owned_uri,
            .message = owned_message,
            .key = owned_key,
        });
    }

    /// The batch size from which COPY beats a statement per event. Below it the
    /// staging table COPY needs costs more than the round trips it saves. Measured
    /// by `zig build bench-ingestion` (PostgreSQL 18.4, local socket): COPY is 6×
    /// slower for a single event, level at 16, 1.1× faster at 24, and 3.5× faster
    /// at 1024.
    pub const copy_threshold = 24;

    /// Ingest the whole queue into PostgreSQL in one batched transaction and
    /// clear it. On failure the queue is left intact for a later retry. Returns
    /// the number of events ingested.
    ///
    /// Large batches go through COPY and small ones through a statement per event,
    /// since neither path is faster at every size — see `copy_threshold`.
    pub fn drain(self: *EventSpool, repository: EventRepository) (pg.Error || error{OutOfMemory})!usize {
        if (self.events.items.len == 0) return 0;
        const batch = try self.allocator.alloc(Event, self.events.items.len);
        defer self.allocator.free(batch);
        for (self.events.items, batch) |owned, *slot| slot.* = .{
            .node_id = owned.node_id,
            .occurred_at = owned.occurred_at,
            .action = owned.action,
            .uri = owned.uri,
            .message = owned.message,
            .key = owned.key,
        };
        // Kept on failure — nothing is freed until the batch is committed.
        if (batch.len >= copy_threshold) {
            _ = try repository.recordBatchCopy(self.allocator, batch);
        } else {
            _ = try repository.recordBatch(batch);
        }
        const drained = self.events.items.len;
        for (self.events.items) |*event| event.deinit(self.allocator);
        self.events.clearRetainingCapacity();
        return drained;
    }

    /// Drain, recovering from a severed connection (#55). A node's ingestion
    /// connection outlives many database events it cannot control — a restart, a
    /// failover, an idle-connection reaper — and each one fails the next drain.
    /// Rather than requiring an operator, reconnect (same connection string, so a
    /// failover target resolves afresh) and retry the batch once.
    ///
    /// Retrying is safe because ingestion is idempotent: events already committed
    /// by a drain whose acknowledgement was lost carry the same keys, so they are
    /// skipped rather than duplicated. Events stay queued if the retry also fails,
    /// so a database that is down stays a delay, not a loss.
    pub fn drainReconnecting(self: *EventSpool, repository: EventRepository) (pg.Error || error{OutOfMemory})!usize {
        return self.drain(repository) catch |err| switch (err) {
            // Not a transport failure — a reconnect cannot help.
            error.OutOfMemory => err,
            error.ConnectionFailed, error.QueryFailed => {
                try repository.conn.reset();
                return self.drain(repository);
            },
        };
    }

    fn dup(allocator: std.mem.Allocator, value: []const u8) error{OutOfMemory}![:0]u8 {
        const owned = try allocator.allocSentinel(u8, value.len, 0);
        @memcpy(owned, value);
        return owned;
    }

    // ---- crash durability (#55) ----------------------------------------
    //
    // The queue is snapshotted to a single file so a crash or restart loses at
    // most the events enqueued since the last `persist`. The file is a plaintext
    // header — a magic and a format version, so a restore knows what it is looking
    // at before spending work on the body — followed by a Zstandard frame holding
    // the events: a u32 count, then per event five (u32 length, bytes) fields and a
    // presence-flagged idempotency key, all little-endian. `restore` bounds every
    // read against the decoded body, so a truncated or corrupt snapshot is
    // rejected rather than trusted.
    //
    // A restart is exactly when a node is upgraded, so the version that finds a
    // pending snapshot is often not the one that wrote it: snapshots written
    // before keys existed have no magic and no key field, and are still read
    // (their events restore unkeyed) rather than discarded as corrupt.

    /// Identifies a snapshot carrying the header the first format lacked.
    const snapshot_magic = "WAFSPOOL";
    /// Version 2 stores the events verbatim; version 3 stores the same encoding
    /// compressed. Both are read, so an upgrade never discards a pending queue.
    const snapshot_version_plain: u32 = 2;
    const snapshot_version_compressed: u32 = 3;

    /// A generous ceiling on a snapshot we will read back, guarding against a
    /// corrupt or hostile length header claiming a huge file.
    pub const max_snapshot_bytes = 256 * 1024 * 1024;

    pub const RestoreError = error{ SpoolFull, OutOfMemory, CorruptSnapshot, ReadFailed };

    /// Write the queued events to `sub_path` in `dir` as a length-prefixed
    /// snapshot. Call after enqueues (and after a successful `drain`, which
    /// leaves an empty snapshot) so the file always mirrors the live queue.
    pub fn persist(self: *const EventSpool, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) error{ OutOfMemory, WriteFailed }!void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);
        try appendU32(&buffer, self.allocator, @intCast(self.events.items.len));
        for (self.events.items) |event| {
            inline for (.{ event.node_id, event.occurred_at, event.action, event.uri, event.message }) |field| {
                try appendU32(&buffer, self.allocator, @intCast(field.len));
                try buffer.appendSlice(self.allocator, field);
            }
            // A flag, because an absent key and an empty key are different: only
            // the latter deduplicates.
            try buffer.append(self.allocator, if (event.key == null) 0 else 1);
            if (event.key) |key| {
                try appendU32(&buffer, self.allocator, @intCast(key.len));
                try buffer.appendSlice(self.allocator, key);
            }
        }
        // The header stays readable without decompressing anything, so a restore
        // knows which format it is looking at before it spends work on the body.
        const frame = zstd.compress(self.allocator, buffer.items, zstd.default_level) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // Compression itself has no failure mode over a valid input buffer;
            // report anything else as the write failure it would become.
            else => return error.WriteFailed,
        };
        defer self.allocator.free(frame);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, snapshot_magic);
        try appendU32(&out, self.allocator, snapshot_version_compressed);
        try out.appendSlice(self.allocator, frame);
        dir.writeFile(io, .{ .sub_path = sub_path, .data = out.items }) catch return error.WriteFailed;
    }

    /// Reload a snapshot written by `persist` into this (expected empty) queue.
    /// A missing file is a clean start (no error). Every field is bounds-checked
    /// against the file; a short or malformed snapshot yields CorruptSnapshot.
    pub fn restore(self: *EventSpool, io: std.Io, dir: std.Io.Dir, sub_path: []const u8) RestoreError!void {
        const bytes = dir.readFileAlloc(io, sub_path, self.allocator, .limited(max_snapshot_bytes)) catch |err| switch (err) {
            error.FileNotFound => return,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.ReadFailed,
        };
        defer self.allocator.free(bytes);

        // No magic means a snapshot from before keys were carried; its events
        // restore without one.
        const keyed = std.mem.startsWith(u8, bytes, snapshot_magic);
        var cursor: usize = if (keyed) snapshot_magic.len else 0;
        var body = bytes;
        var decompressed: ?[]u8 = null;
        defer if (decompressed) |owned| self.allocator.free(owned);
        if (keyed) {
            switch (try readU32(bytes, &cursor)) {
                snapshot_version_plain => {},
                snapshot_version_compressed => {
                    const owned = zstd.decompress(self.allocator, bytes[cursor..], max_snapshot_bytes) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        // A frame that is not the frame it claims to be, or that
                        // declares more than a snapshot may hold, is corrupt.
                        error.CorruptFrame, error.FrameTooLarge, error.UnknownContentSize => return error.CorruptSnapshot,
                    };
                    decompressed = owned;
                    body = owned;
                    cursor = 0;
                },
                else => return error.CorruptSnapshot,
            }
        }
        const count = try readU32(body, &cursor);
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            const node_id = try readField(body, &cursor);
            const occurred_at = try readField(body, &cursor);
            const action = try readField(body, &cursor);
            const uri = try readField(body, &cursor);
            const message = try readField(body, &cursor);
            const key = if (keyed) try readOptionalField(body, &cursor) else null;
            try self.enqueueRaw(node_id, occurred_at, action, uri, message, key);
        }
        // Trailing bytes after the declared events mean the snapshot is not what
        // it claims — reject rather than silently ignore the tail.
        if (cursor != body.len) return error.CorruptSnapshot;
    }

    fn appendU32(buffer: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) error{OutOfMemory}!void {
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, value, .little);
        try buffer.appendSlice(allocator, &encoded);
    }

    fn readU32(bytes: []const u8, cursor: *usize) error{CorruptSnapshot}!u32 {
        if (cursor.* + 4 > bytes.len) return error.CorruptSnapshot;
        const value = std.mem.readInt(u32, bytes[cursor.*..][0..4], .little);
        cursor.* += 4;
        return value;
    }

    /// Read a field preceded by a presence flag: 0 for absent, 1 for present.
    fn readOptionalField(bytes: []const u8, cursor: *usize) error{CorruptSnapshot}!?[]const u8 {
        if (cursor.* >= bytes.len) return error.CorruptSnapshot;
        const present = bytes[cursor.*];
        cursor.* += 1;
        return switch (present) {
            0 => null,
            1 => try readField(bytes, cursor),
            else => error.CorruptSnapshot,
        };
    }

    fn readField(bytes: []const u8, cursor: *usize) error{CorruptSnapshot}![]const u8 {
        const field_len = try readU32(bytes, cursor);
        if (cursor.* + field_len > bytes.len) return error.CorruptSnapshot;
        const field = bytes[cursor.*..][0..field_len];
        cursor.* += field_len;
        return field;
    }
};

/// Monthly range partitions for the security-event stream (#56). Creating the
/// upcoming month's partition ahead of time keeps inserts routing to a bounded
/// child table; dropping an old month is O(1) retention (the whole partition
/// and its rows are removed without a bulk DELETE). Year/month are validated
/// integers, so the interpolated partition names and bounds are safe.
pub const EventPartitions = struct {
    conn: *pg.Conn,

    /// Create the partition for `year`-`month` if it does not exist. Its range
    /// is [month-01, next-month-01). A no-op if the partition already exists.
    pub fn ensureMonth(self: EventPartitions, year: u16, month: u8) pg.Error!void {
        if (month < 1 or month > 12) return error.QueryFailed;
        const next_year: u16 = if (month == 12) year + 1 else year;
        const next_month: u8 = if (month == 12) 1 else month + 1;
        var buffer: [320]u8 = undefined;
        const sql = std.fmt.bufPrint(
            &buffer,
            "CREATE TABLE IF NOT EXISTS security_events_{d:0>4}_{d:0>2} PARTITION OF security_events " ++
                "FOR VALUES FROM ('{d:0>4}-{d:0>2}-01') TO ('{d:0>4}-{d:0>2}-01')",
            .{ year, month, year, month, next_year, next_month },
        ) catch return error.QueryFailed;
        buffer[sql.len] = 0;
        try self.conn.exec(buffer[0..sql.len :0]);
    }

    /// Drop the partition for `year`-`month` and all its rows — O(1) retention.
    /// A no-op if the partition does not exist.
    pub fn dropMonth(self: EventPartitions, year: u16, month: u8) pg.Error!void {
        if (month < 1 or month > 12) return error.QueryFailed;
        var buffer: [128]u8 = undefined;
        const sql = std.fmt.bufPrint(&buffer, "DROP TABLE IF EXISTS security_events_{d:0>4}_{d:0>2}", .{ year, month }) catch return error.QueryFailed;
        buffer[sql.len] = 0;
        try self.conn.exec(buffer[0..sql.len :0]);
    }
};

/// Alert rules and webhook targets (#59): when an event with a matching action
/// is ingested, the enabled rules' webhooks are the delivery targets.
pub const AlertRepository = struct {
    conn: *pg.Conn,

    pub fn create(self: AlertRepository, name: [:0]const u8, event_action: [:0]const u8, webhook_url: [:0]const u8) pg.Error!void {
        try self.conn.execParams(
            "INSERT INTO alert_rules (name, event_action, webhook_url) VALUES ($1, $2, $3)",
            &.{ name, event_action, webhook_url },
        );
    }

    pub fn setEnabled(self: AlertRepository, name: [:0]const u8, enabled: bool) pg.Error!void {
        try self.conn.execParams(
            "UPDATE alert_rules SET enabled = $2 WHERE name = $1",
            &.{ name, if (enabled) "true" else "false" },
        );
    }

    /// The webhook URLs of enabled rules that fire on `action`, for dispatch —
    /// a row cursor over column (0) webhook_url; the caller `deinit`s it.
    pub fn webhooksFor(self: AlertRepository, action: [:0]const u8) pg.Error!pg.Rows {
        return self.conn.query(
            "SELECT webhook_url FROM alert_rules WHERE enabled AND event_action = $1 ORDER BY name",
            &.{action},
        );
    }

    /// Set (or clear, with a null secret) a rule's webhook signing secret (#59).
    pub fn setSecret(self: AlertRepository, name: [:0]const u8, secret: ?[:0]const u8) pg.Error!void {
        try self.conn.execParamsOpt("UPDATE alert_rules SET secret = $2 WHERE name = $1", &.{ name, secret });
    }

    /// A rule's signing secret (caller frees), or null if the rule delivers
    /// unsigned or does not exist.
    pub fn secretFor(self: AlertRepository, allocator: std.mem.Allocator, name: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(allocator, "SELECT secret FROM alert_rules WHERE name = $1", &.{name});
    }
};

/// The audit trail of webhook dispatch attempts (#59): every delivery records
/// its outcome so operators can see failing alert channels and drive retries.
pub const AlertDeliveryRepository = struct {
    conn: *pg.Conn,

    /// Record a delivery attempt. `http_status` is null when the host was
    /// unreachable and no HTTP response arrived (distinct from a 5xx response).
    pub fn record(self: AlertDeliveryRepository, alert_name: [:0]const u8, webhook_url: [:0]const u8, status: [:0]const u8, http_status: ?[:0]const u8) pg.Error!void {
        try self.conn.execParamsOpt(
            "INSERT INTO alert_deliveries (alert_name, webhook_url, status, http_status) VALUES ($1, $2, $3, $4::smallint)",
            &.{ alert_name, webhook_url, status, http_status },
        );
    }

    /// How many delivery attempts ended in a given status (e.g. 'failed') —
    /// alert-channel health (caller frees the text count).
    pub fn countByStatus(self: AlertDeliveryRepository, allocator: std.mem.Allocator, status: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(allocator, "SELECT count(*) FROM alert_deliveries WHERE status = $1", &.{status});
    }

    /// The HTTP status of a rule's most recent delivery attempt (caller frees),
    /// or null if the last attempt had no HTTP response or the rule has never
    /// been delivered.
    pub fn lastHttpStatus(self: AlertDeliveryRepository, allocator: std.mem.Allocator, alert_name: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            "SELECT http_status::text FROM alert_deliveries WHERE alert_name = $1 ORDER BY attempted_at DESC, id DESC LIMIT 1",
            &.{alert_name},
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

    /// Publish a signed bundle version (#54): the Ed25519 signature over the
    /// content is stored in the `signature` column, so a node verifies the bundle
    /// was authored by the control plane and not tampered with in transit before
    /// applying it. Like `publish`, versions are immutable.
    ///
    /// The signature is asymmetric on purpose. A bundle is verified by every node
    /// in the fleet, and a shared secret would have to be distributed to all of
    /// them — after which any single compromised node could forge a policy the
    /// whole fleet would accept. With Ed25519 nodes hold only the public key, and
    /// the signing key never leaves the control plane.
    pub fn publishSigned(
        self: RulesetRepository,
        name: [:0]const u8,
        version: [:0]const u8,
        content: [:0]const u8,
        key_pair: std.crypto.sign.Ed25519.KeyPair,
    ) pg.Error!void {
        const signature = key_pair.sign(content, null) catch return error.QueryFailed;
        var hex: [signature_hex_len + 1]u8 = undefined;
        toHex(&signature.toBytes(), hex[0..signature_hex_len]);
        hex[signature_hex_len] = 0;
        // decode($4, 'hex') stores the hex signature into the bytea column.
        try self.conn.execParams(
            "INSERT INTO rulesets (name, version, content, signature) VALUES ($1, $2, $3, decode($4, 'hex'))",
            &.{ name, version, content, hex[0..signature_hex_len :0] },
        );
    }

    /// Verify a bundle's stored signature against `public_key`: true only when the
    /// version exists, is signed, and the signature is valid for the stored
    /// content. Fails closed — an absent or unsigned version, a signature from
    /// another key, and tampered content are all false rather than an error the
    /// caller might ignore.
    pub fn verify(
        self: RulesetRepository,
        name: [:0]const u8,
        version: [:0]const u8,
        public_key: std.crypto.sign.Ed25519.PublicKey,
    ) pg.Error!bool {
        var rows = try self.conn.query(
            "SELECT content, encode(signature, 'hex') FROM rulesets WHERE name = $1 AND version = $2",
            &.{ name, version },
        );
        defer rows.deinit();
        if (!rows.next()) return false; // no such version
        const hex = rows.get(1); // a NULL signature reads as "" — unsigned, so false
        if (hex.len != signature_hex_len) return false;
        var raw: [std.crypto.sign.Ed25519.Signature.encoded_length]u8 = undefined;
        fromHex(hex, &raw) catch return false;
        const signature = std.crypto.sign.Ed25519.Signature.fromBytes(raw);
        signature.verify(rows.get(0), public_key) catch return false;
        return true;
    }

    const signature_hex_len = std.crypto.sign.Ed25519.Signature.encoded_length * 2;
};

const hex_digits = "0123456789abcdef";

/// Write `bytes` as lowercase hex into `out`, which must be twice as long.
fn toHex(bytes: []const u8, out: []u8) void {
    for (bytes, 0..) |byte, index| {
        out[index * 2] = hex_digits[byte >> 4];
        out[index * 2 + 1] = hex_digits[byte & 0x0f];
    }
}

/// Decode lowercase or uppercase hex into `out`, rejecting anything else.
fn fromHex(hex: []const u8, out: []u8) error{InvalidHex}!void {
    if (hex.len != out.len * 2) return error.InvalidHex;
    for (out, 0..) |*byte, index| {
        const high = try hexDigit(hex[index * 2]);
        const low = try hexDigit(hex[index * 2 + 1]);
        byte.* = (high << 4) | low;
    }
}

fn hexDigit(char: u8) error{InvalidHex}!u8 {
    return switch (char) {
        '0'...'9' => char - '0',
        'a'...'f' => char - 'a' + 10,
        'A'...'F' => char - 'A' + 10,
        else => error.InvalidHex,
    };
}

/// Which ruleset version each node is assigned to run (#54). The control plane
/// records the desired version per node; a node reconciles by fetching the
/// content of its assigned version from `RulesetRepository`. Assignment is
/// idempotent — re-assigning a node updates its target and re-stamps the time.
pub const RolloutRepository = struct {
    conn: *pg.Conn,

    /// Assign one node to a ruleset version (staged/canary rollout).
    pub fn assign(self: RolloutRepository, node_id: [:0]const u8, ruleset_name: [:0]const u8, version: [:0]const u8) pg.Error!void {
        try self.conn.execParams(
            \\INSERT INTO node_rulesets (node_id, ruleset_name, version) VALUES ($1, $2, $3)
            \\ON CONFLICT (node_id, ruleset_name) DO UPDATE SET version = EXCLUDED.version, assigned_at = now()
        , &.{ node_id, ruleset_name, version });
    }

    /// Assign every enrolled node to a ruleset version (fleet-wide rollout).
    /// Returns the number of nodes assigned (caller frees the text count).
    pub fn assignAll(self: RolloutRepository, allocator: std.mem.Allocator, ruleset_name: [:0]const u8, version: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            \\WITH rolled AS (
            \\  INSERT INTO node_rulesets (node_id, ruleset_name, version)
            \\  SELECT node_id, $1, $2 FROM nodes
            \\  ON CONFLICT (node_id, ruleset_name) DO UPDATE SET version = EXCLUDED.version, assigned_at = now()
            \\  RETURNING 1
            \\) SELECT count(*) FROM rolled
        ,
            &.{ ruleset_name, version },
        );
    }

    /// Assign every node carrying `label_key` = `label_value` to a ruleset
    /// version — a segmented rollout to a labeled cohort (region, tier, canary),
    /// pairing `NodeRepository.setLabel`/`withLabel` with staged distribution.
    /// Returns the number of nodes assigned (caller frees the text count).
    pub fn assignByLabel(self: RolloutRepository, allocator: std.mem.Allocator, label_key: [:0]const u8, label_value: [:0]const u8, ruleset_name: [:0]const u8, version: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            \\WITH rolled AS (
            \\  INSERT INTO node_rulesets (node_id, ruleset_name, version)
            \\  SELECT node_id, $3, $4 FROM nodes WHERE labels ->> $1 = $2
            \\  ON CONFLICT (node_id, ruleset_name) DO UPDATE SET version = EXCLUDED.version, assigned_at = now()
            \\  RETURNING 1
            \\) SELECT count(*) FROM rolled
        ,
            &.{ label_key, label_value, ruleset_name, version },
        );
    }

    /// The version a node is assigned to run for `ruleset_name` (caller frees),
    /// or null if the node has no assignment.
    pub fn assignedVersion(self: RolloutRepository, allocator: std.mem.Allocator, node_id: [:0]const u8, ruleset_name: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            "SELECT version::text FROM node_rulesets WHERE node_id = $1 AND ruleset_name = $2",
            &.{ node_id, ruleset_name },
        );
    }

    /// How the cohort already assigned a version is faring — the evidence a staged
    /// rollout needs before it widens (#54).
    pub const CohortHealth = struct {
        /// Nodes assigned this version.
        assigned: usize,
        /// Of those, how many have not been seen within the heartbeat window.
        unresponsive: usize,
        /// Of those, how many have not confirmed they are running it.
        unconfirmed: usize,

        /// Whether the cohort is evidence the version is safe to widen to: it has
        /// to exist, every node has to be responsive, and every node has to have
        /// confirmed the version it runs.
        pub fn isHealthy(self: CohortHealth) bool {
            return self.assigned > 0 and self.unresponsive == 0 and self.unconfirmed == 0;
        }
    };

    /// Measure the cohort assigned `version`, counting a node as unresponsive when
    /// its last heartbeat is older than `max_age_seconds` (or it has never sent
    /// one).
    pub fn healthOfVersion(
        self: RolloutRepository,
        ruleset_name: [:0]const u8,
        version: [:0]const u8,
        max_age_seconds: u32,
    ) pg.Error!CohortHealth {
        var seconds_buffer: [16]u8 = undefined;
        const seconds = std.fmt.bufPrint(&seconds_buffer, "{d}", .{max_age_seconds}) catch return error.QueryFailed;
        seconds_buffer[seconds.len] = 0;
        var rows = try self.conn.query(
            \\SELECT count(*),
            \\  count(*) FILTER (WHERE n.last_seen_at IS NULL OR n.last_seen_at < now() - make_interval(secs => $3::int)),
            \\  count(*) FILTER (WHERE nr.running_version IS DISTINCT FROM nr.version)
            \\FROM node_rulesets nr JOIN nodes n USING (node_id)
            \\WHERE nr.ruleset_name = $1 AND nr.version = $2::int
        , &.{ ruleset_name, version, seconds_buffer[0..seconds.len :0] });
        defer rows.deinit();
        if (!rows.next()) return error.QueryFailed; // aggregates always return a row
        return .{
            .assigned = std.fmt.parseInt(usize, rows.get(0), 10) catch return error.QueryFailed,
            .unresponsive = std.fmt.parseInt(usize, rows.get(1), 10) catch return error.QueryFailed,
            .unconfirmed = std.fmt.parseInt(usize, rows.get(2), 10) catch return error.QueryFailed,
        };
    }

    /// Widen a rollout to the whole fleet only if the cohort already on `version`
    /// is healthy — the gate between a canary and everyone (#54). Returns the
    /// number of nodes moved, or null when the gate held the rollout back.
    ///
    /// An empty cohort fails the gate. Rolling out to the fleet on the strength of
    /// a canary that was never actually deployed is exactly the mistake a gate
    /// exists to prevent, so the absence of evidence is not treated as evidence.
    pub fn advanceIfHealthy(
        self: RolloutRepository,
        allocator: std.mem.Allocator,
        ruleset_name: [:0]const u8,
        version: [:0]const u8,
        max_age_seconds: u32,
    ) pg.Error!?[]u8 {
        const health = try self.healthOfVersion(ruleset_name, version, max_age_seconds);
        if (!health.isHealthy()) return null;
        return self.assignAll(allocator, ruleset_name, version);
    }

    /// A node reports the version it is actually running (#54), normally on its
    /// heartbeat. A node with no assignment for this ruleset has nothing to drift
    /// from, so the report is ignored rather than inventing an assignment.
    pub fn reportRunning(self: RolloutRepository, node_id: [:0]const u8, ruleset_name: [:0]const u8, version: [:0]const u8) pg.Error!void {
        try self.conn.execParams(
            "UPDATE node_rulesets SET running_version = $3::int WHERE node_id = $1 AND ruleset_name = $2",
            &.{ node_id, ruleset_name, version },
        );
    }

    /// The nodes whose running version is not the version they were assigned —
    /// drift (#54). A node that has never reported counts as drifted: the control
    /// plane has no evidence it is running the policy it was given, and treating
    /// silence as compliance is how a fleet quietly diverges. The cursor yields
    /// columns (0) node_id, (1) assigned version, (2) running version or empty when
    /// never reported; the caller `deinit`s it.
    pub fn drifted(self: RolloutRepository, ruleset_name: [:0]const u8) pg.Error!pg.Rows {
        return self.conn.query(
            \\SELECT node_id::text, version::text, coalesce(running_version::text, '')
            \\FROM node_rulesets
            \\WHERE ruleset_name = $1 AND running_version IS DISTINCT FROM version
            \\ORDER BY node_id
        , &.{ruleset_name});
    }

    /// How many nodes have drifted from their assigned version (caller frees the
    /// text count).
    pub fn driftCount(self: RolloutRepository, allocator: std.mem.Allocator, ruleset_name: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            \\SELECT count(*) FROM node_rulesets
            \\WHERE ruleset_name = $1 AND running_version IS DISTINCT FROM version
        ,
            &.{ruleset_name},
        );
    }

    /// How many nodes are assigned to a specific version — rollout progress /
    /// convergence (caller frees the text count).
    pub fn countOnVersion(self: RolloutRepository, allocator: std.mem.Allocator, ruleset_name: [:0]const u8, version: [:0]const u8) pg.Error!?[]u8 {
        return self.conn.queryScalarParams(
            allocator,
            "SELECT count(*) FROM node_rulesets WHERE ruleset_name = $1 AND version = $2",
            &.{ ruleset_name, version },
        );
    }
};

// ---- tests --------------------------------------------------------------
//
// The integration tests need a live PostgreSQL named by PG_TEST_DSN and skip
// when it is unset. Each one runs against a freshly migrated, empty schema
// (`TestDb`), so tests neither see each other's rows nor depend on order.

const testing = std.testing;

/// A connection to a private schema in the PG_TEST_DSN database with the fleet
/// schema freshly applied, so each test starts from empty tables at the latest
/// version and never contends with a test running in parallel.
const TestDb = struct {
    /// Isolate and migrate. Returns error.SkipZigTest when PG_TEST_DSN is unset.
    fn open(allocator: std.mem.Allocator) !pg.TestSchema {
        var db = try pg.TestSchema.open(allocator);
        _ = apply(&db.conn, allocator) catch |err| {
            db.close();
            return err;
        };
        return db;
    }

    /// Isolate without migrating — for tests that assert on `apply` itself.
    fn openUnmigrated(allocator: std.mem.Allocator) !pg.TestSchema {
        return pg.TestSchema.open(allocator);
    }
};

test "signPayload matches the HMAC-SHA256 reference vector" {
    // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
    var out: [64]u8 = undefined;
    signPayload("Jefe", "what do ya want for nothing?", &out);
    try testing.expectEqualStrings("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", &out);

    // A different payload (a tampered body) yields a different signature.
    var other: [64]u8 = undefined;
    signPayload("Jefe", "what do ya want for something?", &other);
    try testing.expect(!std.mem.eql(u8, &out, &other));
}

test "the fleet schema applies to a clean database and is idempotent" {
    // Start from a clean slate so the migration exercises real DDL.
    var db = try TestDb.openUnmigrated(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    try testing.expectEqual(migrations.len, try apply(conn, testing.allocator));
    try testing.expectEqual(@as(usize, 0), try apply(conn, testing.allocator)); // idempotent

    // The core tables exist and are usable.
    for ([_][:0]const u8{ "nodes", "rulesets", "security_events", "alert_rules" }) |table_name| {
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
}

test "event retention prunes only events past the window" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const events = EventRepository{ .conn = conn };
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
}

test "csv fields are quoted and escaped per RFC 4180" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try appendCsvRow(&out, testing.allocator, &.{ "plain", "has,comma", "has\"quote", "line\nbreak" });
    try testing.expectEqualStrings("plain,\"has,comma\",\"has\"\"quote\",\"line\nbreak\"\r\n", out.items);
}

test "event export produces escaped CSV" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const events = EventRepository{ .conn = conn };
    const node_id = "44444444-4444-4444-4444-444444444444";
    try events.recordAt(node_id, "2024-01-01T00:00:00Z", "deny", "/a?id=1", "first");
    // A URI with a comma and a quote must be CSV-quoted and its quote doubled.
    try events.recordAt(node_id, "2024-01-02T00:00:00Z", "pass", "/x,\"y\"", "second");

    const csv = try events.exportCsv(testing.allocator, node_id);
    defer testing.allocator.free(csv);

    // Header, then the two events oldest-first; the tricky URI is quoted.
    try testing.expect(std.mem.startsWith(u8, csv, "occurred_at,action,uri,message\r\n"));
    try testing.expect(std.mem.indexOf(u8, csv, ",deny,/a?id=1,first\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, csv, ",pass,\"/x,\"\"y\"\"\",second\r\n") != null);
    // Exactly three CRLF-terminated records (header + 2 rows).
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, csv, "\r\n"));
}

test "event spool buffers, drains in a batch, and retains on failure" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;
    const events = EventRepository{ .conn = conn };
    const node_id = "55555555-5555-5555-5555-555555555555";

    var spool = EventSpool.init(testing.allocator, 3);
    defer spool.deinit();

    try spool.enqueue(.{ .node_id = node_id, .occurred_at = "2024-01-01T00:00:00Z", .action = "deny", .uri = "/a", .message = "1" });
    try spool.enqueue(.{ .node_id = node_id, .occurred_at = "2024-01-01T00:00:01Z", .action = "pass", .uri = "/b", .message = "2" });
    try testing.expectEqual(@as(usize, 2), spool.len());

    // Drain ingests the batch and empties the spool.
    try testing.expectEqual(@as(usize, 2), try spool.drain(events));
    try testing.expectEqual(@as(usize, 0), spool.len());
    const count = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("2", count);

    // Capacity is enforced (backpressure).
    for (0..3) |_| try spool.enqueue(.{ .node_id = node_id, .occurred_at = "2024-01-02T00:00:00Z", .action = "deny", .uri = "/c", .message = "x" });
    try testing.expectError(error.SpoolFull, spool.enqueue(.{ .node_id = node_id, .occurred_at = "2024-01-02T00:00:00Z", .action = "deny", .uri = "/d", .message = "y" }));

    // A drain that fails (one row has a bad timestamp) keeps the whole spool for
    // a retry — no events are lost on a transient database error.
    var retry_spool = EventSpool.init(testing.allocator, 8);
    defer retry_spool.deinit();
    try retry_spool.enqueue(.{ .node_id = node_id, .occurred_at = "2024-03-01T00:00:00Z", .action = "deny", .uri = "/ok", .message = "good" });
    try retry_spool.enqueue(.{ .node_id = node_id, .occurred_at = "not-a-timestamp", .action = "deny", .uri = "/bad", .message = "bad" });
    try testing.expectError(error.QueryFailed, retry_spool.drain(events));
    try testing.expectEqual(@as(usize, 2), retry_spool.len()); // retained for retry
}

test "event spool survives a crash via its on-disk snapshot" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // A missing snapshot is a clean start, not an error.
    var fresh = EventSpool.init(testing.allocator, 8);
    defer fresh.deinit();
    try fresh.restore(io, tmp.dir, "spool.bin");
    try testing.expectEqual(@as(usize, 0), fresh.len());

    // Enqueue events (including an SQLi-shaped URI with embedded quotes) and
    // snapshot them to disk — as a worker would before a crash.
    {
        var spool = EventSpool.init(testing.allocator, 8);
        defer spool.deinit();
        try spool.enqueue(.{ .node_id = "77777777-7777-7777-7777-777777777777", .occurred_at = "2024-05-01T00:00:00Z", .action = "deny", .uri = "/a?id=1", .message = "first" });
        try spool.enqueue(.{ .node_id = "88888888-8888-8888-8888-888888888888", .occurred_at = "2024-05-01T00:00:01Z", .action = "pass", .uri = "/'; DROP TABLE nodes; --", .message = "second" });
        try spool.persist(io, tmp.dir, "spool.bin");
    }

    // A brand-new spool (as after a restart) recovers both events verbatim.
    var recovered = EventSpool.init(testing.allocator, 8);
    defer recovered.deinit();
    try recovered.restore(io, tmp.dir, "spool.bin");
    try testing.expectEqual(@as(usize, 2), recovered.len());
    try testing.expectEqualStrings("77777777-7777-7777-7777-777777777777", recovered.events.items[0].node_id);
    try testing.expectEqualStrings("/a?id=1", recovered.events.items[0].uri);
    try testing.expectEqualStrings("/'; DROP TABLE nodes; --", recovered.events.items[1].uri);
    try testing.expectEqualStrings("second", recovered.events.items[1].message);

    // Persisting an empty spool (as after a successful drain) leaves an empty
    // snapshot, so recovery yields nothing.
    var empty = EventSpool.init(testing.allocator, 8);
    defer empty.deinit();
    try empty.persist(io, tmp.dir, "spool.bin");
    var reloaded = EventSpool.init(testing.allocator, 8);
    defer reloaded.deinit();
    try reloaded.restore(io, tmp.dir, "spool.bin");
    try testing.expectEqual(@as(usize, 0), reloaded.len());

    // A truncated snapshot is rejected rather than trusted.
    try tmp.dir.writeFile(io, .{ .sub_path = "corrupt.bin", .data = "WAFSPOOL" ++ &[_]u8{ 2, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 'a', 'b' } });
    var corrupt = EventSpool.init(testing.allocator, 8);
    defer corrupt.deinit();
    try testing.expectError(error.CorruptSnapshot, corrupt.restore(io, tmp.dir, "corrupt.bin"));

    // A snapshot claiming a format this build does not know is rejected, rather
    // than decoded as if its layout were the familiar one.
    try tmp.dir.writeFile(io, .{ .sub_path = "future.bin", .data = "WAFSPOOL" ++ &[_]u8{ 99, 0, 0, 0, 0, 0, 0, 0 } });
    var future = EventSpool.init(testing.allocator, 8);
    defer future.deinit();
    try testing.expectError(error.CorruptSnapshot, future.restore(io, tmp.dir, "future.bin"));
}

test "spooled events keep their idempotency keys across a snapshot" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var spool = EventSpool.init(testing.allocator, 8);
        defer spool.deinit();
        try spool.enqueue(.{ .node_id = "99999999-9999-9999-9999-999999999999", .occurred_at = "2024-07-01T00:00:00Z", .action = "deny", .uri = "/a", .message = "keyed", .key = "txn-42" });
        // An absent key and an empty key are different: only the latter has an
        // identity, so the snapshot must not conflate them.
        try spool.enqueue(.{ .node_id = "99999999-9999-9999-9999-999999999999", .occurred_at = "2024-07-01T00:00:01Z", .action = "deny", .uri = "/b", .message = "unkeyed" });
        try spool.enqueue(.{ .node_id = "99999999-9999-9999-9999-999999999999", .occurred_at = "2024-07-01T00:00:02Z", .action = "deny", .uri = "/c", .message = "empty key", .key = "" });
        try spool.persist(io, tmp.dir, "keyed.bin");
    }

    var recovered = EventSpool.init(testing.allocator, 8);
    defer recovered.deinit();
    try recovered.restore(io, tmp.dir, "keyed.bin");
    try testing.expectEqual(@as(usize, 3), recovered.len());
    try testing.expectEqualStrings("txn-42", recovered.events.items[0].key.?);
    try testing.expect(recovered.events.items[1].key == null);
    try testing.expectEqualStrings("", recovered.events.items[2].key.?);

    // A snapshot written before keys existed has no header and no key field. A
    // restart is when a node is upgraded, so that file must still be read — its
    // events restore unkeyed rather than being discarded as corrupt.
    const legacy: []const u8 = &([_]u8{ 1, 0, 0, 0 } ++ // one event
        [_]u8{ 2, 0, 0, 0 } ++ "id".* ++
        [_]u8{ 1, 0, 0, 0 } ++ "t".* ++
        [_]u8{ 4, 0, 0, 0 } ++ "deny".* ++
        [_]u8{ 2, 0, 0, 0 } ++ "/x".* ++
        [_]u8{ 3, 0, 0, 0 } ++ "old".*);
    try tmp.dir.writeFile(io, .{ .sub_path = "legacy.bin", .data = legacy });
    var upgraded = EventSpool.init(testing.allocator, 8);
    defer upgraded.deinit();
    try upgraded.restore(io, tmp.dir, "legacy.bin");
    try testing.expectEqual(@as(usize, 1), upgraded.len());
    try testing.expectEqualStrings("old", upgraded.events.items[0].message);
    try testing.expect(upgraded.events.items[0].key == null);
}

test "batched event ingestion commits the whole batch atomically" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const events = EventRepository{ .conn = conn };
    const node_id = "44444444-4444-4444-4444-444444444444";
    const batch = [_]Event{
        .{ .node_id = node_id, .occurred_at = "2024-01-01T00:00:00Z", .action = "deny", .uri = "/a", .message = "1" },
        .{ .node_id = node_id, .occurred_at = "2024-01-01T00:00:01Z", .action = "deny", .uri = "/b", .message = "2" },
        .{ .node_id = node_id, .occurred_at = "2024-01-01T00:00:02Z", .action = "pass", .uri = "/c", .message = "3" },
    };
    try testing.expectEqual(@as(usize, 3), try events.recordBatch(&batch));
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
}

test "keyed event ingestion is idempotent across a re-sent batch" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const events = EventRepository{ .conn = conn };
    const node_id = "55555555-5555-5555-5555-555555555555";
    const batch = [_]Event{
        .{ .node_id = node_id, .occurred_at = "2024-03-01T00:00:00Z", .action = "deny", .uri = "/a", .message = "1", .key = "txn-1" },
        .{ .node_id = node_id, .occurred_at = "2024-03-01T00:00:01Z", .action = "deny", .uri = "/b", .message = "2", .key = "txn-2" },
    };
    try testing.expectEqual(@as(usize, 2), try events.recordBatch(&batch));

    // The node never saw the acknowledgement and re-sends the same batch: every
    // event is recognized by its key and skipped, so nothing is duplicated.
    try testing.expectEqual(@as(usize, 0), try events.recordBatch(&batch));

    // A re-send that also carries new events ingests only the new ones.
    const overlapping = [_]Event{
        batch[1],
        .{ .node_id = node_id, .occurred_at = "2024-03-01T00:00:02Z", .action = "pass", .uri = "/c", .message = "3", .key = "txn-3" },
    };
    try testing.expectEqual(@as(usize, 1), try events.recordBatch(&overlapping));

    const count = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("3", count);

    // Keyless events carry no identity, so they are always ingested — two
    // otherwise-identical unkeyed events are two events.
    const unkeyed = [_]Event{
        .{ .node_id = node_id, .occurred_at = "2024-03-02T00:00:00Z", .action = "deny", .uri = "/d", .message = "4" },
        .{ .node_id = node_id, .occurred_at = "2024-03-02T00:00:00Z", .action = "deny", .uri = "/d", .message = "4" },
    };
    try testing.expectEqual(@as(usize, 2), try events.recordBatch(&unkeyed));

    // The same key at a different occurred_at is a different event: the key
    // deduplicates a replay, not two genuine events that share a transaction id.
    const later = [_]Event{
        .{ .node_id = node_id, .occurred_at = "2024-03-03T00:00:00Z", .action = "deny", .uri = "/a", .message = "5", .key = "txn-1" },
    };
    try testing.expectEqual(@as(usize, 1), try events.recordBatch(&later));

    const total = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(total);
    try testing.expectEqualStrings("6", total);
}

test "COPY ingestion round-trips awkward fields and deduplicates by key" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const events = EventRepository{ .conn = conn };
    const node_id = "77777777-7777-7777-7777-777777777777";
    const batch = [_]Event{
        // Fields carrying COPY's own delimiters: a tab, a newline, and a
        // backslash must survive rather than shifting the columns after them.
        .{ .node_id = node_id, .occurred_at = "2024-05-01T00:00:00Z", .action = "deny", .uri = "/a\tb", .message = "line\nbreak", .key = "copy-1" },
        .{ .node_id = node_id, .occurred_at = "2024-05-01T00:00:01Z", .action = "deny", .uri = "/c\\d", .message = "back\\slash", .key = "copy-2" },
        // A keyless event, which must be stored with a NULL key rather than the
        // literal text "\N".
        .{ .node_id = node_id, .occurred_at = "2024-05-01T00:00:02Z", .action = "pass", .uri = "/e", .message = "no key" },
    };
    try testing.expectEqual(@as(usize, 3), try events.recordBatchCopy(testing.allocator, &batch));

    // Re-copying the same batch ingests only the keyless event, whose NULL key
    // carries no identity; the two keyed events are recognized and skipped.
    try testing.expectEqual(@as(usize, 1), try events.recordBatchCopy(testing.allocator, &batch));

    const count = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("4", count);

    // The awkward fields came back byte-for-byte.
    const uri = (try conn.queryScalarParams(
        testing.allocator,
        "SELECT uri FROM security_events WHERE event_key = $1",
        &.{"copy-1"},
    )).?;
    defer testing.allocator.free(uri);
    try testing.expectEqualStrings("/a\tb", uri);
    const message = (try conn.queryScalarParams(
        testing.allocator,
        "SELECT message FROM security_events WHERE event_key = $1",
        &.{"copy-1"},
    )).?;
    defer testing.allocator.free(message);
    try testing.expectEqualStrings("line\nbreak", message);
    const escaped = (try conn.queryScalarParams(
        testing.allocator,
        "SELECT uri || ' ' || message FROM security_events WHERE event_key = $1",
        &.{"copy-2"},
    )).?;
    defer testing.allocator.free(escaped);
    try testing.expectEqualStrings("/c\\d back\\slash", escaped);

    // The keyless events really are NULL-keyed, not the text "\N".
    const nulls = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM security_events WHERE event_key IS NULL")).?;
    defer testing.allocator.free(nulls);
    try testing.expectEqualStrings("2", nulls);

    // A batch the server rejects leaves nothing behind, staging table included.
    const bad = [_]Event{
        .{ .node_id = node_id, .occurred_at = "not-a-timestamp", .action = "deny", .uri = "/x", .message = "bad", .key = "copy-3" },
    };
    try testing.expectError(error.QueryFailed, events.recordBatchCopy(testing.allocator, &bad));
    const after = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(after);
    try testing.expectEqualStrings("4", after);

    // The failed batch's rollback left the connection usable.
    try testing.expectEqual(@as(usize, 1), try events.recordBatchCopy(testing.allocator, &.{
        .{ .node_id = node_id, .occurred_at = "2024-05-02T00:00:00Z", .action = "deny", .uri = "/f", .message = "after failure", .key = "copy-4" },
    }));
}

test "a full spool refuses or sheds according to its overflow policy" {
    const node_id = "cccccccc-cccc-cccc-cccc-cccccccccccc";

    // The default: a full queue refuses new events and keeps what it has, so the
    // caller learns ingestion is stalled and decides what to do about it.
    var rejecting = EventSpool.init(testing.allocator, 2);
    defer rejecting.deinit();
    try rejecting.enqueue(.{ .node_id = node_id, .occurred_at = "t", .action = "deny", .uri = "/1", .message = "first" });
    try rejecting.enqueue(.{ .node_id = node_id, .occurred_at = "t", .action = "deny", .uri = "/2", .message = "second" });
    try testing.expectError(error.SpoolFull, rejecting.enqueue(.{ .node_id = node_id, .occurred_at = "t", .action = "deny", .uri = "/3", .message = "third" }));
    try testing.expectEqual(@as(usize, 2), rejecting.len());
    try testing.expectEqualStrings("first", rejecting.events.items[0].message);
    try testing.expectEqual(@as(usize, 0), rejecting.dropped);

    // Shedding: the oldest event makes way for the newest, and the queue stays at
    // capacity. The count of what was shed is visible rather than silent.
    var shedding = EventSpool.initShedding(testing.allocator, 2);
    defer shedding.deinit();
    try shedding.enqueue(.{ .node_id = node_id, .occurred_at = "t", .action = "deny", .uri = "/1", .message = "first" });
    try shedding.enqueue(.{ .node_id = node_id, .occurred_at = "t", .action = "deny", .uri = "/2", .message = "second" });
    try shedding.enqueue(.{ .node_id = node_id, .occurred_at = "t", .action = "deny", .uri = "/3", .message = "third" });
    try testing.expectEqual(@as(usize, 2), shedding.len());
    try testing.expectEqualStrings("second", shedding.events.items[0].message);
    try testing.expectEqualStrings("third", shedding.events.items[1].message);
    try testing.expectEqual(@as(usize, 1), shedding.dropped);

    try shedding.enqueue(.{ .node_id = node_id, .occurred_at = "t", .action = "deny", .uri = "/4", .message = "fourth" });
    try testing.expectEqual(@as(usize, 2), shedding.dropped);
    try testing.expectEqualStrings("fourth", shedding.events.items[1].message);

    // A zero-capacity spool has nothing to shed, so it refuses under either policy
    // rather than looping or discarding the event it was just handed.
    var empty_capacity = EventSpool.initShedding(testing.allocator, 0);
    defer empty_capacity.deinit();
    try testing.expectError(error.SpoolFull, empty_capacity.enqueue(.{ .node_id = node_id, .occurred_at = "t", .action = "deny", .uri = "/x", .message = "none" }));
    try testing.expectEqual(@as(usize, 0), empty_capacity.dropped);
}

test "a snapshot is compressed, and an uncompressed one still restores" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // A node buffering events during an outage queues many that differ only in
    // their query string — the redundancy compression exists to remove.
    var raw_bytes: usize = 0;
    {
        var spool = EventSpool.init(testing.allocator, 512);
        defer spool.deinit();
        var buffer: [64]u8 = undefined;
        for (0..200) |index| {
            const uri = try std.fmt.bufPrint(&buffer, "/search?q={d}", .{index});
            buffer[uri.len] = 0;
            try spool.enqueue(.{
                .node_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                .occurred_at = "2024-09-01T00:00:00Z",
                .action = "deny",
                .uri = buffer[0..uri.len :0],
                .message = "SQL injection detected",
            });
        }
        for (spool.events.items) |event| {
            raw_bytes += event.node_id.len + event.occurred_at.len + event.action.len + event.uri.len + event.message.len;
        }
        try spool.persist(io, tmp.dir, "compressed.bin");
    }

    const stat = try tmp.dir.statFile(io, "compressed.bin", .{});
    try testing.expect(stat.size * 4 < raw_bytes);

    var recovered = EventSpool.init(testing.allocator, 512);
    defer recovered.deinit();
    try recovered.restore(io, tmp.dir, "compressed.bin");
    try testing.expectEqual(@as(usize, 200), recovered.len());
    try testing.expectEqualStrings("/search?q=199", recovered.events.items[199].uri);

    // A snapshot written before the body was compressed declares version 2 and
    // stores the events verbatim. A node upgrading with a pending queue must still
    // recover it, so that format is read as well.
    const plain: []const u8 = "WAFSPOOL" ++ &([_]u8{ 2, 0, 0, 0 } ++ // version 2, plaintext body
        [_]u8{ 1, 0, 0, 0 } ++ // one event
        [_]u8{ 4, 0, 0, 0 } ++ "node".* ++
        [_]u8{ 1, 0, 0, 0 } ++ "t".* ++
        [_]u8{ 4, 0, 0, 0 } ++ "deny".* ++
        [_]u8{ 2, 0, 0, 0 } ++ "/p".* ++
        [_]u8{ 5, 0, 0, 0 } ++ "plain".* ++
        [_]u8{1} ++ [_]u8{ 3, 0, 0, 0 } ++ "key".*);
    try tmp.dir.writeFile(io, .{ .sub_path = "plain.bin", .data = plain });
    var from_plain = EventSpool.init(testing.allocator, 8);
    defer from_plain.deinit();
    try from_plain.restore(io, tmp.dir, "plain.bin");
    try testing.expectEqual(@as(usize, 1), from_plain.len());
    try testing.expectEqualStrings("plain", from_plain.events.items[0].message);
    try testing.expectEqualStrings("key", from_plain.events.items[0].key.?);
}

test "a drain at the threshold ingests through COPY" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const events = EventRepository{ .conn = conn };
    const node_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    var spool = EventSpool.init(testing.allocator, 128);
    defer spool.deinit();

    // A batch at the threshold takes the COPY path; every event must still arrive
    // exactly once, keys and awkward fields included.
    var buffer: [64]u8 = undefined;
    for (0..EventSpool.copy_threshold) |index| {
        const key = try std.fmt.bufPrint(&buffer, "drain-{d}", .{index});
        buffer[key.len] = 0;
        try spool.enqueue(.{
            .node_id = node_id,
            .occurred_at = "2024-08-01T00:00:00Z",
            .action = "deny",
            .uri = "/tab\there",
            .message = "copied",
            .key = buffer[0..key.len :0],
        });
    }
    try testing.expectEqual(@as(usize, EventSpool.copy_threshold), try spool.drain(events));
    try testing.expectEqual(@as(usize, 0), spool.len());

    const count = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(count);
    var expected: [8]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "{d}", .{EventSpool.copy_threshold}), count);
    const uri = (try conn.queryScalarParams(testing.allocator, "SELECT uri FROM security_events WHERE event_key = $1", &.{"drain-0"})).?;
    defer testing.allocator.free(uri);
    try testing.expectEqualStrings("/tab\there", uri);
}

test "a spool drain survives the server severing the connection" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const events = EventRepository{ .conn = conn };
    const node_id = "66666666-6666-6666-6666-666666666666";
    var spool = EventSpool.init(testing.allocator, 8);
    defer spool.deinit();
    try spool.enqueue(.{ .node_id = node_id, .occurred_at = "2024-04-01T00:00:00Z", .action = "deny", .uri = "/a", .message = "1", .key = "txn-a" });
    try spool.enqueue(.{ .node_id = node_id, .occurred_at = "2024-04-01T00:00:01Z", .action = "deny", .uri = "/b", .message = "2", .key = "txn-b" });

    // The server terminates this connection's backend, exactly as a restart or a
    // failover would. Killing our own backend severs the connection carrying the
    // statement, so libpq reports that statement as failed too — tolerate it and
    // assert on the state it leaves behind.
    conn.exec("SELECT pg_terminate_backend(pg_backend_pid())") catch {};
    try testing.expect(!conn.isOpen());
    // A plain drain now fails and keeps every event queued.
    try testing.expectError(error.QueryFailed, spool.drain(events));
    try testing.expectEqual(@as(usize, 2), spool.len());

    // The reconnecting drain re-establishes the connection and ingests the batch.
    try testing.expectEqual(@as(usize, 2), try spool.drainReconnecting(events));
    try testing.expectEqual(@as(usize, 0), spool.len());
    const count = (try events.countForNode(testing.allocator, node_id)).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("2", count);

    // The reconnected session still resolves to the same schema, so the events
    // are readable through the same repository — connection-string state, not
    // session state, is what survives a reset.
    try testing.expect(conn.isOpen());
    const csv = try events.exportCsv(testing.allocator, node_id);
    defer testing.allocator.free(csv);
    try testing.expect(std.mem.indexOf(u8, csv, ",deny,/a,1\r\n") != null);
}

test "ruleset repository publishes immutable versions and rolls back" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const rulesets = RulesetRepository{ .conn = conn };
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

    // A signed bundle verifies under the control plane's public key. A fixed seed
    // keeps the test deterministic; a real control plane generates its key once.
    const signing_key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(7));
    const other_key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(9));
    try rulesets.publishSigned("signed", "1", "SecRuleEngine On # signed", signing_key);
    try testing.expect(try rulesets.verify("signed", "1", signing_key.public_key));

    // Every way a bundle can fail to be the one the control plane signed is
    // false, not an error a caller might overlook: another key's signature, an
    // absent version, and an unsigned bundle whose signature column is NULL.
    try testing.expect(!try rulesets.verify("signed", "1", other_key.public_key));
    try testing.expect(!try rulesets.verify("signed", "99", signing_key.public_key));
    try testing.expect(!try rulesets.verify("crs", "1", signing_key.public_key));

    // Tampering with the content of a published bundle breaks its signature. The
    // schema keeps versions immutable, so this takes direct SQL — which is exactly
    // the situation the signature is there to catch.
    try conn.execParams("UPDATE rulesets SET content = $1 WHERE name = 'signed' AND version = 1", &.{"SecRuleEngine Off # tampered"});
    try testing.expect(!try rulesets.verify("signed", "1", signing_key.public_key));

    // A signature that is not hex, or is the wrong length, is rejected rather than
    // decoded into whatever it happens to parse as.
    try conn.exec("UPDATE rulesets SET signature = decode('00ff', 'hex') WHERE name = 'signed' AND version = 1");
    try testing.expect(!try rulesets.verify("signed", "1", signing_key.public_key));
}

test "hex round-trips and rejects non-hex" {
    var encoded: [8]u8 = undefined;
    toHex(&[_]u8{ 0x00, 0x0f, 0xa5, 0xff }, &encoded);
    try testing.expectEqualStrings("000fa5ff", &encoded);

    var decoded: [4]u8 = undefined;
    try fromHex("000fa5ff", &decoded);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x0f, 0xa5, 0xff }, &decoded);
    // Uppercase decodes; anything outside the alphabet, or a length mismatch, does
    // not.
    try fromHex("000FA5FF", &decoded);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x0f, 0xa5, 0xff }, &decoded);
    try testing.expectError(error.InvalidHex, fromHex("00 fa5ff", &decoded));
    try testing.expectError(error.InvalidHex, fromHex("zz0fa5ff", &decoded));
    try testing.expectError(error.InvalidHex, fromHex("000fa5f", &decoded));
}

test "rollout assigns ruleset versions per node and fleet-wide" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const nodes = NodeRepository{ .conn = conn };
    const rollout = RolloutRepository{ .conn = conn };
    const a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    try nodes.enroll(a, "edge-a", "1.0");
    try nodes.enroll(b, "edge-b", "1.0");

    // A node with no assignment reports null.
    try testing.expect((try rollout.assignedVersion(testing.allocator, a, "crs")) == null);

    // Canary one node to v2; re-assigning it updates the target (idempotent).
    try rollout.assign(a, "crs", "2");
    try rollout.assign(a, "crs", "2");
    {
        const v = (try rollout.assignedVersion(testing.allocator, a, "crs")).?;
        defer testing.allocator.free(v);
        try testing.expectEqualStrings("2", v);
    }
    {
        const on2 = (try rollout.countOnVersion(testing.allocator, "crs", "2")).?;
        defer testing.allocator.free(on2);
        try testing.expectEqualStrings("1", on2);
    }

    // Roll the whole fleet to v3 — both nodes, overwriting the canary.
    {
        const rolled = (try rollout.assignAll(testing.allocator, "crs", "3")).?;
        defer testing.allocator.free(rolled);
        try testing.expectEqualStrings("2", rolled);
    }
    {
        const on3 = (try rollout.countOnVersion(testing.allocator, "crs", "3")).?;
        defer testing.allocator.free(on3);
        try testing.expectEqualStrings("2", on3);
        const on2_after = (try rollout.countOnVersion(testing.allocator, "crs", "2")).?;
        defer testing.allocator.free(on2_after);
        try testing.expectEqualStrings("0", on2_after);
    }
    {
        const vb = (try rollout.assignedVersion(testing.allocator, b, "crs")).?;
        defer testing.allocator.free(vb);
        try testing.expectEqualStrings("3", vb);
    }

    // Segmented rollout: only the labeled cohort is moved to v4.
    try nodes.setLabel(a, "tier", "canary");
    {
        const rolled = (try rollout.assignByLabel(testing.allocator, "tier", "canary", "crs", "4")).?;
        defer testing.allocator.free(rolled);
        try testing.expectEqualStrings("1", rolled); // only node a is canary
    }
    {
        const va = (try rollout.assignedVersion(testing.allocator, a, "crs")).?;
        defer testing.allocator.free(va);
        try testing.expectEqualStrings("4", va);
        const vb2 = (try rollout.assignedVersion(testing.allocator, b, "crs")).?;
        defer testing.allocator.free(vb2);
        try testing.expectEqualStrings("3", vb2); // unlabeled node b untouched
    }
}

test "a rollout widens only when its canary cohort is healthy" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const nodes = NodeRepository{ .conn = conn };
    const rollout = RolloutRepository{ .conn = conn };
    const canary = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const rest1 = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    const rest2 = "cccccccc-cccc-cccc-cccc-cccccccccccc";
    for ([_][:0]const u8{ canary, rest1, rest2 }) |node| try nodes.enroll(node, "edge", "1.0");

    // Nothing has been canaried: the gate holds, because rolling out to the fleet
    // on the strength of a canary that was never deployed is the mistake it exists
    // to prevent.
    try testing.expect((try rollout.advanceIfHealthy(testing.allocator, "crs", "2", 60)) == null);
    {
        const health = try rollout.healthOfVersion("crs", "2", 60);
        try testing.expectEqual(@as(usize, 0), health.assigned);
        try testing.expect(!health.isHealthy());
    }

    // Canary the version. It is assigned but unconfirmed, so the gate still holds:
    // the node has not said it is running the new policy.
    try rollout.assign(canary, "crs", "2");
    try nodes.heartbeat(canary);
    {
        const health = try rollout.healthOfVersion("crs", "2", 60);
        try testing.expectEqual(@as(usize, 1), health.assigned);
        try testing.expectEqual(@as(usize, 0), health.unresponsive);
        try testing.expectEqual(@as(usize, 1), health.unconfirmed);
    }
    try testing.expect((try rollout.advanceIfHealthy(testing.allocator, "crs", "2", 60)) == null);

    // The canary confirms it is running v2 and is heartbeating, so the cohort is
    // healthy and the rollout widens to the whole fleet.
    try rollout.reportRunning(canary, "crs", "2");
    {
        const health = try rollout.healthOfVersion("crs", "2", 60);
        try testing.expect(health.isHealthy());
    }
    for ([_][:0]const u8{ rest1, rest2 }) |node| try nodes.heartbeat(node);
    {
        const rolled = (try rollout.advanceIfHealthy(testing.allocator, "crs", "2", 60)).?;
        defer testing.allocator.free(rolled);
        try testing.expectEqualStrings("3", rolled);
    }

    // A canary that stops heartbeating fails the gate for the next version, even
    // though it has confirmed the version it runs — an unresponsive node is not
    // evidence that a policy is safe.
    try rollout.assign(canary, "crs", "3");
    try rollout.reportRunning(canary, "crs", "3");
    try conn.execParams("UPDATE nodes SET last_seen_at = now() - interval '1 hour' WHERE node_id = $1", &.{canary});
    {
        const health = try rollout.healthOfVersion("crs", "3", 60);
        try testing.expectEqual(@as(usize, 1), health.assigned);
        try testing.expectEqual(@as(usize, 1), health.unresponsive);
        try testing.expectEqual(@as(usize, 0), health.unconfirmed);
        try testing.expect(!health.isHealthy());
    }
    try testing.expect((try rollout.advanceIfHealthy(testing.allocator, "crs", "3", 60)) == null);

    // The fleet is still on v2 — the failed gate changed nothing.
    {
        const on2 = (try rollout.countOnVersion(testing.allocator, "crs", "2")).?;
        defer testing.allocator.free(on2);
        try testing.expectEqualStrings("2", on2);
    }

    // A window long enough to cover the last heartbeat passes the gate: the health
    // question is always "within what window", not an absolute.
    {
        const rolled = (try rollout.advanceIfHealthy(testing.allocator, "crs", "3", 7200)).?;
        defer testing.allocator.free(rolled);
        try testing.expectEqualStrings("3", rolled);
    }
}

test "drift is reported until a node confirms the version it runs" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const nodes = NodeRepository{ .conn = conn };
    const rollout = RolloutRepository{ .conn = conn };
    const a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    try nodes.enroll(a, "edge-a", "1.0");
    try nodes.enroll(b, "edge-b", "1.0");
    try rollout.assign(a, "crs", "2");
    try rollout.assign(b, "crs", "2");

    // Both nodes have been assigned v2 but neither has confirmed running it. That
    // is drift: the control plane has no evidence either is running the policy it
    // was given, and treating silence as compliance is how a fleet diverges.
    {
        const count = (try rollout.driftCount(testing.allocator, "crs")).?;
        defer testing.allocator.free(count);
        try testing.expectEqualStrings("2", count);
    }

    // One node reconciles and reports v2, which clears its drift.
    try rollout.reportRunning(a, "crs", "2");
    {
        const count = (try rollout.driftCount(testing.allocator, "crs")).?;
        defer testing.allocator.free(count);
        try testing.expectEqualStrings("1", count);
    }

    // The other reports an older version — it failed to apply the bundle, or was
    // changed out of band. It stays drifted, and is listed with both versions so an
    // operator can see what it is actually running.
    try rollout.reportRunning(b, "crs", "1");
    {
        var rows = try rollout.drifted("crs");
        defer rows.deinit();
        try testing.expectEqual(@as(usize, 1), rows.len());
        try testing.expect(rows.next());
        try testing.expectEqualStrings(b, rows.get(0));
        try testing.expectEqualStrings("2", rows.get(1)); // assigned
        try testing.expectEqualStrings("1", rows.get(2)); // actually running
    }

    // A new rollout re-opens drift for every node until each confirms again.
    if (try rollout.assignAll(testing.allocator, "crs", "3")) |rolled| testing.allocator.free(rolled);
    {
        const count = (try rollout.driftCount(testing.allocator, "crs")).?;
        defer testing.allocator.free(count);
        try testing.expectEqualStrings("2", count);
    }

    // A node reporting a version it was never assigned is still drift.
    try rollout.reportRunning(a, "crs", "99");
    {
        const count = (try rollout.driftCount(testing.allocator, "crs")).?;
        defer testing.allocator.free(count);
        try testing.expectEqualStrings("2", count);
    }

    // A report for a ruleset a node has no assignment for is ignored rather than
    // inventing one.
    try rollout.reportRunning(a, "other", "1");
    try testing.expect((try rollout.assignedVersion(testing.allocator, a, "other")) == null);
}

test "node labels segment the fleet for targeted selection" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const nodes = NodeRepository{ .conn = conn };
    const west1 = "cccccccc-cccc-cccc-cccc-cccccccccccc";
    const west2 = "dddddddd-dddd-dddd-dddd-dddddddddddd";
    const east1 = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
    try nodes.enroll(west1, "edge-w1", "1.0");
    try nodes.enroll(west2, "edge-w2", "1.0");
    try nodes.enroll(east1, "edge-e1", "1.0");

    // An unlabeled node reports null for a missing key.
    try testing.expect((try nodes.labelOf(testing.allocator, west1, "region")) == null);

    // Labels merge — setting a second key preserves the first.
    try nodes.setLabel(west1, "region", "west");
    try nodes.setLabel(west1, "tier", "canary");
    try nodes.setLabel(west2, "region", "west");
    try nodes.setLabel(east1, "region", "east");
    {
        const region = (try nodes.labelOf(testing.allocator, west1, "region")).?;
        defer testing.allocator.free(region);
        try testing.expectEqualStrings("west", region);
        const tier = (try nodes.labelOf(testing.allocator, west1, "tier")).?;
        defer testing.allocator.free(tier);
        try testing.expectEqualStrings("canary", tier);
    }

    // The "west" cohort is exactly the two west nodes, ordered by id.
    {
        var rows = try nodes.withLabel("region", "west");
        defer rows.deinit();
        try testing.expectEqual(@as(usize, 2), rows.len());
        try testing.expect(rows.next());
        try testing.expectEqualStrings(west1, rows.get(0));
        try testing.expect(rows.next());
        try testing.expectEqualStrings(west2, rows.get(0));
        try testing.expect(!rows.next());
    }

    // Overwriting a label changes cohort membership.
    try nodes.setLabel(west2, "region", "east");
    {
        var rows = try nodes.withLabel("region", "west");
        defer rows.deinit();
        try testing.expectEqual(@as(usize, 1), rows.len());
    }
}

test "alert rules resolve enabled webhooks for an action" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const alerts = AlertRepository{ .conn = conn };
    try alerts.create("pager", "deny", "https://hooks.example/pager");
    try alerts.create("slack", "deny", "https://hooks.example/slack");
    try alerts.create("audit", "pass", "https://hooks.example/audit");

    // Names are unique — re-creating "pager" conflicts.
    try testing.expectError(error.QueryFailed, alerts.create("pager", "deny", "https://x"));

    // Two enabled webhooks fire on "deny", ordered by name (pager, slack).
    {
        var rows = try alerts.webhooksFor("deny");
        defer rows.deinit();
        try testing.expectEqual(@as(usize, 2), rows.len());
        try testing.expect(rows.next());
        try testing.expectEqualStrings("https://hooks.example/pager", rows.get(0));
        try testing.expect(rows.next());
        try testing.expectEqualStrings("https://hooks.example/slack", rows.get(0));
        try testing.expect(!rows.next());
    }

    // Disabling a rule removes it from the delivery set.
    try alerts.setEnabled("pager", false);
    {
        var rows = try alerts.webhooksFor("deny");
        defer rows.deinit();
        try testing.expectEqual(@as(usize, 1), rows.len());
        try testing.expect(rows.next());
        try testing.expectEqualStrings("https://hooks.example/slack", rows.get(0));
    }

    // An action with no matching enabled rule yields an empty cursor.
    {
        var rows = try alerts.webhooksFor("allow");
        defer rows.deinit();
        try testing.expectEqual(@as(usize, 0), rows.len());
        try testing.expect(!rows.next());
    }

    // A signing secret round-trips; a rule delivers unsigned (null) by default,
    // and the stored secret signs a payload deterministically.
    try testing.expect((try alerts.secretFor(testing.allocator, "slack")) == null);
    try alerts.setSecret("slack", "s3cr3t");
    {
        const secret = (try alerts.secretFor(testing.allocator, "slack")).?;
        defer testing.allocator.free(secret);
        try testing.expectEqualStrings("s3cr3t", secret);
        var sig: [64]u8 = undefined;
        signPayload(secret, "{\"event\":\"deny\"}", &sig);
        var expected: [64]u8 = undefined;
        signPayload("s3cr3t", "{\"event\":\"deny\"}", &expected);
        try testing.expectEqualStrings(&expected, &sig);
    }
    // Clearing the secret returns the rule to unsigned delivery.
    try alerts.setSecret("slack", null);
    try testing.expect((try alerts.secretFor(testing.allocator, "slack")) == null);
}

test "alert deliveries record outcomes, including unreachable (null status)" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const deliveries = AlertDeliveryRepository{ .conn = conn };

    // A rule with no delivery history reports null.
    try testing.expect((try deliveries.lastHttpStatus(testing.allocator, "pager")) == null);

    // A successful delivery, a 500 response, and an unreachable host (no HTTP
    // status at all — bound as SQL NULL).
    try deliveries.record("pager", "https://hooks.example/pager", "ok", "200");
    try deliveries.record("pager", "https://hooks.example/pager", "failed", "500");
    try deliveries.record("slack", "https://hooks.example/slack", "failed", null);

    {
        const failed = (try deliveries.countByStatus(testing.allocator, "failed")).?;
        defer testing.allocator.free(failed);
        try testing.expectEqualStrings("2", failed);
        const ok = (try deliveries.countByStatus(testing.allocator, "ok")).?;
        defer testing.allocator.free(ok);
        try testing.expectEqualStrings("1", ok);
    }

    // pager's most recent attempt was the 500.
    {
        const last = (try deliveries.lastHttpStatus(testing.allocator, "pager")).?;
        defer testing.allocator.free(last);
        try testing.expectEqualStrings("500", last);
    }
    // slack's most recent attempt had no HTTP response → null, distinct from a
    // rule that was never delivered.
    try testing.expect((try deliveries.lastHttpStatus(testing.allocator, "slack")) == null);
}

test "security events are partitioned by month with O(1) retention" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    // After migration v5 security_events is a partitioned table.
    {
        const partitioned = (try conn.queryScalar(
            testing.allocator,
            "SELECT count(*) FROM pg_partitioned_table WHERE partrelid = 'security_events'::regclass",
        )).?;
        defer testing.allocator.free(partitioned);
        try testing.expectEqualStrings("1", partitioned);
    }

    const events = EventRepository{ .conn = conn };
    const partitions = EventPartitions{ .conn = conn };
    const node_id = "99999999-9999-9999-9999-999999999999";

    // Provision explicit monthly partitions, then ingest into each so rows route
    // to their month's child table (not the default partition).
    try partitions.ensureMonth(2024, 3);
    try partitions.ensureMonth(2024, 4);
    try partitions.ensureMonth(2024, 12); // year-boundary bounds are valid
    try events.recordAt(node_id, "2024-03-15T12:00:00Z", "deny", "/march", "m3");
    try events.recordAt(node_id, "2024-03-20T12:00:00Z", "deny", "/march2", "m3b");
    try events.recordAt(node_id, "2024-04-10T12:00:00Z", "deny", "/april", "m4");

    // All three are visible through the parent table.
    {
        const total = (try events.countForNode(testing.allocator, node_id)).?;
        defer testing.allocator.free(total);
        try testing.expectEqualStrings("3", total);
    }
    // The March rows physically live in the March partition.
    {
        const in_march = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM security_events_2024_03")).?;
        defer testing.allocator.free(in_march);
        try testing.expectEqualStrings("2", in_march);
    }

    // Dropping the March partition removes exactly its rows — O(1) retention.
    try partitions.dropMonth(2024, 3);
    {
        const total_after = (try events.countForNode(testing.allocator, node_id)).?;
        defer testing.allocator.free(total_after);
        try testing.expectEqualStrings("1", total_after); // only April remains
    }
    // Dropping a non-existent partition is a no-op.
    try partitions.dropMonth(2024, 3);
    // An out-of-range month is rejected.
    try testing.expectError(error.QueryFailed, partitions.ensureMonth(2024, 13));
}

test "node and event repositories enroll, heartbeat, and ingest safely" {
    var db = try TestDb.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const nodes = NodeRepository{ .conn = conn };
    const events = EventRepository{ .conn = conn };
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
}
