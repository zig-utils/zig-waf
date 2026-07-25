//! A minimal PostgreSQL client over libpq, plus a transactional schema-migration
//! runner. This is the foundation of the fleet control-plane's storage layer:
//! repositories build on `Conn`, and the schema evolves through ordered,
//! all-or-nothing migrations tracked in `schema_migrations`.
//!
//! Compiled only into the `-Dpg` build (it links libpq); the WAF engine has no
//! database dependency. Integration tests connect to a PostgreSQL named by the
//! `PG_TEST_DSN` environment variable and skip when it is unset.

const std = @import("std");
const c = @import("pq");

pub const Error = error{
    ConnectionFailed,
    QueryFailed,
    OutOfMemory,
};

/// One PostgreSQL connection. Not thread-safe; a pool hands one out per task.
pub const Conn = struct {
    handle: *c.PGconn,

    /// Open a connection from a libpq DSN / conninfo string (e.g.
    /// "host=/tmp port=5455 user=waf dbname=fleet").
    pub fn open(conninfo: [:0]const u8) Error!Conn {
        const handle = c.PQconnectdb(conninfo.ptr) orelse return error.ConnectionFailed;
        if (c.PQstatus(handle) != c.CONNECTION_OK) {
            c.PQfinish(handle);
            return error.ConnectionFailed;
        }
        return .{ .handle = handle };
    }

    pub fn close(self: *Conn) void {
        c.PQfinish(self.handle);
        self.* = undefined;
    }

    /// Reconnect using the same parameters, after the server severed the
    /// connection (#55) — a restart, a failover, or an idle-connection reaper.
    /// The handle stays valid, so callers holding this `Conn` keep working.
    ///
    /// Session state does not survive: an in-flight transaction is gone, and
    /// anything `SET` on the session reverts. Configuration that must outlive a
    /// reset belongs in the connection string (e.g. `options=-csearch_path=…`),
    /// which is reused verbatim.
    pub fn reset(self: *Conn) Error!void {
        c.PQreset(self.handle);
        if (c.PQstatus(self.handle) != c.CONNECTION_OK) return error.ConnectionFailed;
    }

    /// Run a statement, reconnecting and retrying it when the connection turns out
    /// to have been severed (#53) — the failure a long-lived connection actually
    /// hits, since a database restart or failover invalidates it silently and the
    /// next statement is how the client finds out.
    ///
    /// Only for statements that may safely run twice. The first attempt may have
    /// reached the server and committed before the connection dropped, so a
    /// non-idempotent statement can take effect twice; heartbeats, upserts, and
    /// keyed inserts are fine, a blind `UPDATE … SET n = n + 1` is not.
    ///
    /// Retrying is limited to lost connections. Serialization failures are not
    /// retried here: nothing in the control plane runs at SERIALIZABLE isolation, so
    /// they cannot arise, and retrying a statement inside a transaction the caller
    /// owns would be the caller's decision anyway.
    pub fn execRetrying(self: *Conn, sql: [:0]const u8, attempts: usize) Error!void {
        var attempt: usize = 0;
        while (true) {
            attempt += 1;
            self.exec(sql) catch |err| {
                // A connection libpq still considers good failed for a reason a
                // reconnect cannot fix, so report it rather than retrying blindly.
                if (self.isOpen() or attempt >= attempts) return err;
                try self.reset();
                continue;
            };
            return;
        }
    }

    /// Whether the connection is still usable. libpq only marks a connection bad
    /// once a command has actually failed on it, so this reports the last known
    /// state rather than probing the server.
    pub fn isOpen(self: *const Conn) bool {
        return c.PQstatus(self.handle) == c.CONNECTION_OK;
    }

    /// The last error text from libpq (borrowed; valid until the next call).
    pub fn lastError(self: *const Conn) []const u8 {
        return std.mem.span(c.PQerrorMessage(self.handle));
    }

    /// Run a statement expecting no result rows (DDL, INSERT, BEGIN/COMMIT).
    pub fn exec(self: *Conn, sql: [:0]const u8) Error!void {
        const result = c.PQexec(self.handle, sql.ptr);
        defer c.PQclear(result);
        switch (c.PQresultStatus(result)) {
            c.PGRES_COMMAND_OK, c.PGRES_TUPLES_OK => {},
            else => return error.QueryFailed,
        }
    }

    /// Run a query and return the first column of the first row, copied with
    /// `allocator` (caller owns), or null when the query returns no rows.
    pub fn queryScalar(self: *Conn, allocator: std.mem.Allocator, sql: [:0]const u8) Error!?[]u8 {
        const result = c.PQexec(self.handle, sql.ptr);
        defer c.PQclear(result);
        if (c.PQresultStatus(result) != c.PGRES_TUPLES_OK) return error.QueryFailed;
        if (c.PQntuples(result) == 0 or c.PQnfields(result) == 0) return null;
        if (c.PQgetisnull(result, 0, 0) != 0) return null; // SQL NULL, not an empty string
        const value = c.PQgetvalue(result, 0, 0);
        return try allocator.dupe(u8, std.mem.span(value));
    }

    const max_params = 16;

    /// Run a parameterized statement (`$1`, `$2`, …) with text-format arguments —
    /// the injection-safe way to pass untrusted values. Expects no result rows.
    pub fn execParams(self: *Conn, sql: [:0]const u8, params: []const [:0]const u8) Error!void {
        if (params.len > max_params) return error.QueryFailed;
        var values: [max_params][*c]const u8 = undefined;
        for (params, 0..) |param, index| values[index] = param.ptr;
        const result = c.PQexecParams(self.handle, sql.ptr, @intCast(params.len), null, &values, null, null, 0);
        defer c.PQclear(result);
        switch (c.PQresultStatus(result)) {
            c.PGRES_COMMAND_OK, c.PGRES_TUPLES_OK => {},
            else => return error.QueryFailed,
        }
    }

    /// Like `execParams`, but each parameter may be null → a SQL NULL is bound
    /// (libpq reads a null value pointer as NULL). For columns that are
    /// genuinely absent (e.g. no HTTP status when a webhook host is unreachable)
    /// rather than empty.
    pub fn execParamsOpt(self: *Conn, sql: [:0]const u8, params: []const ?[:0]const u8) Error!void {
        if (params.len > max_params) return error.QueryFailed;
        var values: [max_params][*c]const u8 = undefined;
        for (params, 0..) |param, index| values[index] = if (param) |p| p.ptr else null;
        const result = c.PQexecParams(self.handle, sql.ptr, @intCast(params.len), null, &values, null, null, 0);
        defer c.PQclear(result);
        switch (c.PQresultStatus(result)) {
            c.PGRES_COMMAND_OK, c.PGRES_TUPLES_OK => {},
            else => return error.QueryFailed,
        }
    }

    /// Like `execParamsOpt`, but returns how many rows the statement actually
    /// affected (libpq's command tuples). This is how an idempotent
    /// `INSERT ... ON CONFLICT DO NOTHING` reports whether the row was new: 1 for
    /// an insert, 0 when an existing row already carried the same key.
    pub fn execParamsOptCount(self: *Conn, sql: [:0]const u8, params: []const ?[:0]const u8) Error!usize {
        if (params.len > max_params) return error.QueryFailed;
        var values: [max_params][*c]const u8 = undefined;
        for (params, 0..) |param, index| values[index] = if (param) |p| p.ptr else null;
        const result = c.PQexecParams(self.handle, sql.ptr, @intCast(params.len), null, &values, null, null, 0);
        defer c.PQclear(result);
        switch (c.PQresultStatus(result)) {
            c.PGRES_COMMAND_OK, c.PGRES_TUPLES_OK => {},
            else => return error.QueryFailed,
        }
        const tuples = std.mem.span(c.PQcmdTuples(result));
        if (tuples.len == 0) return 0; // not a row-affecting command
        return std.fmt.parseInt(usize, tuples, 10) catch error.QueryFailed;
    }

    /// Parse and plan a statement once under `name`, to be run repeatedly with
    /// `execPrepared`/`queryPrepared` (#53). The control plane's hot statements —
    /// heartbeats, event inserts, assignment lookups — are the same handful of
    /// shapes on every call, and preparing them moves parsing off each one.
    ///
    /// The name is scoped to this connection and lives until the session ends, so a
    /// pooled connection keeps its prepared statements across checkouts. Preparing
    /// the same name twice is an error, not a redefinition.
    pub fn prepare(self: *Conn, name: [:0]const u8, sql: [:0]const u8) Error!void {
        // Zero parameter types: the server infers them from the statement.
        const result = c.PQprepare(self.handle, name.ptr, sql.ptr, 0, null);
        defer c.PQclear(result);
        if (c.PQresultStatus(result) != c.PGRES_COMMAND_OK) return error.QueryFailed;
    }

    /// Run a prepared statement, returning how many rows it affected. Parameters
    /// may be null to bind SQL NULL.
    pub fn execPrepared(self: *Conn, name: [:0]const u8, params: []const ?[:0]const u8) Error!usize {
        if (params.len > max_params) return error.QueryFailed;
        var values: [max_params][*c]const u8 = undefined;
        for (params, 0..) |param, index| values[index] = if (param) |p| p.ptr else null;
        const result = c.PQexecPrepared(self.handle, name.ptr, @intCast(params.len), &values, null, null, 0);
        defer c.PQclear(result);
        switch (c.PQresultStatus(result)) {
            c.PGRES_COMMAND_OK, c.PGRES_TUPLES_OK => {},
            else => return error.QueryFailed,
        }
        const tuples = std.mem.span(c.PQcmdTuples(result));
        if (tuples.len == 0) return 0;
        return std.fmt.parseInt(usize, tuples, 10) catch error.QueryFailed;
    }

    /// Run a prepared statement and return a row cursor over its results.
    pub fn queryPrepared(self: *Conn, name: [:0]const u8, params: []const [:0]const u8) Error!Rows {
        if (params.len > max_params) return error.QueryFailed;
        var values: [max_params][*c]const u8 = undefined;
        for (params, 0..) |param, index| values[index] = param.ptr;
        const result = c.PQexecPrepared(self.handle, name.ptr, @intCast(params.len), &values, null, null, 0) orelse return error.QueryFailed;
        if (c.PQresultStatus(result) != c.PGRES_TUPLES_OK) {
            c.PQclear(result);
            return error.QueryFailed;
        }
        return .{ .result = result, .count = c.PQntuples(result) };
    }

    /// Bound how long any statement on this connection may run (#53). The server
    /// cancels one that exceeds it, so a pathological query cannot hold a pooled
    /// connection — and the pool's whole budget — indefinitely. Zero disables the
    /// bound.
    ///
    /// This is session state, so it must be re-applied after `reset`.
    pub fn setStatementTimeout(self: *Conn, milliseconds: u32) Error!void {
        var buffer: [64]u8 = undefined;
        try self.exec(try bufSqlZ(&buffer, "SET statement_timeout = {d}", .{milliseconds}));
    }

    /// Send a statement without waiting for it (#53), so the caller can `cancel` it
    /// or do other work while the server runs it. Every send must be followed by
    /// `discardResults` (or a `cancel` and then `discardResults`) before the
    /// connection is used again, since libpq refuses a new command while results
    /// are outstanding.
    pub fn sendQuery(self: *Conn, sql: [:0]const u8) Error!void {
        if (c.PQsendQuery(self.handle, sql.ptr) != 1) return error.QueryFailed;
    }

    /// Ask the server to abandon the statement in flight on this connection (#53).
    /// Cancellation is a request, not a guarantee: a statement that has already
    /// finished completes normally, so the caller learns the outcome from
    /// `discardResults` rather than from this call.
    pub fn cancel(self: *const Conn) Error!void {
        const handle = c.PQgetCancel(@constCast(self.handle)) orelse return error.ConnectionFailed;
        defer c.PQfreeCancel(handle);
        var message: [256]u8 = undefined;
        if (c.PQcancel(handle, &message, message.len) != 1) return error.QueryFailed;
    }

    /// Drain the results of a `sendQuery`, reporting whether the statement
    /// succeeded. A cancelled statement reports false — the error libpq holds says
    /// it was cancelled.
    pub fn discardResults(self: *Conn) bool {
        var succeeded = true;
        while (c.PQgetResult(self.handle)) |result| {
            switch (c.PQresultStatus(result)) {
                c.PGRES_COMMAND_OK, c.PGRES_TUPLES_OK => {},
                else => succeeded = false,
            }
            c.PQclear(result);
        }
        return succeeded;
    }

    /// Stream `data` into the server with `COPY … FROM STDIN` (#55) — one round
    /// trip and one parse for a whole batch, instead of a statement per row.
    ///
    /// `data` is the COPY payload in PostgreSQL's text format: tab-separated
    /// fields, one newline-terminated row each, `\N` for NULL, and backslash
    /// escapes for tabs, newlines, carriage returns, and backslashes
    /// (`copyEscape` produces exactly this). COPY cannot upsert, so callers that
    /// need idempotency copy into a staging table and insert from it.
    pub fn copyIn(self: *Conn, copy_sql: [:0]const u8, data: []const u8) Error!void {
        const start = c.PQexec(self.handle, copy_sql.ptr);
        defer c.PQclear(start);
        if (c.PQresultStatus(start) != c.PGRES_COPY_IN) return error.QueryFailed;
        if (c.PQputCopyData(self.handle, data.ptr, @intCast(data.len)) != 1) return error.QueryFailed;
        // A null error message ends the stream successfully; a non-null one would
        // ask the server to fail the COPY.
        if (c.PQputCopyEnd(self.handle, null) != 1) return error.QueryFailed;
        // Drain every result the COPY produced, keeping the first status.
        var failed = false;
        while (c.PQgetResult(self.handle)) |result| {
            if (c.PQresultStatus(result) != c.PGRES_COMMAND_OK) failed = true;
            c.PQclear(result);
        }
        if (failed) return error.QueryFailed;
    }

    /// Like `queryScalar`, but with text-format bind parameters.
    pub fn queryScalarParams(self: *Conn, allocator: std.mem.Allocator, sql: [:0]const u8, params: []const [:0]const u8) Error!?[]u8 {
        if (params.len > max_params) return error.QueryFailed;
        var values: [max_params][*c]const u8 = undefined;
        for (params, 0..) |param, index| values[index] = param.ptr;
        const result = c.PQexecParams(self.handle, sql.ptr, @intCast(params.len), null, &values, null, null, 0);
        defer c.PQclear(result);
        if (c.PQresultStatus(result) != c.PGRES_TUPLES_OK) return error.QueryFailed;
        if (c.PQntuples(result) == 0 or c.PQnfields(result) == 0) return null;
        if (c.PQgetisnull(result, 0, 0) != 0) return null; // SQL NULL, not an empty string
        return try allocator.dupe(u8, std.mem.span(c.PQgetvalue(result, 0, 0)));
    }

    /// Run a parameterized query and return a row cursor. The caller iterates
    /// with `next()`, reads borrowed column text with `get()`, and must
    /// `deinit()` to release the result.
    pub fn query(self: *Conn, sql: [:0]const u8, params: []const [:0]const u8) Error!Rows {
        if (params.len > max_params) return error.QueryFailed;
        var values: [max_params][*c]const u8 = undefined;
        for (params, 0..) |param, index| values[index] = param.ptr;
        const result = c.PQexecParams(self.handle, sql.ptr, @intCast(params.len), null, &values, null, null, 0) orelse return error.QueryFailed;
        if (c.PQresultStatus(result) != c.PGRES_TUPLES_OK) {
            c.PQclear(result);
            return error.QueryFailed;
        }
        return .{ .result = result, .count = c.PQntuples(result) };
    }
};

/// Append `field` to a COPY text-format payload, escaping the four characters
/// that would otherwise end the field, the row, or the escape itself. Without
/// this, a URI containing a tab or a message containing a newline would shift
/// every following column.
pub fn copyEscape(out: *std.ArrayList(u8), allocator: std.mem.Allocator, field: []const u8) error{OutOfMemory}!void {
    for (field) |byte| switch (byte) {
        '\\' => try out.appendSlice(allocator, "\\\\"),
        '\t' => try out.appendSlice(allocator, "\\t"),
        '\n' => try out.appendSlice(allocator, "\\n"),
        '\r' => try out.appendSlice(allocator, "\\r"),
        else => try out.append(allocator, byte),
    };
}

/// A forward cursor over a query result. Column values are borrowed from the
/// result and valid only until `deinit`.
pub const Rows = struct {
    result: *c.PGresult,
    count: c_int,
    index: c_int = -1,

    pub fn deinit(self: *Rows) void {
        c.PQclear(self.result);
        self.* = undefined;
    }

    /// Advance to the next row; false when exhausted.
    pub fn next(self: *Rows) bool {
        self.index += 1;
        return self.index < self.count;
    }

    /// Borrowed text of column `col` in the current row (valid until `deinit`).
    pub fn get(self: *const Rows, col: usize) []const u8 {
        return std.mem.span(c.PQgetvalue(self.result, self.index, @intCast(col)));
    }

    pub fn len(self: *const Rows) usize {
        return @intCast(self.count);
    }
};

/// A bounded pool of PostgreSQL connections, opened lazily and reused (#53).
/// Thread-safe: `acquire`/`release` are guarded by a mutex so many std.Io tasks
/// can share it. `acquire` returns an idle connection, opens a new one while
/// under `max`, or fails with `PoolExhausted` when all `max` are checked out —
/// non-blocking, so a caller drops or retries rather than stalling a worker.
pub const Pool = struct {
    allocator: std.mem.Allocator,
    dsn: [:0]const u8,
    max: usize,
    /// Tiny-critical-section spinlock over the idle list and counter; new
    /// connections are opened outside it so a blocking connect never stalls
    /// other tasks holding the lock.
    locked: std.atomic.Value(bool) = .init(false),
    idle: std.ArrayList(Conn) = .empty,
    checked_out: usize = 0,

    pub const AcquireError = Error || error{PoolExhausted};

    pub fn init(allocator: std.mem.Allocator, dsn: [:0]const u8, max: usize) Pool {
        return .{ .allocator = allocator, .dsn = dsn, .max = max };
    }

    fn lock(self: *Pool) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn unlock(self: *Pool) void {
        self.locked.store(false, .release);
    }

    /// Close every idle connection. All checked-out connections must have been
    /// released first.
    pub fn deinit(self: *Pool) void {
        self.lock();
        defer self.unlock();
        for (self.idle.items) |*conn| conn.close();
        self.idle.deinit(self.allocator);
        self.* = undefined;
    }

    /// Borrow a connection; return it with `release`.
    pub fn acquire(self: *Pool) AcquireError!Conn {
        self.lock();
        if (self.idle.pop()) |conn| {
            self.checked_out += 1;
            self.unlock();
            return conn;
        }
        if (self.checked_out >= self.max) {
            self.unlock();
            return error.PoolExhausted;
        }
        self.checked_out += 1; // reserve the slot before releasing the lock
        self.unlock();

        // Open outside the lock (a blocking connect must not stall other tasks).
        return Conn.open(self.dsn) catch |err| {
            self.lock();
            self.checked_out -= 1; // hand the reserved slot back on failure
            self.unlock();
            return err;
        };
    }

    /// Return a connection to the pool for reuse.
    pub fn release(self: *Pool, conn: Conn) void {
        self.lock();
        defer self.unlock();
        self.checked_out -= 1;
        self.idle.append(self.allocator, conn) catch {
            // Out of memory tracking the idle handle: close it rather than leak.
            var owned = conn;
            owned.close();
        };
    }
};

/// Which control-plane workload a connection is for (#53). They fail differently
/// and must not share a budget: API requests are many and short, ingestion is a
/// steady trickle of batches, and rollout is occasional but must not be blocked by
/// either — a bad afternoon of console traffic should not stop the fleet from
/// receiving a policy.
pub const Workload = enum { api, rollout, ingestion };

/// Separate bounded pools, one per workload, so exhausting one cannot starve
/// another (#53). A single shared pool makes every workload as available as the
/// greediest one; these limits are a partition of the database's connection budget,
/// so each workload's worst case is its own.
pub const WorkloadPools = struct {
    api: Pool,
    rollout: Pool,
    ingestion: Pool,

    /// Connections each workload may hold. The defaults reflect their shapes: many
    /// short API requests, a couple of ingestion drains, and one rollout at a time.
    pub const Limits = struct {
        api: usize = 8,
        rollout: usize = 1,
        ingestion: usize = 2,
    };

    pub fn init(allocator: std.mem.Allocator, dsn: [:0]const u8, limits: Limits) WorkloadPools {
        return .{
            .api = Pool.init(allocator, dsn, limits.api),
            .rollout = Pool.init(allocator, dsn, limits.rollout),
            .ingestion = Pool.init(allocator, dsn, limits.ingestion),
        };
    }

    pub fn deinit(self: *WorkloadPools) void {
        self.api.deinit();
        self.rollout.deinit();
        self.ingestion.deinit();
        self.* = undefined;
    }

    pub fn pool(self: *WorkloadPools, workload: Workload) *Pool {
        return switch (workload) {
            .api => &self.api,
            .rollout => &self.rollout,
            .ingestion => &self.ingestion,
        };
    }

    /// Borrow a connection for `workload`; return it with `release`.
    pub fn acquire(self: *WorkloadPools, workload: Workload) Pool.AcquireError!Conn {
        return self.pool(workload).acquire();
    }

    pub fn release(self: *WorkloadPools, workload: Workload, conn: Conn) void {
        self.pool(workload).release(conn);
    }

    /// The total connections every workload could hold at once — what the database's
    /// `max_connections` has to accommodate for this process.
    pub fn totalLimit(self: *const WorkloadPools) usize {
        return self.api.max + self.rollout.max + self.ingestion.max;
    }
};

/// One schema migration: a stable version, a name, and its idempotent-at-the-
/// -version SQL (which may contain several statements).
pub const Migration = struct {
    version: i64,
    name: []const u8,
    sql: [:0]const u8,
};

/// Format a null-terminated SQL string into `buf` (libpq needs a C string).
fn bufSqlZ(buf: []u8, comptime fmt: []const u8, args: anytype) Error![:0]const u8 {
    const written = std.fmt.bufPrint(buf, fmt, args) catch return error.QueryFailed;
    if (written.len >= buf.len) return error.QueryFailed;
    buf[written.len] = 0;
    return buf[0..written.len :0];
}

/// Apply every migration in `migrations` (assumed version-ordered) that has not
/// yet been recorded, each inside its own transaction, and record it in
/// `schema_migrations`. Applying twice is a no-op. On any failure the current
/// migration's transaction is rolled back and the error is returned, leaving the
/// schema at the last fully-applied version.
pub fn migrate(conn: *Conn, allocator: std.mem.Allocator, migrations: []const Migration) Error!usize {
    try conn.exec(
        \\CREATE TABLE IF NOT EXISTS schema_migrations (
        \\  version     bigint PRIMARY KEY,
        \\  name        text NOT NULL,
        \\  applied_at  timestamptz NOT NULL DEFAULT now()
        \\)
    );

    var applied: usize = 0;
    for (migrations) |migration| {
        var version_buffer: [128]u8 = undefined;
        const version_text = try bufSqlZ(&version_buffer, "SELECT 1 FROM schema_migrations WHERE version = {d}", .{migration.version});
        if (try conn.queryScalar(allocator, version_text)) |existing| {
            allocator.free(existing); // already applied
            continue;
        }

        try conn.exec("BEGIN");
        conn.exec(migration.sql) catch |err| {
            conn.exec("ROLLBACK") catch {};
            return err;
        };
        var record_buffer: [512]u8 = undefined;
        const record_sql = bufSqlZ(&record_buffer, "INSERT INTO schema_migrations (version, name) VALUES ({d}, '{s}')", .{ migration.version, migration.name }) catch {
            conn.exec("ROLLBACK") catch {};
            return error.QueryFailed;
        };
        conn.exec(record_sql) catch |err| {
            conn.exec("ROLLBACK") catch {};
            return err;
        };
        try conn.exec("COMMIT");
        applied += 1;
    }
    return applied;
}

// ---- tests --------------------------------------------------------------
//
// These require a live PostgreSQL; set PG_TEST_DSN (e.g.
// "host=/tmp/pgtest port=5455 user=waf dbname=postgres") to run them.

const testing = std.testing;

test {
    // Run the fleet schema's and identity layer's tests under `pg-test` too.
    _ = @import("fleet.zig");
    _ = @import("fleet_auth.zig");
}

/// Test-only: a connection whose search_path is a private, uniquely named
/// schema, dropped on `close`.
///
/// The build runner executes tests in parallel, so every integration test in
/// this suite shares the one database named by PG_TEST_DSN. Tests that create
/// tables — and `migrate`, which records versions in `schema_migrations` — would
/// otherwise contend: one test's teardown drops the tables another is still
/// using, intermittently and unreproducibly. A per-test schema gives each one
/// its own `schema_migrations` and its own tables, so DDL is genuinely isolated.
pub const TestSchema = struct {
    dsn: [:0]u8,
    name: [:0]u8,
    conn: Conn,

    /// Distinguishes concurrent tests within the process; the pid distinguishes
    /// concurrent test binaries.
    var next_id: std.atomic.Value(u32) = .init(0);

    /// Open PG_TEST_DSN and switch to a fresh private schema. Returns
    /// error.SkipZigTest when PG_TEST_DSN is unset, which is how this suite stays
    /// runnable without a database.
    pub fn open(allocator: std.mem.Allocator) !TestSchema {
        const raw = std.c.getenv("PG_TEST_DSN") orelse return error.SkipZigTest;
        const value = std.mem.span(raw);
        if (value.len == 0) return error.SkipZigTest;

        var name_buffer: [64]u8 = undefined;
        const generated = std.fmt.bufPrint(&name_buffer, "waf_test_{d}_{d}", .{
            std.c.getpid(),
            next_id.fetchAdd(1, .monotonic),
        }) catch unreachable;
        const name = try allocator.allocSentinel(u8, generated.len, 0);
        errdefer allocator.free(name);
        @memcpy(name, generated);

        // Put the schema in the connection string rather than `SET`ting it on the
        // session, so it survives a `reset` — which the reconnect tests rely on.
        //
        // Notices are silenced with it: libpq prints them to stderr, and the
        // schema teardown alone emits one per dropped table. Under the build
        // runner that stderr traffic shares a stream with the test protocol.
        const dsn = try allocator.printSentinel(
            "{s} options='-csearch_path={s} -cclient_min_messages=warning'",
            .{ value, name },
            0,
        );
        errdefer allocator.free(dsn);

        var conn = try Conn.open(dsn);
        errdefer conn.close();
        // A crashed earlier run can leave the schema behind, so drop first.
        var sql_buffer: [256]u8 = undefined;
        try conn.exec(try bufSqlZ(&sql_buffer, "DROP SCHEMA IF EXISTS {s} CASCADE", .{name}));
        try conn.exec(try bufSqlZ(&sql_buffer, "CREATE SCHEMA {s}", .{name}));
        return .{ .dsn = dsn, .name = name, .conn = conn };
    }

    /// Drop the private schema with everything in it, then close.
    pub fn close(self: *TestSchema) void {
        var sql_buffer: [256]u8 = undefined;
        if (bufSqlZ(&sql_buffer, "DROP SCHEMA IF EXISTS {s} CASCADE", .{self.name})) |sql| {
            self.conn.exec(sql) catch {};
        } else |_| {}
        self.conn.close();
        testing.allocator.free(self.name);
        testing.allocator.free(self.dsn);
        self.* = undefined;
    }
};

fn testDsn(allocator: std.mem.Allocator) !?[:0]u8 {
    const raw = std.c.getenv("PG_TEST_DSN") orelse return null;
    const value = std.mem.span(raw);
    if (value.len == 0) return null;
    const owned = try allocator.allocSentinel(u8, value.len, 0);
    @memcpy(owned, value);
    return owned;
}

test "a statement retries across a severed connection" {
    var db = try TestSchema.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    try conn.exec("CREATE TABLE retry_probe (n int)");
    // The server severs this connection; the next statement is how the client finds
    // out, which is exactly the failure a long-lived connection hits after a
    // database restart.
    conn.exec("SELECT pg_terminate_backend(pg_backend_pid())") catch {};
    try testing.expect(!conn.isOpen());
    try conn.execRetrying("INSERT INTO retry_probe (n) VALUES (1)", 2);
    try testing.expect(conn.isOpen());

    // The reconnected session still resolves to the test's schema, so the row
    // landed in the table created before the drop.
    const count = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM retry_probe")).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("1", count);

    // A statement that fails on a healthy connection is reported, not retried: no
    // number of attempts fixes a syntax error or a constraint violation.
    try testing.expectError(error.QueryFailed, conn.execRetrying("INSERT INTO retry_probe (n) VALUES ('not a number')", 3));
    const unchanged = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM retry_probe")).?;
    defer testing.allocator.free(unchanged);
    try testing.expectEqualStrings("1", unchanged);

    // A single attempt does not reconnect — the caller asked for one try.
    conn.exec("SELECT pg_terminate_backend(pg_backend_pid())") catch {};
    try testing.expectError(error.QueryFailed, conn.execRetrying("INSERT INTO retry_probe (n) VALUES (2)", 1));
}

test "workload pools are budgeted separately" {
    const dsn = (try testDsn(testing.allocator)) orelse return error.SkipZigTest;
    defer testing.allocator.free(dsn);
    var pools = WorkloadPools.init(testing.allocator, dsn, .{ .api = 2, .rollout = 1, .ingestion = 1 });
    defer pools.deinit();
    try testing.expectEqual(@as(usize, 4), pools.totalLimit());

    // Exhaust ingestion entirely.
    const ingesting = try pools.acquire(.ingestion);
    try testing.expectError(error.PoolExhausted, pools.acquire(.ingestion));

    // Rollout and API are unaffected: a stalled ingestion drain cannot stop the
    // fleet from receiving a policy or the console from answering.
    const rolling = try pools.acquire(.rollout);
    var serving = try pools.acquire(.api);
    const one = (try serving.queryScalar(testing.allocator, "SELECT 1")).?;
    defer testing.allocator.free(one);
    try testing.expectEqualStrings("1", one);

    // Each workload's limit is its own, so API's second connection is still there
    // while rollout has none left.
    const serving_two = try pools.acquire(.api);
    try testing.expectError(error.PoolExhausted, pools.acquire(.api));
    try testing.expectError(error.PoolExhausted, pools.acquire(.rollout));

    pools.release(.ingestion, ingesting);
    pools.release(.rollout, rolling);
    pools.release(.api, serving);
    pools.release(.api, serving_two);

    // Released connections are reused rather than reopened, per workload.
    const reused = try pools.acquire(.ingestion);
    pools.release(.ingestion, reused);
}

test "prepared statements run repeatedly and bind NULL" {
    var db = try TestSchema.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    try conn.exec("CREATE TABLE prepared_probe (id int, label text)");
    try conn.prepare("insert_probe", "INSERT INTO prepared_probe (id, label) VALUES ($1::int, $2)");
    try testing.expectEqual(@as(usize, 1), try conn.execPrepared("insert_probe", &.{ "1", "first" }));
    try testing.expectEqual(@as(usize, 1), try conn.execPrepared("insert_probe", &.{ "2", "second" }));
    // A null parameter binds SQL NULL through the prepared path too.
    try testing.expectEqual(@as(usize, 1), try conn.execPrepared("insert_probe", &.{ "3", null }));

    try conn.prepare("select_probe", "SELECT label FROM prepared_probe WHERE id = $1::int");
    {
        var rows = try conn.queryPrepared("select_probe", &.{"2"});
        defer rows.deinit();
        try testing.expect(rows.next());
        try testing.expectEqualStrings("second", rows.get(0));
    }
    const nulls = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM prepared_probe WHERE label IS NULL")).?;
    defer testing.allocator.free(nulls);
    try testing.expectEqualStrings("1", nulls);

    // A name is defined once; redefining it is an error rather than a silent
    // replacement of a statement other call sites are using.
    try testing.expectError(error.QueryFailed, conn.prepare("insert_probe", "SELECT 1"));
    // An unprepared name is an error, not an empty result.
    try testing.expectError(error.QueryFailed, conn.execPrepared("absent", &.{}));
}

test "a statement timeout bounds a pathological query" {
    var db = try TestSchema.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    try conn.setStatementTimeout(50);
    // The server cancels the sleep, so a query that would hold the connection for
    // a second fails in a fraction of it.
    try testing.expectError(error.QueryFailed, conn.exec("SELECT pg_sleep(1)"));
    // The connection stays usable afterwards: the statement was cancelled, not the
    // session.
    try testing.expect(conn.isOpen());
    const one = (try conn.queryScalar(testing.allocator, "SELECT 1")).?;
    defer testing.allocator.free(one);
    try testing.expectEqualStrings("1", one);

    // Zero lifts the bound.
    try conn.setStatementTimeout(0);
    try conn.exec("SELECT pg_sleep(0.05)");
}

test "an in-flight statement can be cancelled" {
    var db = try TestSchema.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    // A statement that would run for a second, abandoned before it finishes.
    try conn.sendQuery("SELECT pg_sleep(1)");
    try conn.cancel();
    try testing.expect(!conn.discardResults()); // reported as failed: cancelled

    // The session survives its statement being cancelled and is immediately usable.
    try testing.expect(conn.isOpen());
    const one = (try conn.queryScalar(testing.allocator, "SELECT 1")).?;
    defer testing.allocator.free(one);
    try testing.expectEqualStrings("1", one);

    // Cancelling when nothing is in flight is not an error — cancellation is a
    // request about whatever the server is doing, and it may already have finished.
    try conn.sendQuery("SELECT 2");
    try testing.expect(conn.discardResults());
    try conn.cancel();
}

test "connection pool reuses connections and bounds concurrency" {
    const dsn = (try testDsn(testing.allocator)) orelse return error.SkipZigTest;
    defer testing.allocator.free(dsn);
    var pool = Pool.init(testing.allocator, dsn, 2);
    defer pool.deinit();

    var a = try pool.acquire();
    const b = try pool.acquire();
    // At max (2 checked out): a third acquire fails without blocking.
    try testing.expectError(error.PoolExhausted, pool.acquire());
    const one = (try a.queryScalar(testing.allocator, "SELECT 1")).?;
    defer testing.allocator.free(one);
    try testing.expectEqualStrings("1", one);

    pool.release(a);
    // Releasing frees a slot; re-acquiring reuses the now-idle connection.
    var reused = try pool.acquire();
    const two = (try reused.queryScalar(testing.allocator, "SELECT 2")).?;
    defer testing.allocator.free(two);
    try testing.expectEqualStrings("2", two);
    pool.release(b);
    pool.release(reused);
}

test "connects and runs a scalar query" {
    const dsn = (try testDsn(testing.allocator)) orelse return error.SkipZigTest;
    defer testing.allocator.free(dsn);
    var conn = try Conn.open(dsn);
    defer conn.close();
    const value = (try conn.queryScalar(testing.allocator, "SELECT 1 + 1")).?;
    defer testing.allocator.free(value);
    try testing.expectEqualStrings("2", value);

    // A SQL NULL result is reported as null — distinct from an empty string, so
    // callers can tell "no value" from "the value is the empty string".
    try testing.expect((try conn.queryScalar(testing.allocator, "SELECT NULL::text")) == null);
    const empty = (try conn.queryScalarParams(testing.allocator, "SELECT $1::text", &.{""})).?;
    defer testing.allocator.free(empty);
    try testing.expectEqualStrings("", empty);
    try testing.expect((try conn.queryScalarParams(testing.allocator, "SELECT NULLIF($1::text, 'x')", &.{"x"})) == null);

    // execParamsOpt binds a null parameter as SQL NULL (round-tripped through a
    // temp table), distinct from an empty string.
    try conn.exec("CREATE TEMP TABLE opt_probe (a text, b text)");
    try conn.execParamsOpt("INSERT INTO opt_probe (a, b) VALUES ($1, $2)", &.{ "present", null });
    try testing.expect((try conn.queryScalar(testing.allocator, "SELECT b FROM opt_probe")) == null);
    const a_val = (try conn.queryScalar(testing.allocator, "SELECT a FROM opt_probe")).?;
    defer testing.allocator.free(a_val);
    try testing.expectEqualStrings("present", a_val);
    const null_count = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM opt_probe WHERE b IS NULL")).?;
    defer testing.allocator.free(null_count);
    try testing.expectEqualStrings("1", null_count);
}

test "migrations apply once, are idempotent, and are transactional" {
    // A private schema, so this test's schema_migrations and tables are its own.
    var db = try TestSchema.open(testing.allocator);
    defer db.close();
    const conn = &db.conn;

    const good = [_]Migration{
        .{ .version = 99001, .name = "create_widgets", .sql = "CREATE TABLE pg_test_widgets (id bigint PRIMARY KEY)" },
        .{ .version = 99002, .name = "seed_widget", .sql = "INSERT INTO pg_test_widgets (id) VALUES (7)" },
    };
    try testing.expectEqual(@as(usize, 2), try migrate(conn, testing.allocator, &good));
    // Second run applies nothing (idempotent).
    try testing.expectEqual(@as(usize, 0), try migrate(conn, testing.allocator, &good));

    const count = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM pg_test_widgets")).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("1", count);

    // A failing migration rolls back and leaves the version unrecorded.
    const bad = [_]Migration{
        .{ .version = 99003, .name = "broken", .sql = "INSERT INTO pg_test_widgets (id) VALUES (7)" }, // duplicate PK
    };
    try testing.expectError(error.QueryFailed, migrate(conn, testing.allocator, &bad));
    try testing.expect((try conn.queryScalar(testing.allocator, "SELECT 1 FROM schema_migrations WHERE version = 99003")) == null);
}
