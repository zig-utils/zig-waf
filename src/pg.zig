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

    /// Like `queryScalar`, but with text-format bind parameters.
    pub fn queryScalarParams(self: *Conn, allocator: std.mem.Allocator, sql: [:0]const u8, params: []const [:0]const u8) Error!?[]u8 {
        if (params.len > max_params) return error.QueryFailed;
        var values: [max_params][*c]const u8 = undefined;
        for (params, 0..) |param, index| values[index] = param.ptr;
        const result = c.PQexecParams(self.handle, sql.ptr, @intCast(params.len), null, &values, null, null, 0);
        defer c.PQclear(result);
        if (c.PQresultStatus(result) != c.PGRES_TUPLES_OK) return error.QueryFailed;
        if (c.PQntuples(result) == 0 or c.PQnfields(result) == 0) return null;
        return try allocator.dupe(u8, std.mem.span(c.PQgetvalue(result, 0, 0)));
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
    // Run the fleet schema's migration tests under `pg-test` too.
    _ = @import("fleet.zig");
}

fn testDsn(allocator: std.mem.Allocator) !?[:0]u8 {
    const raw = std.c.getenv("PG_TEST_DSN") orelse return null;
    const value = std.mem.span(raw);
    if (value.len == 0) return null;
    const owned = try allocator.allocSentinel(u8, value.len, 0);
    @memcpy(owned, value);
    return owned;
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
}

test "migrations apply once, are idempotent, and are transactional" {
    const dsn = (try testDsn(testing.allocator)) orelse return error.SkipZigTest;
    defer testing.allocator.free(dsn);
    var conn = try Conn.open(dsn);
    defer conn.close();

    // Isolate from any prior run (schema_migrations may not exist yet).
    try conn.exec("DROP TABLE IF EXISTS pg_test_widgets");
    conn.exec("DELETE FROM schema_migrations WHERE version IN (99001, 99002, 99003)") catch {};

    const good = [_]Migration{
        .{ .version = 99001, .name = "create_widgets", .sql = "CREATE TABLE pg_test_widgets (id bigint PRIMARY KEY)" },
        .{ .version = 99002, .name = "seed_widget", .sql = "INSERT INTO pg_test_widgets (id) VALUES (7)" },
    };
    try testing.expectEqual(@as(usize, 2), try migrate(&conn, testing.allocator, &good));
    // Second run applies nothing (idempotent).
    try testing.expectEqual(@as(usize, 0), try migrate(&conn, testing.allocator, &good));

    const count = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM pg_test_widgets")).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("1", count);

    // A failing migration rolls back and leaves the version unrecorded.
    const bad = [_]Migration{
        .{ .version = 99003, .name = "broken", .sql = "INSERT INTO pg_test_widgets (id) VALUES (7)" }, // duplicate PK
    };
    try testing.expectError(error.QueryFailed, migrate(&conn, testing.allocator, &bad));
    try testing.expect((try conn.queryScalar(testing.allocator, "SELECT 1 FROM schema_migrations WHERE version = 99003")) == null);

    try conn.exec("DROP TABLE pg_test_widgets");
    try conn.exec("DELETE FROM schema_migrations WHERE version IN (99001, 99002)");
}
