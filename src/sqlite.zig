//! A minimal SQLite client over libsqlite3, plus a transactional schema-migration
//! runner — an in-process, serverless storage backend for single-node fleet
//! deployments and dependency-free tests (#57). The API mirrors `pg.zig`
//! (`Conn`, bound parameters, a `Rows` cursor, `migrate`) so repository logic can
//! be exercised without a PostgreSQL server.
//!
//! Compiled only into the `sqlite-test` build (it links libsqlite3); the WAF
//! engine has no database dependency.

const std = @import("std");
const c = @import("sqlite3");

pub const Error = error{
    OpenFailed,
    QueryFailed,
    OutOfMemory,
};

/// SQLite's SQLITE_TRANSIENT destructor sentinel (`(void(*)(void*))-1`), which
/// tells SQLite to copy bound text immediately so it need not outlive the bind.
/// translate-C cannot render the cast-in-macro, and the value is deliberately an
/// unaligned/invalid pointer (SQLite only compares it, never calls it), so it is
/// materialized at runtime with the alignment assertion disabled.
fn sqliteTransient() c.sqlite3_destructor_type {
    @setRuntimeSafety(false);
    var raw: usize = undefined;
    raw = std.math.maxInt(usize);
    const ptr: *const anyopaque = @ptrFromInt(raw);
    return @ptrCast(@alignCast(ptr));
}

const max_params = 16;

/// One SQLite connection/database handle. Not thread-safe; hand one out per task.
pub const Conn = struct {
    handle: *c.sqlite3,

    /// Open (creating if absent) a database file. Use ":memory:" for a private,
    /// ephemeral in-memory database.
    pub fn open(path: [:0]const u8) Error!Conn {
        var handle: ?*c.sqlite3 = null;
        if (c.sqlite3_open(path.ptr, &handle) != c.SQLITE_OK) {
            if (handle) |h| _ = c.sqlite3_close(h);
            return error.OpenFailed;
        }
        return .{ .handle = handle orelse return error.OpenFailed };
    }

    /// A private in-memory database — for tests and caches.
    pub fn openMemory() Error!Conn {
        return open(":memory:");
    }

    pub fn close(self: *Conn) void {
        _ = c.sqlite3_close(self.handle);
        self.* = undefined;
    }

    /// The last error text from SQLite (borrowed; valid until the next call).
    pub fn lastError(self: *const Conn) []const u8 {
        return std.mem.span(c.sqlite3_errmsg(self.handle));
    }

    /// Run one or more statements expecting no result rows (DDL, INSERT,
    /// BEGIN/COMMIT). Unlike the prepared-statement path, this accepts multiple
    /// semicolon-separated statements — used for multi-statement migrations.
    pub fn exec(self: *Conn, sql: [:0]const u8) Error!void {
        if (c.sqlite3_exec(self.handle, sql.ptr, null, null, null) != c.SQLITE_OK) return error.QueryFailed;
    }

    /// Prepare `sql` and bind text parameters (1-based); a null binds SQL NULL.
    /// The caller finalizes the returned statement.
    fn prepare(self: *Conn, sql: [:0]const u8, params: []const ?[:0]const u8) Error!*c.sqlite3_stmt {
        if (params.len > max_params) return error.QueryFailed;
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(self.handle, sql.ptr, -1, &stmt, null) != c.SQLITE_OK) return error.QueryFailed;
        const handle = stmt orelse return error.QueryFailed;
        for (params, 0..) |param, index| {
            const position: c_int = @intCast(index + 1);
            const rc = if (param) |value|
                c.sqlite3_bind_text(handle, position, value.ptr, @intCast(value.len), sqliteTransient())
            else
                c.sqlite3_bind_null(handle, position);
            if (rc != c.SQLITE_OK) {
                _ = c.sqlite3_finalize(handle);
                return error.QueryFailed;
            }
        }
        return handle;
    }

    /// Run a statement with bound text parameters, expecting no result rows.
    pub fn execParams(self: *Conn, sql: [:0]const u8, params: []const [:0]const u8) Error!void {
        var optional: [max_params]?[:0]const u8 = undefined;
        if (params.len > max_params) return error.QueryFailed;
        for (params, 0..) |param, index| optional[index] = param;
        return self.execParamsOpt(sql, optional[0..params.len]);
    }

    /// Like `execParams`, but a null parameter binds SQL NULL (for genuinely
    /// absent columns, not empty strings).
    pub fn execParamsOpt(self: *Conn, sql: [:0]const u8, params: []const ?[:0]const u8) Error!void {
        const stmt = try self.prepare(sql, params);
        defer _ = c.sqlite3_finalize(stmt);
        switch (c.sqlite3_step(stmt)) {
            c.SQLITE_DONE, c.SQLITE_ROW => {},
            else => return error.QueryFailed,
        }
    }

    /// The first column of the first row (copied with `allocator`, caller owns),
    /// null when there are no rows or the value is SQL NULL.
    pub fn queryScalar(self: *Conn, allocator: std.mem.Allocator, sql: [:0]const u8) Error!?[]u8 {
        return self.queryScalarParams(allocator, sql, &.{});
    }

    /// Like `queryScalar`, but with bound text parameters.
    pub fn queryScalarParams(self: *Conn, allocator: std.mem.Allocator, sql: [:0]const u8, params: []const [:0]const u8) Error!?[]u8 {
        var optional: [max_params]?[:0]const u8 = undefined;
        if (params.len > max_params) return error.QueryFailed;
        for (params, 0..) |param, index| optional[index] = param;
        const stmt = try self.prepare(sql, optional[0..params.len]);
        defer _ = c.sqlite3_finalize(stmt);
        switch (c.sqlite3_step(stmt)) {
            c.SQLITE_ROW => {},
            c.SQLITE_DONE => return null, // no rows
            else => return error.QueryFailed,
        }
        if (c.sqlite3_column_count(stmt) == 0) return null;
        if (c.sqlite3_column_type(stmt, 0) == c.SQLITE_NULL) return null; // SQL NULL, not empty
        const text = c.sqlite3_column_text(stmt, 0);
        return try allocator.dupe(u8, std.mem.span(text));
    }

    /// Run a query and return a forward cursor. The caller iterates with
    /// `next()`, reads borrowed column text with `get()`, and must `deinit()`.
    pub fn query(self: *Conn, sql: [:0]const u8, params: []const [:0]const u8) Error!Rows {
        var optional: [max_params]?[:0]const u8 = undefined;
        if (params.len > max_params) return error.QueryFailed;
        for (params, 0..) |param, index| optional[index] = param;
        const stmt = try self.prepare(sql, optional[0..params.len]);
        return .{ .stmt = stmt };
    }
};

/// A forward cursor over a query result. Unlike the PostgreSQL cursor, rows are
/// streamed, so a column value is borrowed only until the next `next()` or
/// `deinit()`.
pub const Rows = struct {
    stmt: *c.sqlite3_stmt,

    pub fn deinit(self: *Rows) void {
        _ = c.sqlite3_finalize(self.stmt);
        self.* = undefined;
    }

    /// Advance to the next row; false when exhausted.
    pub fn next(self: *Rows) bool {
        return c.sqlite3_step(self.stmt) == c.SQLITE_ROW;
    }

    /// Borrowed text of column `col` in the current row (valid until the next
    /// `next()`/`deinit()`). An SQL NULL reads as an empty slice.
    pub fn get(self: *const Rows, col: usize) []const u8 {
        const text = c.sqlite3_column_text(self.stmt, @intCast(col));
        if (text == null) return "";
        return std.mem.span(text);
    }
};

pub const Migration = struct {
    version: i64,
    name: []const u8,
    sql: [:0]const u8,
};

/// Format a null-terminated SQL string into `buf`.
fn bufSqlZ(buf: []u8, comptime fmt: []const u8, args: anytype) Error![:0]const u8 {
    const written = std.fmt.bufPrint(buf, fmt, args) catch return error.QueryFailed;
    if (written.len >= buf.len) return error.QueryFailed;
    buf[written.len] = 0;
    return buf[0..written.len :0];
}

/// Apply every not-yet-recorded migration (assumed version-ordered), each in its
/// own transaction, recording it in `schema_migrations`. Applying twice is a
/// no-op; on failure the current migration is rolled back and the schema is left
/// at the last fully-applied version. Returns the number applied.
pub fn migrate(conn: *Conn, allocator: std.mem.Allocator, migrations: []const Migration) Error!usize {
    try conn.exec(
        \\CREATE TABLE IF NOT EXISTS schema_migrations (
        \\  version     INTEGER PRIMARY KEY,
        \\  name        TEXT NOT NULL,
        \\  applied_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
        const record_sql = bufSqlZ(&record_buffer, "INSERT INTO schema_migrations (version, name) VALUES ({d}, ?1)", .{migration.version}) catch {
            conn.exec("ROLLBACK") catch {};
            return error.QueryFailed;
        };
        // Bind the name as a parameter so any quote in it is never interpolated.
        const name_z = allocator.allocSentinel(u8, migration.name.len, 0) catch {
            conn.exec("ROLLBACK") catch {};
            return error.OutOfMemory;
        };
        defer allocator.free(name_z);
        @memcpy(name_z, migration.name);
        conn.execParams(record_sql, &.{name_z}) catch |err| {
            conn.exec("ROLLBACK") catch {};
            return err;
        };
        conn.exec("COMMIT") catch |err| {
            conn.exec("ROLLBACK") catch {};
            return err;
        };
        applied += 1;
    }
    return applied;
}

// ---- tests ----------------------------------------------------------------
// These use a private in-memory database, so they need no server and run under
// `zig build sqlite-test`.

const testing = std.testing;

test "connection runs statements, bound params, and scalar reads" {
    var conn = try Conn.openMemory();
    defer conn.close();

    try conn.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, note TEXT)");
    try conn.execParams("INSERT INTO t (name, note) VALUES (?1, ?2)", &.{ "alice", "hi" });
    // A quote-laden value is stored literally via binding, never interpolated.
    try conn.execParams("INSERT INTO t (name, note) VALUES (?1, ?2)", &.{ "bob'; DROP TABLE t; --", "x" });

    const count = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM t")).?;
    defer testing.allocator.free(count);
    try testing.expectEqualStrings("2", count);

    const name = (try conn.queryScalarParams(testing.allocator, "SELECT name FROM t WHERE note = ?1", &.{"hi"})).?;
    defer testing.allocator.free(name);
    try testing.expectEqualStrings("alice", name);

    // No matching row → null; distinct from an empty-string value.
    try testing.expect((try conn.queryScalarParams(testing.allocator, "SELECT name FROM t WHERE note = ?1", &.{"absent"})) == null);
}

test "null binds and reads as SQL NULL, distinct from empty string" {
    var conn = try Conn.openMemory();
    defer conn.close();
    try conn.exec("CREATE TABLE probe (a TEXT, b TEXT)");
    try conn.execParamsOpt("INSERT INTO probe (a, b) VALUES (?1, ?2)", &.{ "present", null });

    try testing.expect((try conn.queryScalar(testing.allocator, "SELECT b FROM probe")) == null);
    const a_val = (try conn.queryScalar(testing.allocator, "SELECT a FROM probe")).?;
    defer testing.allocator.free(a_val);
    try testing.expectEqualStrings("present", a_val);

    try conn.execParams("INSERT INTO probe (a, b) VALUES (?1, ?2)", &.{ "", "" });
    const empties = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM probe WHERE b IS NULL")).?;
    defer testing.allocator.free(empties);
    try testing.expectEqualStrings("1", empties); // only the bound-null row, not the empty string
}

test "row cursor iterates in order" {
    var conn = try Conn.openMemory();
    defer conn.close();
    try conn.exec("CREATE TABLE t (n INTEGER, label TEXT)");
    try conn.execParams("INSERT INTO t (n, label) VALUES (?1, ?2)", &.{ "1", "one" });
    try conn.execParams("INSERT INTO t (n, label) VALUES (?1, ?2)", &.{ "2", "two" });

    var rows = try conn.query("SELECT label FROM t WHERE n >= ?1 ORDER BY n", &.{"1"});
    defer rows.deinit();
    try testing.expect(rows.next());
    try testing.expectEqualStrings("one", rows.get(0));
    try testing.expect(rows.next());
    try testing.expectEqualStrings("two", rows.get(0));
    try testing.expect(!rows.next());
}

test "migrations apply once, are idempotent, and are transactional" {
    var conn = try Conn.openMemory();
    defer conn.close();

    const migrations = [_]Migration{
        .{ .version = 1, .name = "first", .sql = "CREATE TABLE a (id INTEGER PRIMARY KEY)" },
        .{ .version = 2, .name = "sec'ond", .sql = "CREATE TABLE b (id INTEGER PRIMARY KEY)" },
    };
    try testing.expectEqual(@as(usize, 2), try migrate(&conn, testing.allocator, &migrations));
    try testing.expectEqual(@as(usize, 0), try migrate(&conn, testing.allocator, &migrations)); // idempotent

    for ([_][:0]const u8{ "a", "b" }) |table| {
        var buffer: [128]u8 = undefined;
        const q = try bufSqlZ(&buffer, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{s}'", .{table});
        const present = (try conn.queryScalar(testing.allocator, q)).?;
        defer testing.allocator.free(present);
        try testing.expectEqualStrings("1", present);
    }

    // A failing migration rolls back: its table is absent and it is not recorded.
    const bad = [_]Migration{
        .{ .version = 3, .name = "broken", .sql = "CREATE TABLE c (id INTEGER); INSERT INTO nope VALUES (1)" },
    };
    try testing.expectError(error.QueryFailed, migrate(&conn, testing.allocator, &bad));
    const recorded = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM schema_migrations WHERE version = 3")).?;
    defer testing.allocator.free(recorded);
    try testing.expectEqualStrings("0", recorded);
    const c_table = (try conn.queryScalar(testing.allocator, "SELECT count(*) FROM sqlite_master WHERE name='c'")).?;
    defer testing.allocator.free(c_table);
    try testing.expectEqualStrings("0", c_table);
}
