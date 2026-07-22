//! Pantry-linked LMDB backend for persistent SecLang collections.

const std = @import("std");
const persistent = @import("persistent.zig");
const c = @import("lmdb");

const format_magic = "ZWPC";
const format_version: u16 = 1;
const fixed_header_bytes = format_magic.len + @sizeOf(u16) + @sizeOf(u8) + @sizeOf(u64) + @sizeOf(u32) + @sizeOf(u32);
const value_header_bytes = @sizeOf(u32) + @sizeOf(u32) + @sizeOf(i64) + @sizeOf(u8);

pub const Options = struct {
    map_size: usize = 256 * 1024 * 1024,
    max_readers: c_uint = 126,
    permissions: c.mdb_mode_t = 0o600,
    no_subdirectory: bool = false,
    limits: persistent.Limits = .{},

    pub fn validate(self: Options) error{InvalidOptions}!void {
        if (self.map_size < 1024 * 1024 or self.max_readers == 0) return error.InvalidOptions;
        self.limits.validate() catch return error.InvalidOptions;
    }
};

pub const InitError = std.mem.Allocator.Error || error{
    InvalidOptions,
    EnvironmentCreateFailed,
    EnvironmentConfigurationFailed,
    EnvironmentOpenFailed,
    DatabaseOpenFailed,
};

pub const LmdbBackend = struct {
    allocator: std.mem.Allocator,
    environment: *c.MDB_env,
    database: c.MDB_dbi,
    limits: persistent.Limits,

    pub fn init(allocator: std.mem.Allocator, path: [:0]const u8, options: Options) InitError!LmdbBackend {
        try options.validate();
        var environment: ?*c.MDB_env = null;
        if (c.mdb_env_create(&environment) != c.MDB_SUCCESS) return error.EnvironmentCreateFailed;
        errdefer c.mdb_env_close(environment.?);
        if (c.mdb_env_set_mapsize(environment.?, options.map_size) != c.MDB_SUCCESS or
            c.mdb_env_set_maxreaders(environment.?, options.max_readers) != c.MDB_SUCCESS or
            c.mdb_env_set_maxdbs(environment.?, 1) != c.MDB_SUCCESS)
        {
            return error.EnvironmentConfigurationFailed;
        }
        const flags: c_uint = if (options.no_subdirectory) c.MDB_NOSUBDIR else 0;
        if (c.mdb_env_open(environment.?, path.ptr, flags, options.permissions) != c.MDB_SUCCESS) return error.EnvironmentOpenFailed;

        var transaction: ?*c.MDB_txn = null;
        if (c.mdb_txn_begin(environment.?, null, 0, &transaction) != c.MDB_SUCCESS) return error.DatabaseOpenFailed;
        errdefer c.mdb_txn_abort(transaction.?);
        var database: c.MDB_dbi = 0;
        if (c.mdb_dbi_open(transaction.?, "zig-waf-collections", c.MDB_CREATE, &database) != c.MDB_SUCCESS) return error.DatabaseOpenFailed;
        const open_commit_result = c.mdb_txn_commit(transaction.?);
        transaction = null;
        if (open_commit_result != c.MDB_SUCCESS) return error.DatabaseOpenFailed;
        return .{ .allocator = allocator, .environment = environment.?, .database = database, .limits = options.limits };
    }

    pub fn backend(self: *LmdbBackend) persistent.Backend {
        return .{
            .context = self,
            .loadFn = loadCallback,
            .commitFn = commitCallback,
            .cleanupFn = cleanupCallback,
        };
    }

    pub fn deinit(self: *LmdbBackend) void {
        c.mdb_dbi_close(self.environment, self.database);
        c.mdb_env_close(self.environment);
        self.* = undefined;
    }

    fn loadCallback(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        namespace: persistent.Namespace,
        collection_key: []const u8,
        now_ns: i64,
        limits: persistent.Limits,
    ) persistent.BackendError!persistent.Snapshot {
        const self: *LmdbBackend = @ptrCast(@alignCast(context));
        if (!std.meta.eql(limits, self.limits)) return error.InvalidMutation;
        const key_bytes = try encodeKey(self.allocator, namespace, collection_key, limits);
        defer self.allocator.free(key_bytes);
        var key = toValue(key_bytes);
        var stored: c.MDB_val = undefined;
        var transaction: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.environment, null, c.MDB_RDONLY, &transaction));
        defer c.mdb_txn_abort(transaction.?);
        const result = c.mdb_get(transaction.?, self.database, &key, &stored);
        if (result == c.MDB_NOTFOUND) return persistent.Snapshot.init(allocator, 0);
        try check(result);

        var record = try decodeRecord(self.allocator, valueBytes(stored), limits);
        defer record.deinit();
        if (record.namespace != namespace or !std.mem.eql(u8, record.collection_key, collection_key)) return error.CorruptData;
        var snapshot = persistent.Snapshot.init(allocator, record.revision);
        errdefer snapshot.deinit();
        for (record.values.items) |value| {
            if (!value.expired(now_ns) and value.has_value) try snapshot.append(value);
        }
        return snapshot;
    }

    fn commitCallback(context: *anyopaque, request: persistent.CommitRequest) persistent.BackendError!u64 {
        const self: *LmdbBackend = @ptrCast(@alignCast(context));
        if (!std.meta.eql(request.limits, self.limits)) return error.InvalidMutation;
        const key_bytes = try encodeKey(self.allocator, request.namespace, request.collection_key, request.limits);
        defer self.allocator.free(key_bytes);
        var key = toValue(key_bytes);
        var transaction: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.environment, null, 0, &transaction));
        errdefer if (transaction) |active| c.mdb_txn_abort(active);

        var stored: c.MDB_val = undefined;
        const get_result = c.mdb_get(transaction.?, self.database, &key, &stored);
        var record = if (get_result == c.MDB_NOTFOUND)
            try persistent.Record.init(self.allocator, request.namespace, request.collection_key, 0)
        else blk: {
            try check(get_result);
            break :blk try decodeRecord(self.allocator, valueBytes(stored), request.limits);
        };
        defer record.deinit();
        if (record.namespace != request.namespace or !std.mem.eql(u8, record.collection_key, request.collection_key)) return error.CorruptData;
        if (record.revision != request.expected_revision) return error.Conflict;
        if (record.revision == std.math.maxInt(u64)) return error.CapacityExceeded;
        if (request.mutations.len > request.limits.max_mutations_per_commit) return error.CapacityExceeded;
        try persistent.applyMutations(&record, request.mutations, request.limits);
        record.revision += 1;

        const encoded = try encodeRecord(self.allocator, &record, request.limits);
        defer self.allocator.free(encoded);
        var value = toValue(encoded);
        try check(c.mdb_put(transaction.?, self.database, &key, &value, 0));
        const commit_result = c.mdb_txn_commit(transaction.?);
        transaction = null;
        try check(commit_result);
        return record.revision;
    }

    fn cleanupCallback(context: *anyopaque, now_ns: i64, budget: persistent.CleanupBudget) persistent.BackendError!persistent.CleanupResult {
        const self: *LmdbBackend = @ptrCast(@alignCast(context));
        if (budget.max_records == 0 or budget.max_variables == 0) return .{};
        var transaction: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.environment, null, 0, &transaction));
        errdefer if (transaction) |active| c.mdb_txn_abort(active);
        var cursor: ?*c.MDB_cursor = null;
        try check(c.mdb_cursor_open(transaction.?, self.database, &cursor));
        defer if (cursor) |active| c.mdb_cursor_close(active);

        var result: persistent.CleanupResult = .{};
        var key: c.MDB_val = undefined;
        var stored: c.MDB_val = undefined;
        var cursor_result = c.mdb_cursor_get(cursor.?, &key, &stored, c.MDB_FIRST);
        while (cursor_result == c.MDB_SUCCESS and result.records_scanned < budget.max_records and result.variables_removed < budget.max_variables) {
            result.records_scanned += 1;
            var record = try decodeRecord(self.allocator, valueBytes(stored), self.limits);
            defer record.deinit();
            const removed_before = result.variables_removed;
            var index: usize = 0;
            while (index < record.values.items.len and result.variables_removed < budget.max_variables) {
                if (!record.values.items[index].expired(now_ns)) {
                    index += 1;
                    continue;
                }
                _ = record.values.swapRemove(index);
                result.variables_removed += 1;
            }
            if (result.variables_removed != removed_before) {
                if (record.revision == std.math.maxInt(u64)) return error.CapacityExceeded;
                record.revision += 1;
                const encoded = try encodeRecord(self.allocator, &record, self.limits);
                defer self.allocator.free(encoded);
                var value = toValue(encoded);
                try check(c.mdb_cursor_put(cursor.?, &key, &value, c.MDB_CURRENT));
            }
            cursor_result = c.mdb_cursor_get(cursor.?, &key, &stored, c.MDB_NEXT);
        }
        if (cursor_result != c.MDB_SUCCESS and cursor_result != c.MDB_NOTFOUND) try check(cursor_result);
        c.mdb_cursor_close(cursor.?);
        cursor = null;
        const cleanup_commit_result = c.mdb_txn_commit(transaction.?);
        transaction = null;
        try check(cleanup_commit_result);
        return result;
    }
};

fn encodeKey(allocator: std.mem.Allocator, namespace: persistent.Namespace, collection_key: []const u8, limits: persistent.Limits) persistent.BackendError![]u8 {
    if (collection_key.len == 0 or collection_key.len > limits.max_collection_key_bytes) return error.InvalidKey;
    const result = try allocator.alloc(u8, collection_key.len + 1);
    result[0] = @backingInt(namespace);
    @memcpy(result[1..], collection_key);
    return result;
}

fn encodeRecord(allocator: std.mem.Allocator, record: *const persistent.Record, limits: persistent.Limits) persistent.BackendError![]u8 {
    if (record.collection_key.len == 0 or record.collection_key.len > limits.max_collection_key_bytes) return error.InvalidKey;
    if (record.values.items.len > limits.max_variables_per_record or record.values.items.len > std.math.maxInt(u32)) return error.CapacityExceeded;
    var length = std.math.add(usize, fixed_header_bytes, record.collection_key.len) catch return error.CapacityExceeded;
    var logical_bytes: usize = 0;
    for (record.values.items) |value| {
        if (value.name.len == 0 or value.name.len > limits.max_variable_name_bytes or value.value.len > limits.max_variable_value_bytes) return error.InvalidMutation;
        logical_bytes = std.math.add(usize, logical_bytes, value.name.len + value.value.len) catch return error.CapacityExceeded;
        if (logical_bytes > limits.max_record_bytes) return error.CapacityExceeded;
        length = std.math.add(usize, length, value_header_bytes + value.name.len + value.value.len) catch return error.CapacityExceeded;
    }
    const output = try allocator.alloc(u8, length);
    var offset: usize = 0;
    appendBytes(output, &offset, format_magic);
    appendInt(u16, output, &offset, format_version);
    appendInt(u8, output, &offset, @backingInt(record.namespace));
    appendInt(u64, output, &offset, record.revision);
    appendInt(u32, output, &offset, @intCast(record.collection_key.len));
    appendInt(u32, output, &offset, @intCast(record.values.items.len));
    appendBytes(output, &offset, record.collection_key);
    for (record.values.items) |value| {
        appendInt(u32, output, &offset, @intCast(value.name.len));
        appendInt(u32, output, &offset, @intCast(value.value.len));
        appendInt(i64, output, &offset, value.expires_at_ns orelse -1);
        appendInt(u8, output, &offset, @intFromBool(value.has_value));
        appendBytes(output, &offset, value.name);
        appendBytes(output, &offset, value.value);
    }
    std.debug.assert(offset == output.len);
    return output;
}

fn decodeRecord(allocator: std.mem.Allocator, input: []const u8, limits: persistent.Limits) persistent.BackendError!persistent.Record {
    const overhead_limit = std.math.mul(usize, limits.max_variables_per_record, value_header_bytes) catch return error.CorruptData;
    var encoded_limit = std.math.add(usize, limits.max_record_bytes, overhead_limit) catch return error.CorruptData;
    encoded_limit = std.math.add(usize, encoded_limit, fixed_header_bytes) catch return error.CorruptData;
    encoded_limit = std.math.add(usize, encoded_limit, limits.max_collection_key_bytes) catch return error.CorruptData;
    if (input.len < fixed_header_bytes or input.len > encoded_limit) return error.CorruptData;
    var offset: usize = 0;
    if (!std.mem.eql(u8, readBytes(input, &offset, format_magic.len) catch return error.CorruptData, format_magic)) return error.CorruptData;
    if ((readInt(u16, input, &offset) catch return error.CorruptData) != format_version) return error.CorruptData;
    const namespace_raw = readInt(u8, input, &offset) catch return error.CorruptData;
    if (namespace_raw > @backingInt(persistent.Namespace.resource)) return error.CorruptData;
    const namespace: persistent.Namespace = @fromBackingInt(@intCast(namespace_raw));
    const revision = readInt(u64, input, &offset) catch return error.CorruptData;
    const key_length = readInt(u32, input, &offset) catch return error.CorruptData;
    const value_count = readInt(u32, input, &offset) catch return error.CorruptData;
    if (key_length == 0 or key_length > limits.max_collection_key_bytes or value_count > limits.max_variables_per_record) return error.CorruptData;
    const collection_key = readBytes(input, &offset, key_length) catch return error.CorruptData;
    var record = try persistent.Record.init(allocator, namespace, collection_key, revision);
    errdefer record.deinit();
    var logical_bytes: usize = 0;
    for (0..value_count) |_| {
        const name_length = readInt(u32, input, &offset) catch return error.CorruptData;
        const value_length = readInt(u32, input, &offset) catch return error.CorruptData;
        const expiry = readInt(i64, input, &offset) catch return error.CorruptData;
        const has_value = readInt(u8, input, &offset) catch return error.CorruptData;
        if (name_length == 0 or name_length > limits.max_variable_name_bytes or value_length > limits.max_variable_value_bytes or expiry < -1 or has_value > 1) return error.CorruptData;
        logical_bytes = std.math.add(usize, logical_bytes, @as(usize, name_length) + value_length) catch return error.CorruptData;
        if (logical_bytes > limits.max_record_bytes) return error.CorruptData;
        const name = readBytes(input, &offset, name_length) catch return error.CorruptData;
        const value = readBytes(input, &offset, value_length) catch return error.CorruptData;
        try record.append(.{ .name = name, .value = value, .has_value = has_value == 1, .expires_at_ns = if (expiry == -1) null else expiry });
    }
    if (offset != input.len) return error.CorruptData;
    return record;
}

fn appendInt(comptime T: type, output: []u8, offset: *usize, value: T) void {
    std.mem.writeInt(T, output[offset.*..][0..@sizeOf(T)], value, .little);
    offset.* += @sizeOf(T);
}

fn appendBytes(output: []u8, offset: *usize, value: []const u8) void {
    @memcpy(output[offset.*..][0..value.len], value);
    offset.* += value.len;
}

fn readInt(comptime T: type, input: []const u8, offset: *usize) error{Truncated}!T {
    if (@sizeOf(T) > input.len -| offset.*) return error.Truncated;
    const result = std.mem.readInt(T, input[offset.*..][0..@sizeOf(T)], .little);
    offset.* += @sizeOf(T);
    return result;
}

fn readBytes(input: []const u8, offset: *usize, length: usize) error{Truncated}![]const u8 {
    if (length > input.len -| offset.*) return error.Truncated;
    const result = input[offset.*..][0..length];
    offset.* += length;
    return result;
}

fn toValue(bytes: []const u8) c.MDB_val {
    return .{ .mv_size = bytes.len, .mv_data = @ptrCast(@constCast(bytes.ptr)) };
}

fn valueBytes(value: c.MDB_val) []const u8 {
    const pointer: [*]const u8 = @ptrCast(value.mv_data);
    return pointer[0..value.mv_size];
}

fn check(result: c_int) persistent.BackendError!void {
    if (result == c.MDB_SUCCESS) return;
    return switch (result) {
        c.MDB_MAP_FULL, c.MDB_READERS_FULL, c.MDB_TXN_FULL, c.MDB_DBS_FULL => error.CapacityExceeded,
        c.MDB_CORRUPTED, c.MDB_PANIC, c.MDB_VERSION_MISMATCH, c.MDB_INVALID, c.MDB_BAD_VALSIZE => error.CorruptData,
        else => error.Unavailable,
    };
}

const IncrementWorker = struct {
    backend: persistent.Backend,
    iterations: usize,
    limits: persistent.Limits,
    failures: *std.atomic.Value(usize),

    fn run(self: IncrementWorker) void {
        for (0..self.iterations) |_| {
            var session = persistent.Session.init(std.heap.smp_allocator, self.backend, self.limits) catch {
                _ = self.failures.fetchAdd(1, .monotonic);
                return;
            };
            defer session.deinit();
            var snapshot = (session.initialize(.global, "global", 0) catch {
                _ = self.failures.fetchAdd(1, .monotonic);
                return;
            }) orelse unreachable;
            snapshot.deinit();
            session.add(.global, "counter", 1) catch {
                _ = self.failures.fetchAdd(1, .monotonic);
                return;
            };
            _ = session.flush(0) catch {
                _ = self.failures.fetchAdd(1, .monotonic);
                return;
            };
        }
    }
};

test "record codec rejects truncation and trailing data" {
    var record = try persistent.Record.init(std.testing.allocator, .ip, "192.0.2.1", 7);
    defer record.deinit();
    try record.append(.{ .name = "score", .value = "4", .expires_at_ns = 50 });
    const encoded = try encodeRecord(std.testing.allocator, &record, .{});
    defer std.testing.allocator.free(encoded);
    try std.testing.expectError(error.CorruptData, decodeRecord(std.testing.allocator, encoded[0 .. encoded.len - 1], .{}));
    var with_trailer = try std.testing.allocator.alloc(u8, encoded.len + 1);
    defer std.testing.allocator.free(with_trailer);
    @memcpy(with_trailer[0..encoded.len], encoded);
    with_trailer[encoded.len] = 0;
    try std.testing.expectError(error.CorruptData, decodeRecord(std.testing.allocator, with_trailer, .{}));
}

test "LMDB backend survives reopen and filters expired values" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const terminated = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{temporary.sub_path}, 0);
    defer std.testing.allocator.free(terminated);
    const limits: persistent.Limits = .{};

    {
        var lmdb = try LmdbBackend.init(std.testing.allocator, terminated, .{});
        defer lmdb.deinit();
        const backend = lmdb.backend();
        try std.testing.expectEqual(@as(u64, 1), try backend.commit(.{
            .namespace = .ip,
            .collection_key = "192.0.2.1",
            .expected_revision = 0,
            .mutations = &.{
                .{ .set = .{ .name = "score", .value = "9" } },
                .{ .set = .{ .name = "expired", .value = "x", .expires_at_ns = 5 } },
            },
            .limits = limits,
        }));
    }
    {
        var lmdb = try LmdbBackend.init(std.testing.allocator, terminated, .{});
        defer lmdb.deinit();
        const backend = lmdb.backend();
        try std.testing.expectError(error.Conflict, backend.commit(.{
            .namespace = .ip,
            .collection_key = "192.0.2.1",
            .expected_revision = 0,
            .mutations = &.{.{ .set = .{ .name = "score", .value = "lost" } }},
            .limits = limits,
        }));
        var snapshot = try backend.load(std.testing.allocator, .ip, "192.0.2.1", 5, limits);
        defer snapshot.deinit();
        try std.testing.expectEqual(@as(u64, 1), snapshot.revision);
        try std.testing.expectEqual(@as(usize, 1), snapshot.values.items.len);
        try std.testing.expectEqualStrings("score", snapshot.values.items[0].name);
        try std.testing.expectEqualStrings("9", snapshot.values.items[0].value);
        const cleaned = try backend.cleanup(5, .{ .max_records = 1, .max_variables = 1 });
        try std.testing.expectEqual(@as(usize, 1), cleaned.variables_removed);
        var after_cleanup = try backend.load(std.testing.allocator, .ip, "192.0.2.1", 5, limits);
        defer after_cleanup.deinit();
        try std.testing.expectEqual(@as(u64, 2), after_cleanup.revision);
        try std.testing.expectEqualStrings("9", after_cleanup.values.items[0].value);
    }
}

test "LMDB conflict retries preserve contended increments" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{temporary.sub_path}, 0);
    defer std.testing.allocator.free(path);
    const limits: persistent.Limits = .{ .max_retry_attempts = 64 };
    var lmdb = try LmdbBackend.init(std.testing.allocator, path, .{ .limits = limits });
    defer lmdb.deinit();

    var failures = std.atomic.Value(usize).init(0);
    const worker: IncrementWorker = .{ .backend = lmdb.backend(), .iterations = 50, .limits = limits, .failures = &failures };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, IncrementWorker.run, .{worker});
    for (&threads) |*thread| thread.join();
    try std.testing.expectEqual(@as(usize, 0), failures.load(.acquire));

    var snapshot = try lmdb.backend().load(std.testing.allocator, .global, "global", 0, limits);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 1), snapshot.values.items.len);
    try std.testing.expectEqualStrings("200", snapshot.values.items[0].value);
}

test "LMDB rejects corrupt records without partial decoding" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{temporary.sub_path}, 0);
    defer std.testing.allocator.free(path);
    var lmdb = try LmdbBackend.init(std.testing.allocator, path, .{});
    defer lmdb.deinit();

    const key_bytes = try encodeKey(std.testing.allocator, .session, "broken", .{});
    defer std.testing.allocator.free(key_bytes);
    var key = toValue(key_bytes);
    var corrupt = toValue("not-a-zig-waf-record");
    var transaction: ?*c.MDB_txn = null;
    try check(c.mdb_txn_begin(lmdb.environment, null, 0, &transaction));
    try check(c.mdb_put(transaction.?, lmdb.database, &key, &corrupt, 0));
    const result = c.mdb_txn_commit(transaction.?);
    transaction = null;
    try check(result);
    try std.testing.expectError(error.CorruptData, lmdb.backend().load(std.testing.allocator, .session, "broken", 0, .{}));
}

test "LMDB map-full commit leaves the prior revision readable" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}", .{temporary.sub_path}, 0);
    defer std.testing.allocator.free(path);
    const limits: persistent.Limits = .{
        .max_variable_value_bytes = 2 * 1024 * 1024,
        .max_record_bytes = 3 * 1024 * 1024,
    };
    var lmdb = try LmdbBackend.init(std.testing.allocator, path, .{ .map_size = 1024 * 1024, .limits = limits });
    defer lmdb.deinit();
    const large = try std.testing.allocator.alloc(u8, 2 * 1024 * 1024);
    defer std.testing.allocator.free(large);
    @memset(large, 'x');
    try std.testing.expectError(error.CapacityExceeded, lmdb.backend().commit(.{
        .namespace = .resource,
        .collection_key = "/large",
        .expected_revision = 0,
        .mutations = &.{.{ .set = .{ .name = "blob", .value = large } }},
        .limits = limits,
    }));
    var snapshot = try lmdb.backend().load(std.testing.allocator, .resource, "/large", 0, limits);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(u64, 0), snapshot.revision);
    try std.testing.expectEqual(@as(usize, 0), snapshot.values.items.len);
}
