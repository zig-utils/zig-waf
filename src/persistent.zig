//! Bounded, revisioned storage contracts for persistent SecLang collections.

const std = @import("std");
const collections = @import("collections.zig");

pub const backend_abi_version: u32 = 1;

pub const Namespace = enum(u8) {
    ip,
    session,
    user,
    global,
    resource,

    pub fn collectionName(self: Namespace) collections.Name {
        return switch (self) {
            .ip => .ip,
            .session => .session,
            .user => .user,
            .global => .global,
            .resource => .resource,
        };
    }

    pub fn parse(input: []const u8) ?Namespace {
        inline for (std.meta.tags(Namespace)) |candidate| {
            if (std.ascii.eqlIgnoreCase(input, @tagName(candidate))) return candidate;
        }
        return null;
    }
};

pub const FailurePolicy = enum {
    fail_open,
    fail_closed,
};

pub const Limits = struct {
    max_collection_key_bytes: usize = 1024,
    max_variable_name_bytes: usize = 1024,
    max_variable_value_bytes: usize = 32 * 1024,
    max_variables_per_record: usize = 4096,
    max_record_bytes: usize = 2 * 1024 * 1024,
    max_mutations_per_commit: usize = 4096,
    max_retry_attempts: u8 = 8,
    cleanup_record_budget: usize = 128,
    cleanup_variable_budget: usize = 4096,

    pub fn validate(self: Limits) error{InvalidPersistentLimit}!void {
        if (self.max_collection_key_bytes == 0 or
            self.max_variable_name_bytes == 0 or
            self.max_variable_value_bytes == 0 or
            self.max_variables_per_record == 0 or
            self.max_record_bytes < self.max_variable_value_bytes or
            self.max_mutations_per_commit == 0 or
            self.max_retry_attempts == 0 or
            self.cleanup_record_budget == 0 or
            self.cleanup_variable_budget == 0)
        {
            return error.InvalidPersistentLimit;
        }
    }
};

pub const BackendError = std.mem.Allocator.Error || error{
    Unavailable,
    Timeout,
    Conflict,
    CorruptData,
    CapacityExceeded,
    InvalidKey,
    InvalidMutation,
};

pub const Value = struct {
    name: []const u8,
    value: []const u8,
    expires_at_ns: ?i64 = null,

    pub fn expired(self: Value, now_ns: i64) bool {
        return if (self.expires_at_ns) |deadline| deadline <= now_ns else false;
    }
};

/// Allocator-owned result returned by a backend load. The caller must deinit it.
pub const Snapshot = struct {
    arena: std.heap.ArenaAllocator,
    revision: u64,
    values: std.ArrayList(Value) = .empty,

    pub fn init(allocator: std.mem.Allocator, revision: u64) Snapshot {
        return .{ .arena = .init(allocator), .revision = revision };
    }

    pub fn append(self: *Snapshot, value: Value) std.mem.Allocator.Error!void {
        const allocator = self.arena.allocator();
        try self.values.append(allocator, .{
            .name = try allocator.dupe(u8, value.name),
            .value = try allocator.dupe(u8, value.value),
            .expires_at_ns = value.expires_at_ns,
        });
    }

    pub fn deinit(self: *Snapshot) void {
        self.values.deinit(self.arena.allocator());
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const SetMutation = struct {
    name: []const u8,
    value: []const u8,
    expires_at_ns: ?i64 = null,
};

pub const Mutation = union(enum) {
    set: SetMutation,
    remove: []const u8,
};

pub const CommitRequest = struct {
    namespace: Namespace,
    collection_key: []const u8,
    expected_revision: u64,
    mutations: []const Mutation,
    limits: Limits,
};

pub const CleanupBudget = struct {
    max_records: usize,
    max_variables: usize,
};

pub const CleanupResult = struct {
    records_scanned: usize = 0,
    variables_removed: usize = 0,
};

/// Versioned callback table. Context lifetime is owned by the application and
/// must exceed the WAF and every transaction that can call this backend.
pub const Backend = struct {
    abi_version: u32 = backend_abi_version,
    context: *anyopaque,
    loadFn: *const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        namespace: Namespace,
        collection_key: []const u8,
        now_ns: i64,
        limits: Limits,
    ) BackendError!Snapshot,
    commitFn: *const fn (context: *anyopaque, request: CommitRequest) BackendError!u64,
    cleanupFn: *const fn (context: *anyopaque, now_ns: i64, budget: CleanupBudget) BackendError!CleanupResult,

    pub fn load(
        self: Backend,
        allocator: std.mem.Allocator,
        namespace: Namespace,
        collection_key: []const u8,
        now_ns: i64,
        limits: Limits,
    ) BackendError!Snapshot {
        if (self.abi_version != backend_abi_version) return error.Unavailable;
        return self.loadFn(self.context, allocator, namespace, collection_key, now_ns, limits);
    }

    pub fn commit(self: Backend, request: CommitRequest) BackendError!u64 {
        if (self.abi_version != backend_abi_version) return error.Unavailable;
        return self.commitFn(self.context, request);
    }

    pub fn cleanup(self: Backend, now_ns: i64, budget: CleanupBudget) BackendError!CleanupResult {
        if (self.abi_version != backend_abi_version) return error.Unavailable;
        return self.cleanupFn(self.context, now_ns, budget);
    }
};

const OwnedRecord = struct {
    arena: std.heap.ArenaAllocator,
    namespace: Namespace,
    collection_key: []const u8,
    revision: u64,
    values: std.ArrayList(Value) = .empty,

    fn init(allocator: std.mem.Allocator, namespace: Namespace, collection_key: []const u8, revision: u64) std.mem.Allocator.Error!OwnedRecord {
        var result: OwnedRecord = .{
            .arena = .init(allocator),
            .namespace = namespace,
            .collection_key = undefined,
            .revision = revision,
        };
        errdefer result.arena.deinit();
        result.collection_key = try result.arena.allocator().dupe(u8, collection_key);
        return result;
    }

    fn clone(allocator: std.mem.Allocator, source: *const OwnedRecord) std.mem.Allocator.Error!OwnedRecord {
        var result = try OwnedRecord.init(allocator, source.namespace, source.collection_key, source.revision);
        errdefer result.deinit();
        for (source.values.items) |value| try result.append(value);
        return result;
    }

    fn append(self: *OwnedRecord, value: Value) std.mem.Allocator.Error!void {
        const allocator = self.arena.allocator();
        try self.values.append(allocator, .{
            .name = try allocator.dupe(u8, value.name),
            .value = try allocator.dupe(u8, value.value),
            .expires_at_ns = value.expires_at_ns,
        });
    }

    fn deinit(self: *OwnedRecord) void {
        self.values.deinit(self.arena.allocator());
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Thread-safe optimistic backend used by tests and embedded deployments.
/// Commits build a replacement record before taking publication ownership, so
/// allocation or validation failure cannot expose a partial mutation batch.
pub const InMemoryBackend = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    records: std.ArrayList(OwnedRecord) = .empty,

    pub fn init(allocator: std.mem.Allocator) InMemoryBackend {
        return .{ .allocator = allocator };
    }

    pub fn backend(self: *InMemoryBackend) Backend {
        return .{
            .context = self,
            .loadFn = loadCallback,
            .commitFn = commitCallback,
            .cleanupFn = cleanupCallback,
        };
    }

    pub fn deinit(self: *InMemoryBackend) void {
        lock(&self.mutex);
        for (self.records.items) |*record| record.deinit();
        self.records.deinit(self.allocator);
        self.mutex.unlock();
        self.* = undefined;
    }

    fn loadCallback(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        namespace: Namespace,
        collection_key: []const u8,
        now_ns: i64,
        limits: Limits,
    ) BackendError!Snapshot {
        const self: *InMemoryBackend = @ptrCast(@alignCast(context));
        try validateCollectionKey(collection_key, limits);
        lock(&self.mutex);
        defer self.mutex.unlock();

        const index = self.find(namespace, collection_key) orelse return Snapshot.init(allocator, 0);
        const record = &self.records.items[index];
        var result = Snapshot.init(allocator, record.revision);
        errdefer result.deinit();
        var bytes: usize = 0;
        for (record.values.items) |value| {
            if (value.expired(now_ns)) continue;
            try validateValue(value, limits);
            bytes = checkedRecordBytes(bytes, value, limits) catch return error.CorruptData;
            if (result.values.items.len == limits.max_variables_per_record) return error.CorruptData;
            try result.append(value);
        }
        return result;
    }

    fn commitCallback(context: *anyopaque, request: CommitRequest) BackendError!u64 {
        const self: *InMemoryBackend = @ptrCast(@alignCast(context));
        request.limits.validate() catch return error.InvalidMutation;
        try validateCollectionKey(request.collection_key, request.limits);
        if (request.mutations.len > request.limits.max_mutations_per_commit) return error.CapacityExceeded;

        lock(&self.mutex);
        defer self.mutex.unlock();

        const existing_index = self.find(request.namespace, request.collection_key);
        const current_revision = if (existing_index) |index| self.records.items[index].revision else 0;
        if (current_revision != request.expected_revision) return error.Conflict;
        if (current_revision == std.math.maxInt(u64)) return error.CapacityExceeded;

        var replacement = if (existing_index) |index|
            try OwnedRecord.clone(self.allocator, &self.records.items[index])
        else
            try OwnedRecord.init(self.allocator, request.namespace, request.collection_key, 0);
        errdefer replacement.deinit();
        try applyMutations(&replacement, request.mutations, request.limits);
        replacement.revision = current_revision + 1;

        if (existing_index) |index| {
            var prior = self.records.items[index];
            self.records.items[index] = replacement;
            prior.deinit();
        } else {
            try self.records.append(self.allocator, replacement);
        }
        return current_revision + 1;
    }

    fn cleanupCallback(context: *anyopaque, now_ns: i64, budget: CleanupBudget) BackendError!CleanupResult {
        const self: *InMemoryBackend = @ptrCast(@alignCast(context));
        if (budget.max_records == 0 or budget.max_variables == 0) return .{};
        lock(&self.mutex);
        defer self.mutex.unlock();

        var result: CleanupResult = .{};
        for (self.records.items) |*record| {
            if (result.records_scanned == budget.max_records or result.variables_removed == budget.max_variables) break;
            result.records_scanned += 1;
            var value_index: usize = 0;
            while (value_index < record.values.items.len) {
                if (result.variables_removed == budget.max_variables) break;
                if (!record.values.items[value_index].expired(now_ns)) {
                    value_index += 1;
                    continue;
                }
                _ = record.values.swapRemove(value_index);
                result.variables_removed += 1;
            }
        }
        return result;
    }

    fn find(self: *const InMemoryBackend, namespace: Namespace, collection_key: []const u8) ?usize {
        for (self.records.items, 0..) |record, index| {
            if (record.namespace == namespace and std.mem.eql(u8, record.collection_key, collection_key)) return index;
        }
        return null;
    }
};

fn applyMutations(record: *OwnedRecord, mutations: []const Mutation, limits: Limits) BackendError!void {
    for (mutations) |mutation| switch (mutation) {
        .set => |set| {
            try validateValue(.{ .name = set.name, .value = set.value, .expires_at_ns = set.expires_at_ns }, limits);
            if (findValue(record.values.items, set.name)) |index| {
                const allocator = record.arena.allocator();
                record.values.items[index] = .{
                    .name = try allocator.dupe(u8, set.name),
                    .value = try allocator.dupe(u8, set.value),
                    .expires_at_ns = set.expires_at_ns,
                };
            } else {
                if (record.values.items.len == limits.max_variables_per_record) return error.CapacityExceeded;
                try record.append(.{ .name = set.name, .value = set.value, .expires_at_ns = set.expires_at_ns });
            }
        },
        .remove => |name| {
            if (name.len == 0 or name.len > limits.max_variable_name_bytes) return error.InvalidMutation;
            if (findValue(record.values.items, name)) |index| _ = record.values.swapRemove(index);
        },
    };

    var bytes: usize = 0;
    for (record.values.items) |value| bytes = try checkedRecordBytes(bytes, value, limits);
}

fn validateCollectionKey(collection_key: []const u8, limits: Limits) BackendError!void {
    if (collection_key.len == 0 or collection_key.len > limits.max_collection_key_bytes) return error.InvalidKey;
}

fn validateValue(value: Value, limits: Limits) BackendError!void {
    if (value.name.len == 0 or value.name.len > limits.max_variable_name_bytes) return error.InvalidMutation;
    if (value.value.len > limits.max_variable_value_bytes) return error.InvalidMutation;
}

fn checkedRecordBytes(current: usize, value: Value, limits: Limits) BackendError!usize {
    const item_bytes = std.math.add(usize, value.name.len, value.value.len) catch return error.CapacityExceeded;
    const result = std.math.add(usize, current, item_bytes) catch return error.CapacityExceeded;
    if (result > limits.max_record_bytes) return error.CapacityExceeded;
    return result;
}

fn findValue(values: []const Value, name: []const u8) ?usize {
    for (values, 0..) |value, index| {
        if (std.ascii.eqlIgnoreCase(value.name, name)) return index;
    }
    return null;
}

fn lock(mutex: *std.atomic.Mutex) void {
    var spins: usize = 0;
    while (!mutex.tryLock()) : (spins += 1) {
        if ((spins & 0xff) == 0) std.Thread.yield() catch {} else std.atomic.spinLoopHint();
    }
}

test "persistent namespace registry maps to collection names" {
    inline for (std.meta.tags(Namespace)) |namespace| {
        try std.testing.expectEqual(namespace, Namespace.parse(@tagName(namespace)).?);
        try std.testing.expectEqual(@tagName(namespace), @tagName(namespace.collectionName()));
    }
}

test "in-memory backend commits atomic revisioned mutations and filters expiry" {
    var memory = InMemoryBackend.init(std.testing.allocator);
    defer memory.deinit();
    const backend = memory.backend();
    const limits: Limits = .{};

    const first_revision = try backend.commit(.{
        .namespace = .ip,
        .collection_key = "192.0.2.1",
        .expected_revision = 0,
        .mutations = &.{
            .{ .set = .{ .name = "score", .value = "1" } },
            .{ .set = .{ .name = "short", .value = "gone", .expires_at_ns = 10 } },
        },
        .limits = limits,
    });
    try std.testing.expectEqual(@as(u64, 1), first_revision);
    try std.testing.expectError(error.Conflict, backend.commit(.{
        .namespace = .ip,
        .collection_key = "192.0.2.1",
        .expected_revision = 0,
        .mutations = &.{.{ .set = .{ .name = "score", .value = "lost" } }},
        .limits = limits,
    }));

    var snapshot = try backend.load(std.testing.allocator, .ip, "192.0.2.1", 10, limits);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(u64, 1), snapshot.revision);
    try std.testing.expectEqual(@as(usize, 1), snapshot.values.items.len);
    try std.testing.expectEqualStrings("score", snapshot.values.items[0].name);
    try std.testing.expectEqualStrings("1", snapshot.values.items[0].value);
}

test "in-memory backend enforces record bounds before publication" {
    var memory = InMemoryBackend.init(std.testing.allocator);
    defer memory.deinit();
    const backend = memory.backend();
    const limits: Limits = .{ .max_record_bytes = 3, .max_variable_value_bytes = 3 };
    try std.testing.expectError(error.CapacityExceeded, backend.commit(.{
        .namespace = .session,
        .collection_key = "s",
        .expected_revision = 0,
        .mutations = &.{.{ .set = .{ .name = "ab", .value = "cd" } }},
        .limits = limits,
    }));
    var snapshot = try backend.load(std.testing.allocator, .session, "s", 0, limits);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(u64, 0), snapshot.revision);
    try std.testing.expectEqual(@as(usize, 0), snapshot.values.items.len);
}

test "in-memory cleanup is bounded" {
    var memory = InMemoryBackend.init(std.testing.allocator);
    defer memory.deinit();
    const backend = memory.backend();
    const limits: Limits = .{};
    _ = try backend.commit(.{
        .namespace = .global,
        .collection_key = "global",
        .expected_revision = 0,
        .mutations = &.{
            .{ .set = .{ .name = "one", .value = "1", .expires_at_ns = 1 } },
            .{ .set = .{ .name = "two", .value = "2", .expires_at_ns = 1 } },
        },
        .limits = limits,
    });
    const cleaned = try backend.cleanup(2, .{ .max_records = 1, .max_variables = 1 });
    try std.testing.expectEqual(@as(usize, 1), cleaned.records_scanned);
    try std.testing.expectEqual(@as(usize, 1), cleaned.variables_removed);
}
