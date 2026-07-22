//! Bounded transaction-local keyed collection storage and selection.

const std = @import("std");
const variables = @import("variables.zig");

pub const Name = enum {
    args,
    args_get,
    args_get_names,
    args_names,
    args_path,
    args_post,
    args_post_names,
    env,
    files,
    files_names,
    files_sizes,
    files_tmp_content,
    files_tmp_names,
    geo,
    global,
    ip,
    json,
    matched_vars,
    matched_vars_names,
    multipart_filename,
    multipart_name,
    multipart_part_headers,
    request_cookies,
    request_cookies_names,
    request_headers,
    request_headers_names,
    request_xml,
    resource,
    response_args,
    response_headers,
    response_headers_names,
    response_xml,
    rule,
    session,
    tx,
    user,
    xml,

    pub fn secLangName(self: Name) []const u8 {
        return switch (self) {
            .args => "ARGS",
            .args_get => "ARGS_GET",
            .args_get_names => "ARGS_GET_NAMES",
            .args_names => "ARGS_NAMES",
            .args_path => "ARGS_PATH",
            .args_post => "ARGS_POST",
            .args_post_names => "ARGS_POST_NAMES",
            .env => "ENV",
            .files => "FILES",
            .files_names => "FILES_NAMES",
            .files_sizes => "FILES_SIZES",
            .files_tmp_content => "FILES_TMP_CONTENT",
            .files_tmp_names => "FILES_TMPNAMES",
            .geo => "GEO",
            .global => "GLOBAL",
            .ip => "IP",
            .json => "JSON",
            .matched_vars => "MATCHED_VARS",
            .matched_vars_names => "MATCHED_VARS_NAMES",
            .multipart_filename => "MULTIPART_FILENAME",
            .multipart_name => "MULTIPART_NAME",
            .multipart_part_headers => "MULTIPART_PART_HEADERS",
            .request_cookies => "REQUEST_COOKIES",
            .request_cookies_names => "REQUEST_COOKIES_NAMES",
            .request_headers => "REQUEST_HEADERS",
            .request_headers_names => "REQUEST_HEADERS_NAMES",
            .request_xml => "REQUEST_XML",
            .resource => "RESOURCE",
            .response_args => "RESPONSE_ARGS",
            .response_headers => "RESPONSE_HEADERS",
            .response_headers_names => "RESPONSE_HEADERS_NAMES",
            .response_xml => "RESPONSE_XML",
            .rule => "RULE",
            .session => "SESSION",
            .tx => "TX",
            .user => "USER",
            .xml => "XML",
        };
    }

    pub fn parse(input: []const u8) ?Name {
        inline for (std.meta.tags(Name)) |candidate| {
            if (std.ascii.eqlIgnoreCase(input, candidate.secLangName())) return candidate;
        }
        return null;
    }

    pub fn keyPolicy(self: Name) KeyPolicy {
        return switch (self) {
            .request_headers,
            .request_headers_names,
            .response_headers,
            .response_headers_names,
            .env,
            .geo,
            .rule,
            .tx,
            .ip,
            .session,
            .user,
            .global,
            .resource,
            => .ascii_insensitive,
            else => .sensitive,
        };
    }

    pub fn minimumAvailability(self: Name) variables.Availability {
        return switch (self) {
            .args_post,
            .args_post_names,
            .files,
            .files_names,
            .files_sizes,
            .files_tmp_content,
            .files_tmp_names,
            .json,
            .multipart_filename,
            .multipart_name,
            .multipart_part_headers,
            .request_xml,
            .xml,
            => .request_body,
            .response_headers, .response_headers_names => .response_headers,
            .response_args, .response_xml => .response_body,
            else => .request_headers,
        };
    }
};

pub const KeyPolicy = enum { sensitive, ascii_insensitive };

pub const Limits = struct {
    max_entries: usize = 4096,
    max_key_bytes: usize = 4096,
    max_value_bytes: usize = 32 * 1024,
    max_total_bytes: usize = 2 * 1024 * 1024,

    pub fn validate(self: Limits) error{InvalidCollectionLimit}!void {
        if (self.max_entries == 0 or self.max_key_bytes == 0 or self.max_value_bytes == 0 or self.max_total_bytes < self.max_value_bytes) {
            return error.InvalidCollectionLimit;
        }
    }
};

pub const Source = struct {
    origin: variables.Origin,
    offset: usize,
    length: usize,
};

pub const View = struct {
    collection: Name,
    key: []const u8,
    value: []const u8,
    source: Source,
};

pub const Value = struct {
    collection: Name,
    key: []const u8,
    value: []const u8,
    source: Source,
};

const Entry = struct {
    collection: Name,
    key: []u8,
    value: []u8,
    source: Source,
    active: bool = true,
};

pub const SelectorError = error{ MatcherLimitExceeded, MatcherFailed };

pub const Matcher = struct {
    context: *anyopaque,
    matchesFn: *const fn (context: *anyopaque, key: []const u8) SelectorError!bool,

    pub fn matches(self: Matcher, key: []const u8) SelectorError!bool {
        return self.matchesFn(self.context, key);
    }
};

pub const Selector = union(enum) {
    all,
    key: []const u8,
    key_matcher: Matcher,
};

pub const Target = struct {
    collection: Name,
    selector: Selector = .all,
    count_only: bool = false,
};

pub const StoreError = std.mem.Allocator.Error || error{
    TooManyCollectionEntries,
    CollectionKeyTooLarge,
    CollectionValueTooLarge,
    CollectionStorageLimitExceeded,
    InvalidSourceRange,
};

pub const Store = struct {
    arena: std.heap.ArenaAllocator,
    limits: Limits,
    entries: std.ArrayList(Entry) = .empty,
    total_bytes: usize = 0,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) Store {
        return .{ .arena = .init(allocator), .limits = limits };
    }

    pub fn add(
        self: *Store,
        collection: Name,
        key: []const u8,
        value: []const u8,
        source: Source,
    ) StoreError!void {
        if (self.entries.items.len == self.limits.max_entries) return error.TooManyCollectionEntries;
        if (key.len > self.limits.max_key_bytes) return error.CollectionKeyTooLarge;
        if (value.len > self.limits.max_value_bytes) return error.CollectionValueTooLarge;
        if (source.offset > std.math.maxInt(usize) - source.length) return error.InvalidSourceRange;
        const added = key.len + value.len;
        if (added > self.limits.max_total_bytes -| self.total_bytes) return error.CollectionStorageLimitExceeded;

        const arena_allocator = self.arena.allocator();
        const owned_key = try arena_allocator.dupe(u8, key);
        const owned_value = try arena_allocator.dupe(u8, value);
        try self.entries.append(arena_allocator, .{
            .collection = collection,
            .key = owned_key,
            .value = owned_value,
            .source = source,
        });
        self.total_bytes += added;
    }

    /// Atomically append two related values, such as a header value and its
    /// corresponding `*_NAMES` entry.
    pub fn addPair(self: *Store, first_value: Value, second_value: Value) StoreError!void {
        try self.validateValue(first_value, 2);
        try self.validateValue(second_value, 2);
        const added = first_value.key.len + first_value.value.len + second_value.key.len + second_value.value.len;
        if (added > self.limits.max_total_bytes -| self.total_bytes) return error.CollectionStorageLimitExceeded;

        const first_entry = try self.ownEntry(first_value);
        const second_entry = try self.ownEntry(second_value);
        try self.entries.ensureUnusedCapacity(self.arena.allocator(), 2);
        self.entries.appendAssumeCapacity(first_entry);
        self.entries.appendAssumeCapacity(second_entry);
        self.total_bytes += added;
    }

    pub fn select(self: *const Store, collection: Name, selector: Selector) Iterator {
        return .{ .store = self, .collection = collection, .selector = selector };
    }

    pub fn selectTarget(self: *const Store, target: Target, exclusions: []const Target) TargetIterator {
        return .{
            .base = self.select(target.collection, target.selector),
            .exclusions = exclusions,
        };
    }

    pub fn countTarget(self: *const Store, target: Target, exclusions: []const Target) SelectorError!usize {
        var iterator = self.selectTarget(target, exclusions);
        var result: usize = 0;
        while (try iterator.next() != null) result += 1;
        return result;
    }

    pub fn count(self: *const Store, collection: Name, selector: Selector) SelectorError!usize {
        var iterator = self.select(collection, selector);
        var result: usize = 0;
        while (try iterator.next() != null) result += 1;
        return result;
    }

    pub fn first(self: *const Store, collection: Name, key: []const u8) ?View {
        for (self.entries.items) |entry| {
            if (!entry.active or entry.collection != collection or !keysEqual(collection, entry.key, key)) continue;
            return view(entry);
        }
        return null;
    }

    pub fn firstAny(self: *const Store, collection: Name) ?View {
        for (self.entries.items) |entry| {
            if (entry.active and entry.collection == collection) return view(entry);
        }
        return null;
    }

    /// Replace a map-style key or create it. Superseded arena bytes remain
    /// charged to the physical allocation limit, preventing update churn from
    /// becoming unbounded hidden memory growth.
    pub fn set(self: *Store, collection: Name, key: []const u8, value: []const u8, source: Source) StoreError!void {
        if (key.len > self.limits.max_key_bytes) return error.CollectionKeyTooLarge;
        if (value.len > self.limits.max_value_bytes) return error.CollectionValueTooLarge;
        if (source.offset > std.math.maxInt(usize) - source.length) return error.InvalidSourceRange;
        for (self.entries.items) |*entry| {
            if (entry.collection != collection or !keysEqual(collection, entry.key, key)) continue;
            if (value.len > self.limits.max_total_bytes -| self.total_bytes) return error.CollectionStorageLimitExceeded;
            entry.value = try self.arena.allocator().dupe(u8, value);
            entry.source = source;
            entry.active = true;
            self.total_bytes += value.len;
            return;
        }
        return self.add(collection, key, value, source);
    }

    pub fn remove(self: *Store, collection: Name, selector: Selector) SelectorError!usize {
        var removed: usize = 0;
        for (self.entries.items) |*entry| {
            if (!entry.active or entry.collection != collection or !try selected(collection, entry.key, selector)) continue;
            entry.active = false;
            removed += 1;
        }
        return removed;
    }

    pub fn deinit(self: *Store) void {
        self.entries.deinit(self.arena.allocator());
        self.arena.deinit();
        self.* = undefined;
    }

    fn validateValue(self: *const Store, value: Value, needed_entries: usize) StoreError!void {
        if (needed_entries > self.limits.max_entries -| self.entries.items.len) return error.TooManyCollectionEntries;
        if (value.key.len > self.limits.max_key_bytes) return error.CollectionKeyTooLarge;
        if (value.value.len > self.limits.max_value_bytes) return error.CollectionValueTooLarge;
        if (value.source.offset > std.math.maxInt(usize) - value.source.length) return error.InvalidSourceRange;
    }

    fn ownEntry(self: *Store, value: Value) std.mem.Allocator.Error!Entry {
        const arena_allocator = self.arena.allocator();
        const key = try arena_allocator.dupe(u8, value.key);
        const owned_value = try arena_allocator.dupe(u8, value.value);
        return .{
            .collection = value.collection,
            .key = key,
            .value = owned_value,
            .source = value.source,
        };
    }
};

pub const Iterator = struct {
    store: *const Store,
    collection: Name,
    selector: Selector,
    index: usize = 0,

    pub fn next(self: *Iterator) SelectorError!?View {
        while (self.index < self.store.entries.items.len) {
            const entry = &self.store.entries.items[self.index];
            self.index += 1;
            if (!entry.active or entry.collection != self.collection or !try selected(self.collection, entry.key, self.selector)) continue;
            return view(entry.*);
        }
        return null;
    }
};

pub const TargetIterator = struct {
    base: Iterator,
    exclusions: []const Target,

    pub fn next(self: *TargetIterator) SelectorError!?View {
        while (try self.base.next()) |candidate| {
            var excluded = false;
            for (self.exclusions) |exclusion| {
                if (exclusion.collection == candidate.collection and try selected(candidate.collection, candidate.key, exclusion.selector)) {
                    excluded = true;
                    break;
                }
            }
            if (!excluded) return candidate;
        }
        return null;
    }
};

fn selected(collection: Name, key: []const u8, selector: Selector) SelectorError!bool {
    return switch (selector) {
        .all => true,
        .key => |wanted| keysEqual(collection, key, wanted),
        .key_matcher => |matcher| try matcher.matches(key),
    };
}

fn keysEqual(collection: Name, first_key: []const u8, second_key: []const u8) bool {
    return switch (collection.keyPolicy()) {
        .sensitive => std.mem.eql(u8, first_key, second_key),
        .ascii_insensitive => std.ascii.eqlIgnoreCase(first_key, second_key),
    };
}

fn view(entry: Entry) View {
    return .{ .collection = entry.collection, .key = entry.key, .value = entry.value, .source = entry.source };
}

const PrefixMatcher = struct {
    prefix: []const u8,

    fn matches(context: *anyopaque, key: []const u8) SelectorError!bool {
        const self: *PrefixMatcher = @ptrCast(@alignCast(context));
        return std.mem.startsWith(u8, key, self.prefix);
    }
};

const ErrorMatcher = struct {
    fn matches(_: *anyopaque, _: []const u8) SelectorError!bool {
        return error.MatcherLimitExceeded;
    }
};

test "collection registry round trips and has unique names" {
    const names = std.meta.tags(Name);
    try std.testing.expectEqual(@as(usize, 37), names.len);
    for (names, 0..) |name, index| {
        try std.testing.expectEqual(name, Name.parse(name.secLangName()).?);
        for (names[0..index]) |prior| {
            try std.testing.expect(!std.ascii.eqlIgnoreCase(name.secLangName(), prior.secLangName()));
        }
    }
}

test "store owns repeated values and preserves source origins" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = [_]u8{ 'f', 'i', 'r', 's', 't' };
    try store.add(.request_headers, "X-Test", &value, .{ .origin = .request_header, .offset = 10, .length = 5 });
    value[0] = 'x';
    try store.add(.request_headers, "x-test", "second", .{ .origin = .request_header, .offset = 30, .length = 6 });

    try std.testing.expectEqual(@as(usize, 2), try store.count(.request_headers, .{ .key = "X-TEST" }));
    const first = store.first(.request_headers, "x-test").?;
    try std.testing.expectEqualStrings("first", first.value);
    try std.testing.expectEqual(@as(usize, 10), first.source.offset);
}

test "selector callback scans keys without allocating" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try store.add(.args_get, "user.name", "alice", .{ .origin = .request_target, .offset = 3, .length = 5 });
    try store.add(.args_get, "admin", "false", .{ .origin = .request_target, .offset = 20, .length = 5 });
    var prefix: PrefixMatcher = .{ .prefix = "user." };
    const matcher: Matcher = .{ .context = &prefix, .matchesFn = PrefixMatcher.matches };
    try std.testing.expectEqual(@as(usize, 1), try store.count(.args_get, .{ .key_matcher = matcher }));
}

test "collection limits fail before taking ownership" {
    var store = Store.init(std.testing.allocator, .{
        .max_entries = 1,
        .max_key_bytes = 2,
        .max_value_bytes = 3,
        .max_total_bytes = 4,
    });
    defer store.deinit();
    try std.testing.expectError(error.CollectionKeyTooLarge, store.add(.tx, "key", "1", .{ .origin = .rule, .offset = 0, .length = 0 }));
    try std.testing.expectError(error.CollectionValueTooLarge, store.add(.tx, "k", "1234", .{ .origin = .rule, .offset = 0, .length = 0 }));
    try store.add(.tx, "k", "123", .{ .origin = .rule, .offset = 0, .length = 0 });
    try std.testing.expectError(error.TooManyCollectionEntries, store.add(.tx, "x", "1", .{ .origin = .rule, .offset = 0, .length = 0 }));
}

test "paired insertion is atomic under entry and byte limits" {
    var store = Store.init(std.testing.allocator, .{ .max_entries = 1 });
    defer store.deinit();
    const source: Source = .{ .origin = .request_header, .offset = 0, .length = 1 };
    try std.testing.expectError(error.TooManyCollectionEntries, store.addPair(
        .{ .collection = .request_headers, .key = "x", .value = "1", .source = source },
        .{ .collection = .request_headers_names, .key = "x", .value = "x", .source = source },
    ));
    try std.testing.expectEqual(@as(usize, 0), try store.count(.request_headers, .all));
}

test "map replacement and removal stay physically bounded" {
    var store = Store.init(std.testing.allocator, .{ .max_total_bytes = 12, .max_value_bytes = 12 });
    defer store.deinit();
    const source: Source = .{ .origin = .rule, .offset = 0, .length = 0 };
    try store.set(.tx, "k", "one", source);
    try store.set(.tx, "K", "two", source);
    try std.testing.expectEqualStrings("two", store.first(.tx, "k").?.value);
    try std.testing.expectEqual(@as(usize, 1), try store.remove(.tx, .{ .key = "K" }));
    try std.testing.expect(store.first(.tx, "k") == null);
    try store.set(.tx, "k", "3", source);
    try std.testing.expectEqualStrings("3", store.first(.tx, "K").?.value);
    try std.testing.expectError(error.CollectionStorageLimitExceeded, store.set(.tx, "k", "123456", source));
}

test "target exclusions and count semantics compose without allocation" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();
    const source: Source = .{ .origin = .request_target, .offset = 0, .length = 1 };
    try store.add(.args_get, "user", "a", source);
    try store.add(.args_get, "password", "b", source);
    try store.add(.args_get, "token", "c", source);
    const target: Target = .{ .collection = .args_get, .count_only = true };
    const exclusions = [_]Target{.{ .collection = .args_get, .selector = .{ .key = "password" } }};
    try std.testing.expectEqual(@as(usize, 2), try store.countTarget(target, &exclusions));
}

test "selector matcher failures never become non-matches" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try store.add(.args, "x", "1", .{ .origin = .request_target, .offset = 0, .length = 1 });
    var context: u8 = 0;
    const matcher: Matcher = .{ .context = &context, .matchesFn = ErrorMatcher.matches };
    try std.testing.expectError(error.MatcherLimitExceeded, store.count(.args, .{ .key_matcher = matcher }));
}
