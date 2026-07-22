//! Bounded, transaction-local scalar variable storage.

const std = @import("std");

pub const inline_value_capacity = 256;

pub const Name = enum {
    remote_addr,
    remote_port,
    server_addr,
    server_port,
    request_uri,
    request_uri_raw,
    request_method,
    request_protocol,
    query_string,
    request_filename,
    response_status,
    response_protocol,
    request_body_length,
    response_body_length,
    request_body_error,
    request_body_error_msg,
    inbound_data_error,
    outbound_data_error,
    highest_severity,
    matched_var,
    matched_var_name,
    remote_user,
    user_id,
    unique_id,

    pub fn secLangName(self: Name) []const u8 {
        return switch (self) {
            .remote_addr => "REMOTE_ADDR",
            .remote_port => "REMOTE_PORT",
            .server_addr => "SERVER_ADDR",
            .server_port => "SERVER_PORT",
            .request_uri => "REQUEST_URI",
            .request_uri_raw => "REQUEST_URI_RAW",
            .request_method => "REQUEST_METHOD",
            .request_protocol => "REQUEST_PROTOCOL",
            .query_string => "QUERY_STRING",
            .request_filename => "REQUEST_FILENAME",
            .response_status => "RESPONSE_STATUS",
            .response_protocol => "RESPONSE_PROTOCOL",
            .request_body_length => "REQUEST_BODY_LENGTH",
            .response_body_length => "RESPONSE_BODY_LENGTH",
            .request_body_error => "REQBODY_ERROR",
            .request_body_error_msg => "REQBODY_ERROR_MSG",
            .inbound_data_error => "INBOUND_DATA_ERROR",
            .outbound_data_error => "OUTBOUND_DATA_ERROR",
            .highest_severity => "HIGHEST_SEVERITY",
            .matched_var => "MATCHED_VAR",
            .matched_var_name => "MATCHED_VAR_NAME",
            .remote_user => "REMOTE_USER",
            .user_id => "USERID",
            .unique_id => "UNIQUE_ID",
        };
    }

    pub fn parse(input: []const u8) ?Name {
        inline for (std.meta.tags(Name)) |candidate| {
            if (std.ascii.eqlIgnoreCase(input, candidate.secLangName())) return candidate;
        }
        return null;
    }
};

pub const Origin = enum {
    connection,
    request_target,
    request_body,
    response,
    rule,
    connector,
};

pub const Availability = enum(u8) {
    connection = 1,
    request_headers = 2,
    request_body = 3,
    response_headers = 4,
    response_body = 5,
    logging = 6,
};

pub const View = struct {
    name: Name,
    value: []const u8,
    origin: Origin,
    available_from: Availability,
};

const OwnedValue = struct {
    inline_bytes: [inline_value_capacity]u8 = undefined,
    heap_bytes: ?[]u8 = null,
    len: usize = 0,

    fn assign(self: *OwnedValue, allocator: std.mem.Allocator, input: []const u8) !void {
        if (input.len <= inline_value_capacity) {
            if (self.heap_bytes) |old| allocator.free(old);
            self.heap_bytes = null;
            @memcpy(self.inline_bytes[0..input.len], input);
            self.len = input.len;
            return;
        }

        const replacement = try allocator.dupe(u8, input);
        if (self.heap_bytes) |old| allocator.free(old);
        self.heap_bytes = replacement;
        self.len = input.len;
    }

    fn bytes(self: *const OwnedValue) []const u8 {
        if (self.heap_bytes) |heap| return heap;
        return self.inline_bytes[0..self.len];
    }

    fn deinit(self: *OwnedValue, allocator: std.mem.Allocator) void {
        if (self.heap_bytes) |heap| allocator.free(heap);
        self.* = .{};
    }
};

const Entry = struct {
    value: OwnedValue = .{},
    origin: Origin = .connector,
    available_from: Availability = .connection,
    present: bool = false,
};

pub const StoreError = std.mem.Allocator.Error || error{
    ScalarValueTooLarge,
    ScalarStorageLimitExceeded,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    entries: [std.meta.fieldNames(Name).len]Entry = @splat(.{}),
    total_bytes: usize = 0,

    pub fn init(allocator: std.mem.Allocator) Store {
        return .{ .allocator = allocator };
    }

    pub fn set(
        self: *Store,
        name: Name,
        input: []const u8,
        origin: Origin,
        available_from: Availability,
        max_value_bytes: usize,
        max_total_bytes: usize,
    ) StoreError!void {
        if (input.len > max_value_bytes) return error.ScalarValueTooLarge;
        const entry = &self.entries[@backingInt(name)];
        const previous_len = if (entry.present) entry.value.len else 0;
        const without_previous = self.total_bytes - previous_len;
        if (without_previous > max_total_bytes or input.len > max_total_bytes - without_previous) {
            return error.ScalarStorageLimitExceeded;
        }

        try entry.value.assign(self.allocator, input);
        entry.origin = origin;
        entry.available_from = available_from;
        entry.present = true;
        self.total_bytes = without_previous + input.len;
    }

    pub fn setUnsigned(
        self: *Store,
        name: Name,
        number: anytype,
        origin: Origin,
        available_from: Availability,
        max_value_bytes: usize,
        max_total_bytes: usize,
    ) StoreError!void {
        var buffer: [32]u8 = undefined;
        const rendered = std.fmt.bufPrint(&buffer, "{d}", .{number}) catch unreachable;
        try self.set(name, rendered, origin, available_from, max_value_bytes, max_total_bytes);
    }

    pub fn get(self: *const Store, name: Name, current: Availability) ?View {
        const entry = &self.entries[@backingInt(name)];
        if (!entry.present or @backingInt(current) < @backingInt(entry.available_from)) return null;
        return .{
            .name = name,
            .value = entry.value.bytes(),
            .origin = entry.origin,
            .available_from = entry.available_from,
        };
    }

    pub fn getBySecLangName(self: *const Store, name: []const u8, current: Availability) ?View {
        return self.get(Name.parse(name) orelse return null, current);
    }

    pub fn deinit(self: *Store) void {
        for (&self.entries) |*entry| entry.value.deinit(self.allocator);
        self.total_bytes = 0;
    }
};

test "scalar store owns inputs and enforces phase availability" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    var address = [_]u8{ '1', '2', '7', '.', '0', '.', '0', '.', '1' };
    try store.set(.remote_addr, &address, .connection, .connection, 1024, 4096);
    address[0] = '9';
    try std.testing.expectEqualStrings("127.0.0.1", store.get(.remote_addr, .connection).?.value);

    try store.set(.response_status, "403", .response, .response_headers, 1024, 4096);
    try std.testing.expect(store.get(.response_status, .request_body) == null);
    try std.testing.expectEqualStrings("403", store.getBySecLangName("response_status", .response_headers).?.value);

    var long_value: [inline_value_capacity + 1]u8 = @splat('a');
    try store.set(.unique_id, &long_value, .connector, .request_headers, 1024, 4096);
    long_value[0] = 'z';
    try std.testing.expectEqual(@as(u8, 'a'), store.get(.unique_id, .request_headers).?.value[0]);
}

test "scalar store bounds individual and aggregate values" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try std.testing.expectError(
        error.ScalarValueTooLarge,
        store.set(.request_uri, "12345", .request_target, .request_headers, 4, 8),
    );
    try store.set(.request_method, "POST", .request_target, .request_headers, 4, 8);
    try std.testing.expectError(
        error.ScalarStorageLimitExceeded,
        store.set(.request_protocol, "HTTP/1.1", .request_target, .request_headers, 8, 8),
    );
}
