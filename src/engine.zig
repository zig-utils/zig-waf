//! Core WAF ownership and transaction lifecycle contracts.

const std = @import("std");
const variables = @import("variables.zig");

pub const Mode = enum {
    enabled,
    detection_only,
};

pub const Phase = enum(u8) {
    connection = 1,
    request_headers = 2,
    request_body = 3,
    response_headers = 4,
    response_body = 5,
    logging = 6,
};

pub const Limits = struct {
    max_request_target_bytes: usize = 16 * 1024,
    max_header_count: usize = 256,
    max_header_bytes: usize = 64 * 1024,
    max_request_body_bytes: usize = 16 * 1024 * 1024,
    max_response_body_bytes: usize = 16 * 1024 * 1024,
    max_scalar_value_bytes: usize = 16 * 1024,
    max_scalar_storage_bytes: usize = 64 * 1024,

    fn validate(self: Limits) ConfigError!void {
        if (self.max_request_target_bytes == 0 or
            self.max_header_count == 0 or
            self.max_header_bytes == 0 or
            self.max_request_body_bytes == 0 or
            self.max_response_body_bytes == 0 or
            self.max_scalar_value_bytes == 0 or
            self.max_scalar_storage_bytes < self.max_scalar_value_bytes)
        {
            return error.InvalidLimit;
        }
    }
};

pub const Config = struct {
    mode: Mode = .enabled,
    limits: Limits = .{},
};

pub const ConfigError = error{InvalidLimit};
pub const DeinitError = error{TransactionsActive};

pub const Intervention = struct {
    action: Action,
    status: u16,
    rule_id: ?u32 = null,
    enforced: bool,

    pub const Action = enum(u8) {
        deny,
        redirect,
        drop,
        pause,
    };
};

/// Builder for a validated immutable `Waf`.
///
/// Ruleset compilation will be added behind this type. Publishing only occurs
/// after complete validation, so callers never observe a partially compiled
/// ruleset.
pub const Builder = struct {
    allocator: std.mem.Allocator,
    config: Config = .{},

    pub fn init(allocator: std.mem.Allocator) Builder {
        return .{ .allocator = allocator };
    }

    pub fn setMode(self: *Builder, mode: Mode) void {
        self.config.mode = mode;
    }

    pub fn setLimits(self: *Builder, limits: Limits) void {
        self.config.limits = limits;
    }

    pub fn build(self: *const Builder) (ConfigError || std.mem.Allocator.Error)!*Waf {
        try self.config.limits.validate();
        const waf = try self.allocator.create(Waf);
        waf.* = .{
            .allocator = self.allocator,
            .config = self.config,
            .active_transactions = std.atomic.Value(usize).init(0),
        };
        return waf;
    }
};

/// Immutable, thread-safe compiled WAF state.
///
/// Keep the pointer stable until every child transaction is deinitialized.
/// `deinit` rejects an early destroy instead of allowing a dangling request.
pub const Waf = struct {
    allocator: std.mem.Allocator,
    config: Config,
    active_transactions: std.atomic.Value(usize),

    pub const Builder = @import("engine.zig").Builder;

    pub fn newTransaction(self: *const Waf) Transaction {
        _ = @constCast(&self.active_transactions).fetchAdd(1, .monotonic);
        return .{ .waf = self, .scalar_variables = variables.Store.init(self.allocator) };
    }

    pub fn activeTransactionCount(self: *const Waf) usize {
        return self.active_transactions.load(.acquire);
    }

    pub fn deinit(self: *Waf) DeinitError!void {
        if (self.active_transactions.load(.acquire) != 0) return error.TransactionsActive;
        const allocator = self.allocator;
        allocator.destroy(self);
    }
};

pub const TransactionError = error{
    InvalidLifecycle,
    Deinitialized,
    InvalidConnectionAddress,
    InvalidMethod,
    InvalidProtocol,
    RequestTargetTooLarge,
    InvalidHeader,
    TooManyHeaders,
    HeadersTooLarge,
    RequestBodyLimitExceeded,
    ResponseBodyLimitExceeded,
    InvalidInterventionStatus,
} || variables.StoreError;

const Lifecycle = enum {
    created,
    connection,
    uri,
    request_headers,
    request_body_writing,
    request_body,
    response_headers,
    response_body_writing,
    response_body,
    logging,
    deinitialized,
};

/// Isolated per-request mutable state.
///
/// The initial implementation records only bounded metadata and body byte
/// counts. Connector-controlled buffering and spooling are layered on this
/// contract; `write*Body` never implies unbounded in-memory retention.
pub const Transaction = struct {
    waf: *const Waf,
    lifecycle: Lifecycle = .created,
    request_header_count: usize = 0,
    request_header_bytes: usize = 0,
    response_header_count: usize = 0,
    response_header_bytes: usize = 0,
    request_body_bytes: usize = 0,
    response_body_bytes: usize = 0,
    pending_intervention: ?Intervention = null,
    scalar_variables: variables.Store,

    pub fn processConnection(
        self: *Transaction,
        client_address: []const u8,
        client_port: u16,
        server_address: []const u8,
        server_port: u16,
    ) TransactionError!void {
        try self.require(.created);
        if (!validAddress(client_address) or !validAddress(server_address) or client_port == 0 or server_port == 0) {
            return error.InvalidConnectionAddress;
        }
        try self.setScalar(.remote_addr, client_address, .connection, .connection);
        try self.setScalarUnsigned(.remote_port, client_port, .connection, .connection);
        try self.setScalar(.server_addr, server_address, .connection, .connection);
        try self.setScalarUnsigned(.server_port, server_port, .connection, .connection);
        self.lifecycle = .connection;
    }

    pub fn processUri(
        self: *Transaction,
        uri: []const u8,
        method: []const u8,
        protocol: []const u8,
    ) TransactionError!void {
        try self.require(.connection);
        if (uri.len == 0 or uri.len > self.waf.config.limits.max_request_target_bytes) {
            return error.RequestTargetTooLarge;
        }
        if (!validToken(method)) return error.InvalidMethod;
        if (!validProtocol(protocol)) return error.InvalidProtocol;
        try self.setScalar(.request_uri_raw, uri, .request_target, .request_headers);
        try self.setScalar(.request_uri, uri, .request_target, .request_headers);
        const query_start = std.mem.indexOfScalar(u8, uri, '?');
        const filename = if (query_start) |index| uri[0..index] else uri;
        const query = if (query_start) |index| uri[index + 1 ..] else "";
        try self.setScalar(.request_filename, filename, .request_target, .request_headers);
        try self.setScalar(.query_string, query, .request_target, .request_headers);
        try self.setScalar(.request_method, method, .request_target, .request_headers);
        try self.setScalar(.request_protocol, protocol, .request_target, .request_headers);
        self.lifecycle = .uri;
    }

    pub fn addRequestHeader(self: *Transaction, name: []const u8, value: []const u8) TransactionError!void {
        try self.require(.uri);
        try self.addHeader(name, value, &self.request_header_count, &self.request_header_bytes);
    }

    pub fn processRequestHeaders(self: *Transaction) TransactionError!void {
        try self.require(.uri);
        self.lifecycle = .request_headers;
    }

    pub fn writeRequestBody(self: *Transaction, chunk: []const u8) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body_writing });
        if (chunk.len > self.waf.config.limits.max_request_body_bytes - self.request_body_bytes) {
            return error.RequestBodyLimitExceeded;
        }
        const next_body_bytes = self.request_body_bytes + chunk.len;
        try self.setScalarUnsigned(.request_body_length, next_body_bytes, .request_body, .request_body);
        self.request_body_bytes = next_body_bytes;
        self.lifecycle = .request_body_writing;
    }

    pub fn processRequestBody(self: *Transaction) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body_writing });
        self.lifecycle = .request_body;
    }

    pub fn addResponseHeader(self: *Transaction, name: []const u8, value: []const u8) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body });
        try self.addHeader(name, value, &self.response_header_count, &self.response_header_bytes);
    }

    pub fn processResponseHeaders(self: *Transaction, status: u16, protocol: []const u8) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body });
        if (status < 100 or status > 999) return error.InvalidInterventionStatus;
        if (!validProtocol(protocol)) return error.InvalidProtocol;
        try self.setScalarUnsigned(.response_status, status, .response, .response_headers);
        try self.setScalar(.response_protocol, protocol, .response, .response_headers);
        self.lifecycle = .response_headers;
    }

    pub fn writeResponseBody(self: *Transaction, chunk: []const u8) TransactionError!void {
        try self.requireAny(&.{ .response_headers, .response_body_writing });
        if (chunk.len > self.waf.config.limits.max_response_body_bytes - self.response_body_bytes) {
            return error.ResponseBodyLimitExceeded;
        }
        const next_body_bytes = self.response_body_bytes + chunk.len;
        try self.setScalarUnsigned(.response_body_length, next_body_bytes, .response, .response_body);
        self.response_body_bytes = next_body_bytes;
        self.lifecycle = .response_body_writing;
    }

    pub fn processResponseBody(self: *Transaction) TransactionError!void {
        try self.requireAny(&.{ .response_headers, .response_body_writing });
        self.lifecycle = .response_body;
    }

    pub fn processLogging(self: *Transaction) TransactionError!void {
        try self.requireAny(&.{
            .request_headers,
            .request_body,
            .response_headers,
            .response_body,
        });
        self.lifecycle = .logging;
    }

    pub fn intervention(self: *const Transaction) TransactionError!?Intervention {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        return self.pending_intervention;
    }

    /// Execution-engine hook. Detection-only mode preserves the decision while
    /// marking it non-enforcing for connector policy.
    pub fn recordIntervention(
        self: *Transaction,
        action: Intervention.Action,
        status: u16,
        rule_id: ?u32,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (status < 100 or status > 999) return error.InvalidInterventionStatus;
        self.pending_intervention = .{
            .action = action,
            .status = status,
            .rule_id = rule_id,
            .enforced = self.waf.config.mode == .enabled,
        };
    }

    pub fn currentPhase(self: *const Transaction) ?Phase {
        return switch (self.lifecycle) {
            .created, .deinitialized => null,
            .connection => .connection,
            .uri, .request_headers => .request_headers,
            .request_body_writing, .request_body => .request_body,
            .response_headers => .response_headers,
            .response_body_writing, .response_body => .response_body,
            .logging => .logging,
        };
    }

    pub fn scalar(self: *const Transaction, name: variables.Name) TransactionError!?variables.View {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const availability = self.currentAvailability() orelse return null;
        return self.scalar_variables.get(name, availability);
    }

    pub fn scalarBySecLangName(self: *const Transaction, name: []const u8) TransactionError!?variables.View {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const availability = self.currentAvailability() orelse return null;
        return self.scalar_variables.getBySecLangName(name, availability);
    }

    pub fn setIdentity(self: *Transaction, remote_user: []const u8, user_id: []const u8) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.setScalar(.remote_user, remote_user, .connector, .request_headers);
        try self.setScalar(.user_id, user_id, .connector, .request_headers);
    }

    pub fn recordMatch(self: *Transaction, name: []const u8, value: []const u8, severity: u8) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.setScalar(.matched_var_name, name, .rule, .request_headers);
        try self.setScalar(.matched_var, value, .rule, .request_headers);
        try self.setScalarUnsigned(.highest_severity, severity, .rule, .request_headers);
    }

    pub fn deinit(self: *Transaction) void {
        if (self.lifecycle == .deinitialized) return;
        self.scalar_variables.deinit();
        self.lifecycle = .deinitialized;
        _ = @constCast(&self.waf.active_transactions).fetchSub(1, .release);
    }

    fn addHeader(
        self: *Transaction,
        name: []const u8,
        value: []const u8,
        count: *usize,
        bytes: *usize,
    ) TransactionError!void {
        if (!validToken(name) or containsLineBreak(value)) return error.InvalidHeader;
        if (count.* == self.waf.config.limits.max_header_count) return error.TooManyHeaders;
        const added = name.len + value.len;
        if (added > self.waf.config.limits.max_header_bytes - bytes.*) return error.HeadersTooLarge;
        count.* += 1;
        bytes.* += added;
    }

    fn require(self: *const Transaction, expected: Lifecycle) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (self.lifecycle != expected) return error.InvalidLifecycle;
    }

    fn requireAny(self: *const Transaction, expected: []const Lifecycle) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        for (expected) |candidate| if (self.lifecycle == candidate) return;
        return error.InvalidLifecycle;
    }

    fn currentAvailability(self: *const Transaction) ?variables.Availability {
        return switch (self.currentPhase() orelse return null) {
            .connection => .connection,
            .request_headers => .request_headers,
            .request_body => .request_body,
            .response_headers => .response_headers,
            .response_body => .response_body,
            .logging => .logging,
        };
    }

    fn setScalar(
        self: *Transaction,
        name: variables.Name,
        value: []const u8,
        origin: variables.Origin,
        available_from: variables.Availability,
    ) TransactionError!void {
        try self.scalar_variables.set(
            name,
            value,
            origin,
            available_from,
            self.waf.config.limits.max_scalar_value_bytes,
            self.waf.config.limits.max_scalar_storage_bytes,
        );
    }

    fn setScalarUnsigned(
        self: *Transaction,
        name: variables.Name,
        value: anytype,
        origin: variables.Origin,
        available_from: variables.Availability,
    ) TransactionError!void {
        try self.scalar_variables.setUnsigned(
            name,
            value,
            origin,
            available_from,
            self.waf.config.limits.max_scalar_value_bytes,
            self.waf.config.limits.max_scalar_storage_bytes,
        );
    }
};

fn validAddress(address: []const u8) bool {
    if (address.len == 0 or address.len > 255) return false;
    return !containsLineBreak(address) and std.mem.indexOfScalar(u8, address, 0) == null;
}

fn validProtocol(protocol: []const u8) bool {
    return std.mem.eql(u8, protocol, "HTTP/1.0") or
        std.mem.eql(u8, protocol, "HTTP/1.1") or
        std.mem.eql(u8, protocol, "HTTP/2") or
        std.mem.eql(u8, protocol, "HTTP/2.0");
}

fn validToken(token: []const u8) bool {
    if (token.len == 0) return false;
    for (token) |byte| {
        if (byte <= 0x20 or byte >= 0x7f or switch (byte) {
            '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}' => true,
            else => false,
        }) return false;
    }
    return true;
}

fn containsLineBreak(value: []const u8) bool {
    return std.mem.indexOfAny(u8, value, "\r\n\x00") != null;
}

test "executes the complete connector lifecycle" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();

    var tx = waf.newTransaction();
    try tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try std.testing.expectEqual(Phase.connection, tx.currentPhase().?);
    try tx.processUri("/login", "POST", "HTTP/1.1");
    try tx.addRequestHeader("content-type", "application/json");
    try tx.processRequestHeaders();
    try tx.writeRequestBody("{\"user\":");
    try tx.writeRequestBody("\"alice\"}");
    try tx.processRequestBody();
    try tx.addResponseHeader("content-type", "application/json");
    try tx.processResponseHeaders(200, "HTTP/1.1");
    try tx.writeResponseBody("{\"ok\":true}");
    try tx.processResponseBody();
    try tx.processLogging();
    try std.testing.expectEqual(Phase.logging, tx.currentPhase().?);
    tx.deinit();
    try waf.deinit();
}

test "rejects invalid phase order and use after deinit" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    var tx = waf.newTransaction();
    try std.testing.expectError(error.InvalidLifecycle, tx.processRequestHeaders());
    tx.deinit();
    try std.testing.expectError(error.Deinitialized, tx.intervention());
    try waf.deinit();
}

test "enforces header and body limits before counters overflow" {
    var builder = Builder.init(std.testing.allocator);
    builder.setLimits(.{
        .max_header_count = 1,
        .max_header_bytes = 8,
        .max_request_body_bytes = 4,
        .max_response_body_bytes = 4,
    });
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("::1", 1234, "::1", 8080);
    try tx.processUri("/", "POST", "HTTP/2");
    try tx.addRequestHeader("x", "1234567");
    try std.testing.expectError(error.TooManyHeaders, tx.addRequestHeader("y", "1"));
    try tx.processRequestHeaders();
    try tx.writeRequestBody("1234");
    try std.testing.expectError(error.RequestBodyLimitExceeded, tx.writeRequestBody("5"));
}

test "prevents WAF destruction while transactions are active" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    var first = waf.newTransaction();
    var second = waf.newTransaction();
    try std.testing.expectEqual(@as(usize, 2), waf.activeTransactionCount());
    try std.testing.expectError(error.TransactionsActive, waf.deinit());
    first.deinit();
    second.deinit();
    try waf.deinit();
}

test "detection-only interventions are visible but not enforced" {
    var builder = Builder.init(std.testing.allocator);
    builder.setMode(.detection_only);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.recordIntervention(.deny, 403, 941100);
    const pending = (try tx.intervention()).?;
    try std.testing.expectEqual(Intervention.Action.deny, pending.action);
    try std.testing.expect(!pending.enforced);
}

test "owns scalar variables and exposes them only in valid phases" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    var client = [_]u8{ '1', '9', '2', '.', '0', '.', '2', '.', '1' };
    try tx.processConnection(&client, 54321, "198.51.100.10", 443);
    client[0] = '9';
    try std.testing.expectEqualStrings("192.0.2.1", (try tx.scalar(.remote_addr)).?.value);
    try std.testing.expect((try tx.scalar(.request_method)) == null);

    try tx.processUri("/search?q=zig", "GET", "HTTP/2");
    try std.testing.expectEqualStrings("q=zig", (try tx.scalarBySecLangName("QUERY_STRING")).?.value);
    try std.testing.expectEqualStrings("/search", (try tx.scalar(.request_filename)).?.value);
    try std.testing.expect((try tx.scalar(.response_status)) == null);
    try tx.processRequestHeaders();
    try tx.processResponseHeaders(403, "HTTP/2");
    try std.testing.expectEqualStrings("403", (try tx.scalar(.response_status)).?.value);
}
