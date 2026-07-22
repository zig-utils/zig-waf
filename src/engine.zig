//! Core WAF ownership and transaction lifecycle contracts.

const std = @import("std");
const collections = @import("collections.zig");
const macros = @import("macros.zig");
const persistent = @import("persistent.zig");
const variables = @import("variables.zig");

pub const Mode = enum {
    enabled,
    detection_only,
};

pub const Feature = enum(u6) {
    transaction_lifecycle,
    bounded_streaming_bodies,
    detection_only,
    native_sqli,
    scalar_variables,
    collection_variables,
    runtime_macros,
    persistent_collections,
    atomic_hot_reload,
};

pub const FeatureSet = struct {
    bits: u64,

    pub fn allCompiled() FeatureSet {
        var bits: u64 = 0;
        inline for (std.meta.tags(Feature)) |feature| bits |= bit(feature);
        return .{ .bits = bits };
    }

    pub fn has(self: FeatureSet, feature: Feature) bool {
        return self.bits & bit(feature) != 0;
    }

    fn bit(feature: Feature) u64 {
        return @as(u64, 1) << @backingInt(feature);
    }
};

pub const Phase = enum(u8) {
    request_headers = 1,
    request_body = 2,
    response_headers = 3,
    response_body = 4,
    logging = 5,
};

pub const Limits = struct {
    max_request_target_bytes: usize = 16 * 1024,
    max_header_count: usize = 256,
    max_header_bytes: usize = 64 * 1024,
    max_request_body_bytes: usize = 16 * 1024 * 1024,
    max_response_body_bytes: usize = 16 * 1024 * 1024,
    max_scalar_value_bytes: usize = 32 * 1024,
    max_scalar_storage_bytes: usize = 256 * 1024,
    collection_limits: collections.Limits = .{},

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
        self.collection_limits.validate() catch return error.InvalidLimit;
    }
};

pub const Config = struct {
    mode: Mode = .enabled,
    limits: Limits = .{},
    macro_missing_policy: macros.MissingPolicy = .empty,
    persistent_backend: ?persistent.Backend = null,
    persistent_limits: persistent.Limits = .{},
    persistent_failure_policy: persistent.FailurePolicy = .fail_closed,
};

pub const ClockSample = struct {
    unix_nanoseconds: i96,
    awake_nanoseconds: i96,
};

/// Optional deterministic clock provider for embedders and tests. The callback
/// must be nonblocking and thread-safe, and its context must outlive the WAF.
pub const ClockSource = struct {
    context: *anyopaque,
    nowFn: *const fn (context: *anyopaque) ClockSample,

    pub fn now(self: ClockSource) ClockSample {
        return self.nowFn(self.context);
    }
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
    io: std.Io,
    clock_source: ?ClockSource = null,

    pub fn init(allocator: std.mem.Allocator) Builder {
        return .{
            .allocator = allocator,
            .io = std.Io.Threaded.global_single_threaded.io(),
        };
    }

    /// Override the clock backend. The application owns the backend and must
    /// keep it alive until the WAF and all of its transactions are destroyed.
    pub fn setIo(self: *Builder, io: std.Io) void {
        self.io = io;
    }

    pub fn setClockSource(self: *Builder, source: ClockSource) void {
        self.clock_source = source;
    }

    pub fn setMode(self: *Builder, mode: Mode) void {
        self.config.mode = mode;
    }

    pub fn setLimits(self: *Builder, limits: Limits) void {
        self.config.limits = limits;
    }

    pub fn setMacroMissingPolicy(self: *Builder, policy: macros.MissingPolicy) void {
        self.config.macro_missing_policy = policy;
    }

    pub fn setPersistentBackend(self: *Builder, backend: persistent.Backend) void {
        self.config.persistent_backend = backend;
    }

    pub fn setPersistentLimits(self: *Builder, limits: persistent.Limits) void {
        self.config.persistent_limits = limits;
    }

    pub fn setPersistentFailurePolicy(self: *Builder, policy: persistent.FailurePolicy) void {
        self.config.persistent_failure_policy = policy;
    }

    pub fn build(self: *const Builder) (ConfigError || std.mem.Allocator.Error)!*Waf {
        try self.config.limits.validate();
        self.config.persistent_limits.validate() catch return error.InvalidLimit;
        const waf = try self.allocator.create(Waf);
        waf.* = .{
            .allocator = self.allocator,
            .config = self.config,
            .io = self.io,
            .clock_source = self.clock_source,
            .active_transactions = std.atomic.Value(usize).init(0),
            .transaction_sequence = std.atomic.Value(u64).init(0),
        };
        return waf;
    }

    pub fn buildRuntime(self: *const Builder) (ConfigError || RuntimeInitError)!*Runtime {
        const waf = try self.build();
        errdefer waf.deinit() catch unreachable;
        return Runtime.init(self.allocator, waf);
    }
};

/// Immutable, thread-safe compiled WAF state.
///
/// Keep the pointer stable until every child transaction is deinitialized.
/// `deinit` rejects an early destroy instead of allowing a dangling request.
pub const Waf = struct {
    allocator: std.mem.Allocator,
    config: Config,
    io: std.Io,
    clock_source: ?ClockSource,
    active_transactions: std.atomic.Value(usize),
    transaction_sequence: std.atomic.Value(u64),

    pub const Builder = @import("engine.zig").Builder;

    pub fn newTransaction(self: *const Waf) Transaction {
        _ = @constCast(&self.active_transactions).fetchAdd(1, .monotonic);
        const started = self.now();
        return .{
            .waf = self,
            .scalar_variables = variables.Store.init(self.allocator),
            .collection_variables = collections.Store.init(self.allocator, self.config.limits.collection_limits),
            .persistent_session = if (self.config.persistent_backend) |backend|
                persistent.Session.init(self.allocator, backend, self.config.persistent_limits) catch unreachable
            else
                null,
            .started_real_nanoseconds = started.unix_nanoseconds,
            .started_awake_nanoseconds = started.awake_nanoseconds,
            .sequence = @constCast(&self.transaction_sequence).fetchAdd(1, .monotonic),
        };
    }

    pub fn activeTransactionCount(self: *const Waf) usize {
        return self.active_transactions.load(.acquire);
    }

    pub fn features(_: *const Waf) FeatureSet {
        return FeatureSet.allCompiled();
    }

    fn now(self: *const Waf) ClockSample {
        if (self.clock_source) |source| return source.now();
        return .{
            .unix_nanoseconds = std.Io.Clock.now(.real, self.io).nanoseconds,
            .awake_nanoseconds = std.Io.Clock.now(.awake, self.io).nanoseconds,
        };
    }

    pub fn deinit(self: *Waf) DeinitError!void {
        if (self.active_transactions.load(.acquire) != 0) return error.TransactionsActive;
        const allocator = self.allocator;
        allocator.destroy(self);
    }
};

pub const RuntimeError = error{
    ShuttingDown,
    SameGeneration,
    GenerationInUse,
};

pub const RuntimeInitError = std.mem.Allocator.Error || error{GenerationInUse};

pub const RuntimeDeinitError = error{TransactionsActive};

/// Stable owner for atomically published immutable WAF generations.
///
/// The mutex protects only generation pointer acquisition and replacement.
/// Once returned, a transaction executes without touching the runtime lock and
/// remains pinned to the generation from which it was created.
pub const Runtime = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    active: ?*Waf,

    pub fn init(allocator: std.mem.Allocator, initial: *Waf) RuntimeInitError!*Runtime {
        if (initial.activeTransactionCount() != 0) return error.GenerationInUse;
        const runtime = try allocator.create(Runtime);
        runtime.* = .{ .allocator = allocator, .active = initial };
        return runtime;
    }

    pub fn newTransaction(self: *Runtime) RuntimeError!Transaction {
        lock(&self.mutex);
        defer self.mutex.unlock();
        return (self.active orelse return error.ShuttingDown).newTransaction();
    }

    /// Publish `replacement` and transfer ownership of the prior generation to
    /// the returned retirement handle. A replacement with existing requests is
    /// rejected because its ownership is not exclusive.
    pub fn reload(self: *Runtime, replacement: *Waf) RuntimeError!RetiredGeneration {
        if (replacement.activeTransactionCount() != 0) return error.GenerationInUse;
        lock(&self.mutex);
        defer self.mutex.unlock();
        const current = self.active orelse return error.ShuttingDown;
        if (current == replacement) return error.SameGeneration;
        self.active = replacement;
        return .{ .waf = current };
    }

    pub fn activeTransactionCount(self: *Runtime) RuntimeError!usize {
        lock(&self.mutex);
        defer self.mutex.unlock();
        return (self.active orelse return error.ShuttingDown).activeTransactionCount();
    }

    /// Destroy the runtime and its active generation. Callers must first stop
    /// creating transactions and separately reclaim every retired generation.
    pub fn deinit(self: *Runtime) RuntimeDeinitError!void {
        lock(&self.mutex);
        const active = self.active orelse unreachable;
        if (active.activeTransactionCount() != 0) {
            self.mutex.unlock();
            return error.TransactionsActive;
        }
        self.active = null;
        self.mutex.unlock();

        active.deinit() catch unreachable;
        const allocator = self.allocator;
        allocator.destroy(self);
    }
};

pub const RetiredGeneration = struct {
    waf: ?*Waf,

    pub fn activeTransactionCount(self: *const RetiredGeneration) usize {
        return (self.waf orelse return 0).activeTransactionCount();
    }

    pub fn tryReclaim(self: *RetiredGeneration) DeinitError!void {
        const waf = self.waf orelse return;
        try waf.deinit();
        self.waf = null;
    }

    pub fn isReclaimed(self: *const RetiredGeneration) bool {
        return self.waf == null;
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
    InterventionAlreadyRecorded,
    TransactionTerminated,
    ClockBeforeUnixEpoch,
    MacroOutputTooLarge,
    CollectionSizeOverflow,
    PersistentBackendNotConfigured,
    PersistentTimestampOverflow,
} || variables.StoreError || collections.StoreError || collections.SelectorError || persistent.SessionError;

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

pub const ArgumentOrigin = enum { query, body, path };
pub const PersistentInitialization = enum { loaded, already_initialized, failed_open };

pub const PersistentFailure = enum {
    unavailable,
    timeout,
    conflict_exhausted,
    corrupt_data,
    capacity_exceeded,
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
    collection_variables: collections.Store,
    persistent_session: ?persistent.Session,
    last_persistent_failure: ?PersistentFailure = null,
    phase_interrupted: bool = false,
    transaction_terminated: bool = false,
    started_real_nanoseconds: i96,
    started_awake_nanoseconds: i96,
    sequence: u64,
    highest_severity: u8 = 255,
    args_combined_size: usize = 0,
    files_combined_size: u64 = 0,

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
        try self.initializeCompatibilityScalars();
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
        try self.setScalar(.path_info, filename, .request_target, .request_headers);
        const slash = std.mem.lastIndexOfAny(u8, filename, "/\\");
        const basename = if (slash) |index| filename[index + 1 ..] else filename;
        try self.setScalar(.request_basename, basename, .request_target, .request_headers);
        try self.setScalar(.query_string, query, .request_target, .request_headers);
        try self.setScalar(.request_method, method, .request_target, .request_headers);
        try self.setScalar(.request_protocol, protocol, .request_target, .request_headers);
        const request_line = try std.fmt.allocPrint(self.waf.allocator, "{s} {s} {s}", .{ method, uri, protocol });
        defer self.waf.allocator.free(request_line);
        try self.setScalar(.request_line, request_line, .request_target, .request_headers);
        self.lifecycle = .uri;
    }

    pub fn addRequestHeader(self: *Transaction, name: []const u8, value: []const u8) TransactionError!void {
        try self.require(.uri);
        const added = try self.validateHeader(name, value, self.request_header_count, self.request_header_bytes);
        const name_source: collections.Source = .{
            .origin = .request_header,
            .offset = self.request_header_bytes,
            .length = name.len,
        };
        const value_source: collections.Source = .{
            .origin = .request_header,
            .offset = self.request_header_bytes + name.len + 2,
            .length = value.len,
        };
        try self.collection_variables.addPair(
            .{ .collection = .request_headers, .key = name, .value = value, .source = value_source },
            .{ .collection = .request_headers_names, .key = name, .value = name, .source = name_source },
        );
        if (std.ascii.eqlIgnoreCase(name, "content-type")) {
            if (startsWithIgnoreCase(value, "multipart/form-data")) {
                try self.setScalar(.reqbody_processor, "MULTIPART", .request_header, .request_headers);
            } else if (startsWithIgnoreCase(value, "application/x-www-form-urlencoded")) {
                try self.setScalar(.reqbody_processor, "URLENCODED", .request_header, .request_headers);
            } else if (startsWithIgnoreCase(value, "application/json")) {
                try self.setScalar(.reqbody_processor, "JSON", .request_header, .request_headers);
            } else if (startsWithIgnoreCase(value, "application/xml") or startsWithIgnoreCase(value, "text/xml")) {
                try self.setScalar(.reqbody_processor, "XML", .request_header, .request_headers);
            }
        } else if (std.ascii.eqlIgnoreCase(name, "authorization")) {
            const end = std.mem.indexOfScalar(u8, value, ' ') orelse value.len;
            if (end != 0) try self.setScalar(.auth_type, value[0..end], .request_header, .request_headers);
        } else if (std.ascii.eqlIgnoreCase(name, "host")) {
            const host = hostWithoutPort(value);
            if (host.len != 0) try self.setScalar(.server_name, host, .request_header, .request_headers);
        }
        self.request_header_count += 1;
        self.request_header_bytes += added;
    }

    pub fn processRequestHeaders(self: *Transaction) TransactionError!void {
        try self.require(.uri);
        self.phase_interrupted = false;
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
        if (self.scalar_variables.get(.request_body_length, .request_body) == null) {
            try self.setScalarUnsigned(.request_body_length, 0, .request_body, .request_body);
        }
        try self.setFlagIfMissing(.reqbody_error, false, .request_body, .request_body);
        try self.setFlagIfMissing(.reqbody_processor_error, false, .request_body, .request_body);
        try self.setFlagIfMissing(.inbound_data_error, false, .request_body, .request_body);
        self.phase_interrupted = false;
        self.lifecycle = .request_body;
    }

    pub fn addResponseHeader(self: *Transaction, name: []const u8, value: []const u8) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body });
        const added = try self.validateHeader(name, value, self.response_header_count, self.response_header_bytes);
        const name_source: collections.Source = .{
            .origin = .response_header,
            .offset = self.response_header_bytes,
            .length = name.len,
        };
        const value_source: collections.Source = .{
            .origin = .response_header,
            .offset = self.response_header_bytes + name.len + 2,
            .length = value.len,
        };
        try self.collection_variables.addPair(
            .{ .collection = .response_headers, .key = name, .value = value, .source = value_source },
            .{ .collection = .response_headers_names, .key = name, .value = name, .source = name_source },
        );
        if (std.ascii.eqlIgnoreCase(name, "content-type")) {
            try self.setScalar(.response_content_type, value, .response_header, .response_headers);
        }
        self.response_header_count += 1;
        self.response_header_bytes += added;
    }

    pub fn processResponseHeaders(self: *Transaction, status: u16, protocol: []const u8) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body });
        if (status < 100 or status > 599) return error.InvalidInterventionStatus;
        if (!validProtocol(protocol)) return error.InvalidProtocol;
        try self.setScalarUnsigned(.response_status, status, .response, .response_headers);
        try self.setScalarUnsigned(.status, status, .compatibility, .response_headers);
        try self.setScalar(.response_protocol, protocol, .response, .response_headers);
        const status_line = try std.fmt.allocPrint(self.waf.allocator, "{s} {d}", .{ protocol, status });
        defer self.waf.allocator.free(status_line);
        try self.setScalar(.status_line, status_line, .compatibility, .response_headers);
        self.phase_interrupted = false;
        self.lifecycle = .response_headers;
    }

    pub fn writeResponseBody(self: *Transaction, chunk: []const u8) TransactionError!void {
        try self.requireAny(&.{ .response_headers, .response_body_writing });
        if (chunk.len > self.waf.config.limits.max_response_body_bytes - self.response_body_bytes) {
            return error.ResponseBodyLimitExceeded;
        }
        const next_body_bytes = self.response_body_bytes + chunk.len;
        try self.setScalarUnsigned(.response_content_length, next_body_bytes, .response, .response_body);
        self.response_body_bytes = next_body_bytes;
        self.lifecycle = .response_body_writing;
    }

    pub fn processResponseBody(self: *Transaction) TransactionError!void {
        try self.requireAny(&.{ .response_headers, .response_body_writing });
        if (self.scalar_variables.get(.response_content_length, .response_body) == null) {
            try self.setScalarUnsigned(.response_content_length, 0, .response, .response_body);
        }
        try self.setFlagIfMissing(.outbound_data_error, false, .response, .response_body);
        try self.setFlagIfMissing(.res_body_error, false, .response, .response_body);
        try self.setFlagIfMissing(.res_body_processor_error, false, .response, .response_body);
        self.phase_interrupted = false;
        self.lifecycle = .response_body;
    }

    pub fn processLogging(self: *Transaction) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (self.lifecycle == .created or self.lifecycle == .connection or self.lifecycle == .logging) {
            return error.InvalidLifecycle;
        }
        _ = try self.flushPersistentCollections();
        self.phase_interrupted = false;
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
        if (self.currentPhase() == null) return error.InvalidLifecycle;
        if (self.pending_intervention != null) return error.InterventionAlreadyRecorded;
        if (status < 100 or status > 599) return error.InvalidInterventionStatus;
        self.pending_intervention = .{
            .action = action,
            .status = status,
            .rule_id = rule_id,
            .enforced = self.waf.config.mode == .enabled,
        };
        if (self.waf.config.mode == .enabled) {
            self.phase_interrupted = true;
            self.transaction_terminated = action == .drop;
        }
    }

    pub fn currentPhase(self: *const Transaction) ?Phase {
        return switch (self.lifecycle) {
            .created, .connection, .deinitialized => null,
            .uri, .request_headers => .request_headers,
            .request_body_writing, .request_body => .request_body,
            .response_headers => .response_headers,
            .response_body_writing, .response_body => .response_body,
            .logging => .logging,
        };
    }

    pub fn isPhaseInterrupted(self: *const Transaction) bool {
        return self.phase_interrupted;
    }

    pub fn isTerminated(self: *const Transaction) bool {
        return self.transaction_terminated;
    }

    pub fn isLoggingFinalized(self: *const Transaction) bool {
        return self.lifecycle == .logging;
    }

    pub fn scalar(self: *Transaction, name: variables.Name) TransactionError!?variables.View {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (name == .duration) try self.updateDuration();
        const availability = self.currentAvailability() orelse return null;
        return self.scalar_variables.get(name, availability);
    }

    pub fn scalarBySecLangName(self: *Transaction, name: []const u8) TransactionError!?variables.View {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (variables.Name.parse(name)) |parsed| if (parsed == .duration) try self.updateDuration();
        const availability = self.currentAvailability() orelse return null;
        return self.scalar_variables.getBySecLangName(name, availability);
    }

    pub fn collection(self: *const Transaction, name: collections.Name, selector: collections.Selector) TransactionError!?collections.Iterator {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const availability = self.currentAvailability() orelse return null;
        if (@backingInt(availability) < @backingInt(name.minimumAvailability())) return null;
        return self.collection_variables.select(name, selector);
    }

    pub fn collectionFirst(self: *const Transaction, name: collections.Name, key: []const u8) TransactionError!?collections.View {
        var iterator = (try self.collection(name, .{ .key = key })) orelse return null;
        return try iterator.next();
    }

    pub fn collectionTarget(self: *const Transaction, target: collections.Target, exclusions: []const collections.Target) TransactionError!?collections.TargetIterator {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const availability = self.currentAvailability() orelse return null;
        if (@backingInt(availability) < @backingInt(target.collection.minimumAvailability())) return null;
        return self.collection_variables.selectTarget(target, exclusions);
    }

    pub fn collectionCount(self: *const Transaction, target: collections.Target, exclusions: []const collections.Target) TransactionError!?usize {
        if ((try self.collectionTarget(target, exclusions)) == null) return null;
        return try self.collection_variables.countTarget(target, exclusions);
    }

    pub fn addCollectionValue(
        self: *Transaction,
        name: collections.Name,
        key: []const u8,
        value: []const u8,
        source: collections.Source,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.collection_variables.add(name, key, value, source);
    }

    pub fn addArgument(
        self: *Transaction,
        argument_origin: ArgumentOrigin,
        key: []const u8,
        value: []const u8,
        source: collections.Source,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const mapping: struct {
            specific: collections.Name,
            names: collections.Name,
            availability: variables.Availability,
        } = switch (argument_origin) {
            .query => .{ .specific = .args_get, .names = .args_get_names, .availability = .request_headers },
            .body => .{ .specific = .args_post, .names = .args_post_names, .availability = .request_body },
            .path => .{ .specific = .args_path, .names = .args_names, .availability = .request_headers },
        };
        const values = [_]collections.Value{
            .{ .collection = mapping.specific, .key = key, .value = value, .source = source },
            .{ .collection = mapping.names, .key = key, .value = key, .source = source },
            .{ .collection = .args, .key = key, .value = value, .source = source },
            .{ .collection = .args_names, .key = key, .value = key, .source = source },
        };
        const added = std.math.add(usize, key.len, value.len) catch return error.CollectionSizeOverflow;
        const next_combined_size = std.math.add(usize, self.args_combined_size, added) catch return error.CollectionSizeOverflow;
        try self.collection_variables.addBatch(&values);
        self.args_combined_size = next_combined_size;
        try self.setScalarUnsigned(.args_combined_size, self.args_combined_size, .parser, mapping.availability);
    }

    pub fn addRequestCookie(self: *Transaction, key: []const u8, value: []const u8, source: collections.Source) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.collection_variables.addPair(
            .{ .collection = .request_cookies, .key = key, .value = value, .source = source },
            .{ .collection = .request_cookies_names, .key = key, .value = key, .source = source },
        );
    }

    pub fn addFileMetadata(
        self: *Transaction,
        field: []const u8,
        original_name: []const u8,
        temporary_name: []const u8,
        size: u64,
        source: collections.Source,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        var size_buffer: [32]u8 = undefined;
        const size_text = std.fmt.bufPrint(&size_buffer, "{d}", .{size}) catch unreachable;
        const values = [_]collections.Value{
            .{ .collection = .files, .key = field, .value = temporary_name, .source = source },
            .{ .collection = .files_names, .key = field, .value = original_name, .source = source },
            .{ .collection = .files_sizes, .key = field, .value = size_text, .source = source },
            .{ .collection = .files_tmp_names, .key = field, .value = temporary_name, .source = source },
        };
        const next_combined_size = std.math.add(u64, self.files_combined_size, size) catch return error.CollectionSizeOverflow;
        try self.collection_variables.addBatch(&values);
        self.files_combined_size = next_combined_size;
        try self.setScalarUnsigned(.files_combined_size, self.files_combined_size, .parser, .request_body);
    }

    pub fn setCollectionValue(
        self: *Transaction,
        name: collections.Name,
        key: []const u8,
        value: []const u8,
        source: collections.Source,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.collection_variables.set(name, key, value, source);
    }

    pub fn addTransactionCollectionValue(self: *Transaction, name: []const u8, delta: i64) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const current = if (self.collection_variables.first(.tx, name)) |value|
            persistent.parseNumericOrZero(value.value)
        else
            0;
        const next = std.math.add(i64, current, delta) catch return error.CapacityExceeded;
        var value_buffer: [24]u8 = undefined;
        const value = std.fmt.bufPrint(&value_buffer, "{d}", .{next}) catch unreachable;
        try self.collection_variables.set(
            .tx,
            name,
            value,
            .{ .origin = .rule, .offset = 0, .length = value.len },
        );
    }

    pub fn initializePersistentCollection(
        self: *Transaction,
        namespace: persistent.Namespace,
        collection_key: []const u8,
    ) TransactionError!PersistentInitialization {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const availability = self.currentAvailability() orelse return error.InvalidLifecycle;
        if (@backingInt(availability) < @backingInt(variables.Availability.request_headers)) return error.InvalidLifecycle;
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        var snapshot = (session.initialize(namespace, collection_key, try self.persistentNow()) catch |err| {
            if (try self.handlePersistentFailure(err)) return .failed_open;
            return err;
        }) orelse return .already_initialized;
        defer snapshot.deinit();
        errdefer session.cancelInitialization(namespace);

        var batch: std.ArrayList(collections.Value) = .empty;
        defer batch.deinit(self.waf.allocator);
        try batch.ensureTotalCapacity(self.waf.allocator, snapshot.values.items.len);
        for (snapshot.values.items) |value| batch.appendAssumeCapacity(.{
            .collection = namespace.collectionName(),
            .key = value.name,
            .value = value.value,
            .source = .{ .origin = .persistent, .offset = 0, .length = value.value.len },
        });
        try self.collection_variables.addBatch(batch.items);
        return .loaded;
    }

    pub fn setPersistentCollectionValue(
        self: *Transaction,
        namespace: persistent.Namespace,
        name: []const u8,
        value: []const u8,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        try session.set(namespace, name, value, null);
        self.collection_variables.set(
            namespace.collectionName(),
            name,
            value,
            .{ .origin = .rule, .offset = 0, .length = value.len },
        ) catch |err| {
            session.discardLastMutation(namespace);
            return err;
        };
    }

    pub fn addPersistentCollectionValue(
        self: *Transaction,
        namespace: persistent.Namespace,
        name: []const u8,
        delta: i64,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        const current = if (self.collection_variables.first(namespace.collectionName(), name)) |value|
            persistent.parseNumericOrZero(value.value)
        else
            0;
        const next = std.math.add(i64, current, delta) catch return error.CapacityExceeded;
        var value_buffer: [24]u8 = undefined;
        const value = std.fmt.bufPrint(&value_buffer, "{d}", .{next}) catch unreachable;
        try session.add(namespace, name, delta);
        self.collection_variables.set(
            namespace.collectionName(),
            name,
            value,
            .{ .origin = .rule, .offset = 0, .length = value.len },
        ) catch |err| {
            session.discardLastMutation(namespace);
            return err;
        };
    }

    pub fn removePersistentCollectionValue(self: *Transaction, namespace: persistent.Namespace, name: []const u8) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        try session.remove(namespace, name);
        _ = try self.collection_variables.remove(namespace.collectionName(), .{ .key = name });
    }

    pub fn expirePersistentCollectionValue(
        self: *Transaction,
        namespace: persistent.Namespace,
        name: []const u8,
        ttl_seconds: u32,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        const ttl_ns = std.math.mul(i64, @as(i64, ttl_seconds), std.time.ns_per_s) catch return error.PersistentTimestampOverflow;
        const expires_at_ns = std.math.add(i64, try self.persistentNow(), ttl_ns) catch return error.PersistentTimestampOverflow;
        try session.expire(namespace, name, expires_at_ns);
    }

    pub fn flushPersistentCollections(self: *Transaction) TransactionError!usize {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const session = &(self.persistent_session orelse return 0);
        return session.flush(try self.persistentNow()) catch |err| {
            if (try self.handlePersistentFailure(err)) return 0;
            return err;
        };
    }

    pub fn lastPersistentFailure(self: *const Transaction) ?PersistentFailure {
        return self.last_persistent_failure;
    }

    pub fn removeCollectionValues(self: *Transaction, name: collections.Name, selector: collections.Selector) TransactionError!usize {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        return try self.collection_variables.remove(name, selector);
    }

    pub fn expandMacro(
        self: *Transaction,
        compiled: *const macros.Compiled,
        allocator: std.mem.Allocator,
    ) TransactionError![]u8 {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.updateDuration();
        return compiled.expand(allocator, .{
            .context = self,
            .scalarFn = resolveMacroScalar,
            .collectionFn = resolveMacroCollection,
        }, self.waf.config.macro_missing_policy) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.MacroOutputTooLarge => return error.MacroOutputTooLarge,
        };
    }

    pub fn setIdentity(self: *Transaction, remote_user: []const u8, user_id: []const u8) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.setScalar(.remote_user, remote_user, .connector, .request_headers);
        try self.setScalar(.user_id, user_id, .connector, .request_headers);
    }

    pub fn setServerName(self: *Transaction, server_name: []const u8) TransactionError!void {
        try self.requireBeforeRequestHeaders();
        try self.setScalar(.server_name, server_name, .connector, .request_headers);
    }

    pub fn setCompatibilityIdentity(
        self: *Transaction,
        session_id: []const u8,
        webapp_id: []const u8,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.setScalar(.session_id, session_id, .connector, .request_headers);
        try self.setScalar(.webapp_id, webapp_id, .connector, .request_headers);
    }

    pub fn recordRequestBodyError(self: *Transaction, processor: []const u8, message: []const u8) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body_writing });
        if (processor.len != 0) try self.setScalar(.reqbody_processor, processor, .parser, .request_body);
        try self.setScalar(.reqbody_error, "1", .parser, .request_body);
        try self.setScalar(.reqbody_error_msg, message, .parser, .request_body);
        try self.setScalar(.reqbody_processor_error, "1", .parser, .request_body);
        try self.setScalar(.reqbody_processor_error_msg, message, .parser, .request_body);
    }

    pub fn recordResponseBodyError(self: *Transaction, processor: []const u8, message: []const u8) TransactionError!void {
        try self.requireAny(&.{ .response_headers, .response_body_writing });
        if (processor.len != 0) try self.setScalar(.res_body_processor, processor, .parser, .response_body);
        try self.setScalar(.res_body_error, "1", .parser, .response_body);
        try self.setScalar(.res_body_error_msg, message, .parser, .response_body);
        try self.setScalar(.res_body_processor_error, "1", .parser, .response_body);
        try self.setScalar(.res_body_processor_error_msg, message, .parser, .response_body);
    }

    pub fn recordRegexError(self: *Transaction, limits_exceeded: bool) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.setScalar(.msc_pcre_error, "1", .compatibility, .request_headers);
        if (limits_exceeded) try self.setScalar(.msc_pcre_limits_exceeded, "1", .compatibility, .request_headers);
    }

    pub fn recordMatch(self: *Transaction, name: []const u8, value: []const u8, severity: u8) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.collection_variables.addPair(
            .{ .collection = .matched_vars, .key = name, .value = value, .source = .{ .origin = .rule, .offset = 0, .length = value.len } },
            .{ .collection = .matched_vars_names, .key = name, .value = name, .source = .{ .origin = .rule, .offset = 0, .length = name.len } },
        );
        try self.setScalar(.matched_var_name, name, .rule, .request_headers);
        try self.setScalar(.matched_var, value, .rule, .request_headers);
        if (severity < self.highest_severity) {
            self.highest_severity = severity;
            try self.setScalarUnsigned(.highest_severity, severity, .rule, .request_headers);
        }
    }

    pub fn deinit(self: *Transaction) void {
        if (self.lifecycle == .deinitialized) return;
        if (self.persistent_session) |*session| session.deinit();
        self.scalar_variables.deinit();
        self.collection_variables.deinit();
        self.lifecycle = .deinitialized;
        _ = @constCast(&self.waf.active_transactions).fetchSub(1, .release);
    }

    fn validateHeader(
        self: *Transaction,
        name: []const u8,
        value: []const u8,
        count: usize,
        bytes: usize,
    ) TransactionError!usize {
        if (!validToken(name) or containsLineBreak(value)) return error.InvalidHeader;
        if (count == self.waf.config.limits.max_header_count) return error.TooManyHeaders;
        const added = name.len + value.len;
        if (added > self.waf.config.limits.max_header_bytes - bytes) return error.HeadersTooLarge;
        return added;
    }

    fn require(self: *const Transaction, expected: Lifecycle) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (self.transaction_terminated) return error.TransactionTerminated;
        if (self.lifecycle != expected) return error.InvalidLifecycle;
    }

    fn requireAny(self: *const Transaction, expected: []const Lifecycle) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (self.transaction_terminated) return error.TransactionTerminated;
        for (expected) |candidate| if (self.lifecycle == candidate) return;
        return error.InvalidLifecycle;
    }

    fn currentAvailability(self: *const Transaction) ?variables.Availability {
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

    fn initializeCompatibilityScalars(self: *Transaction) TransactionError!void {
        if (self.started_real_nanoseconds < 0) return error.ClockBeforeUnixEpoch;
        try self.setScalar(.remote_host, (self.scalar_variables.get(.remote_addr, .connection) orelse unreachable).value, .compatibility, .connection);
        try self.setScalar(.modsec_build, "zig-waf/0.0.0-dev", .compatibility, .request_headers);
        try self.setScalar(.msc_pcre_error, "0", .compatibility, .request_headers);
        try self.setScalar(.msc_pcre_limits_exceeded, "0", .compatibility, .request_headers);
        try self.setScalar(.urlencoded_error, "0", .parser, .request_headers);
        try self.setScalar(.highest_severity, "255", .rule, .request_headers);
        try self.setScalar(.duration, "0", .timing, .request_headers);

        var id_buffer: [64]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buffer, "zigwaf-{x}-{x}", .{ self.started_real_nanoseconds, self.sequence }) catch unreachable;
        try self.setScalar(.unique_id, id, .engine, .request_headers);
        try self.setTimeScalars();
    }

    fn setTimeScalars(self: *Transaction) TransactionError!void {
        const seconds: u64 = @intCast(@divFloor(self.started_real_nanoseconds, std.time.ns_per_s));
        const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = seconds };
        const day_seconds = epoch_seconds.getDaySeconds();
        const year_day = epoch_seconds.getEpochDay().calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const hour = day_seconds.getHoursIntoDay();
        const minute = day_seconds.getMinutesIntoHour();
        const second = day_seconds.getSecondsIntoMinute();
        var time_buffer: [8]u8 = undefined;
        const formatted_time = std.fmt.bufPrint(&time_buffer, "{d:0>2}:{d:0>2}:{d:0>2}", .{ hour, minute, second }) catch unreachable;
        try self.setScalar(.time, formatted_time, .timing, .request_headers);
        try self.setScalarUnsigned(.time_day, @as(u8, month_day.day_index) + 1, .timing, .request_headers);
        try self.setScalarUnsigned(.time_epoch, seconds, .timing, .request_headers);
        try self.setScalarUnsigned(.time_hour, hour, .timing, .request_headers);
        try self.setScalarUnsigned(.time_min, minute, .timing, .request_headers);
        try self.setScalarUnsigned(.time_mon, month_day.month.numeric(), .timing, .request_headers);
        try self.setScalarUnsigned(.time_sec, second, .timing, .request_headers);
        // POSIX/Go convention: Sunday=0. 1970-01-01 was Thursday (4).
        try self.setScalarUnsigned(.time_wday, (epoch_seconds.getEpochDay().day + 4) % 7, .timing, .request_headers);
        try self.setScalarUnsigned(.time_year, year_day.year, .timing, .request_headers);
    }

    fn updateDuration(self: *Transaction) TransactionError!void {
        const now = self.waf.now();
        const elapsed = @max(@as(i96, 0), now.awake_nanoseconds - self.started_awake_nanoseconds);
        try self.setScalarUnsigned(.duration, @divTrunc(elapsed, std.time.ns_per_ms), .timing, .request_headers);
    }

    fn persistentNow(self: *const Transaction) TransactionError!i64 {
        const now = self.waf.now().unix_nanoseconds;
        if (now < 0 or now > std.math.maxInt(i64)) return error.PersistentTimestampOverflow;
        return @intCast(now);
    }

    fn handlePersistentFailure(self: *Transaction, err: persistent.SessionError) TransactionError!bool {
        const failure: PersistentFailure = switch (err) {
            error.Unavailable => .unavailable,
            error.Timeout => .timeout,
            error.RetryLimitExceeded, error.Conflict => .conflict_exhausted,
            error.CorruptData => .corrupt_data,
            error.CapacityExceeded => .capacity_exceeded,
            else => return err,
        };
        self.last_persistent_failure = failure;
        return self.waf.config.persistent_failure_policy == .fail_open;
    }

    fn setFlagIfMissing(
        self: *Transaction,
        name: variables.Name,
        value: bool,
        origin: variables.Origin,
        available_from: variables.Availability,
    ) TransactionError!void {
        if (self.scalar_variables.get(name, available_from) == null) {
            try self.setScalar(name, if (value) "1" else "0", origin, available_from);
        }
    }

    fn requireBeforeRequestHeaders(self: *const Transaction) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (self.lifecycle != .created and self.lifecycle != .connection and self.lifecycle != .uri) return error.InvalidLifecycle;
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

fn lock(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

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

fn startsWithIgnoreCase(value: []const u8, prefix: []const u8) bool {
    return value.len >= prefix.len and std.ascii.eqlIgnoreCase(value[0..prefix.len], prefix);
}

fn hostWithoutPort(value: []const u8) []const u8 {
    if (value.len == 0) return value;
    if (value[0] == '[') {
        const close = std.mem.indexOfScalar(u8, value, ']') orelse return value;
        return value[1..close];
    }
    const first_colon = std.mem.indexOfScalar(u8, value, ':') orelse return value;
    if (std.mem.indexOfScalarPos(u8, value, first_colon + 1, ':') != null) return value;
    return value[0..first_colon];
}

fn resolveMacroScalar(context: *anyopaque, name: variables.Name) ?[]const u8 {
    const transaction: *Transaction = @ptrCast(@alignCast(context));
    const availability = transaction.currentAvailability() orelse return null;
    return (transaction.scalar_variables.get(name, availability) orelse return null).value;
}

fn resolveMacroCollection(context: *anyopaque, name: collections.Name, key: ?[]const u8) ?[]const u8 {
    const transaction: *Transaction = @ptrCast(@alignCast(context));
    const availability = transaction.currentAvailability() orelse return null;
    if (@backingInt(availability) < @backingInt(name.minimumAvailability())) return null;
    const found = if (key) |selected_key|
        transaction.collection_variables.first(name, selected_key)
    else
        transaction.collection_variables.firstAny(name);
    return (found orelse return null).value;
}

const ReloadWorker = struct {
    runtime: *Runtime,
    pinned: *std.atomic.Value(usize),
    release: *std.atomic.Value(bool),
    failures: *std.atomic.Value(usize),

    fn run(self: *ReloadWorker) void {
        var pinned_tx = self.runtime.newTransaction() catch {
            _ = self.failures.fetchAdd(1, .monotonic);
            return;
        };
        _ = self.pinned.fetchAdd(1, .release);
        while (!self.release.load(.acquire)) std.atomic.spinLoopHint();
        pinned_tx.deinit();

        for (0..500) |_| {
            var tx = self.runtime.newTransaction() catch {
                _ = self.failures.fetchAdd(1, .monotonic);
                return;
            };
            tx.deinit();
        }
    }
};

const TestClock = struct {
    unix_nanoseconds: i96,
    awake_nanoseconds: i96,

    fn now(context: *anyopaque) ClockSample {
        const self: *TestClock = @ptrCast(@alignCast(context));
        return .{
            .unix_nanoseconds = self.unix_nanoseconds,
            .awake_nanoseconds = self.awake_nanoseconds,
        };
    }
};

const UnavailablePersistence = struct {
    context: u8 = 0,

    fn backend(self: *UnavailablePersistence) persistent.Backend {
        return .{
            .context = &self.context,
            .loadFn = load,
            .commitFn = commit,
            .cleanupFn = cleanup,
        };
    }

    fn load(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: persistent.Namespace,
        _: []const u8,
        _: i64,
        _: persistent.Limits,
    ) persistent.BackendError!persistent.Snapshot {
        return error.Unavailable;
    }

    fn commit(_: *anyopaque, _: persistent.CommitRequest) persistent.BackendError!u64 {
        return error.Unavailable;
    }

    fn cleanup(_: *anyopaque, _: i64, _: persistent.CleanupBudget) persistent.BackendError!persistent.CleanupResult {
        return error.Unavailable;
    }
};

test "executes the complete connector lifecycle" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();

    var tx = waf.newTransaction();
    try tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try std.testing.expect(tx.currentPhase() == null);
    try tx.processUri("/login", "POST", "HTTP/1.1");
    try std.testing.expectEqual(Phase.request_headers, tx.currentPhase().?);
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

test "uses the five stable SecLang phase numbers" {
    try std.testing.expectEqual(@as(u8, 1), @backingInt(Phase.request_headers));
    try std.testing.expectEqual(@as(u8, 2), @backingInt(Phase.request_body));
    try std.testing.expectEqual(@as(u8, 3), @backingInt(Phase.response_headers));
    try std.testing.expectEqual(@as(u8, 4), @backingInt(Phase.response_body));
    try std.testing.expectEqual(@as(u8, 5), @backingInt(Phase.logging));
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

    try tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    try tx.recordIntervention(.deny, 403, 941100);
    const pending = (try tx.intervention()).?;
    try std.testing.expectEqual(Intervention.Action.deny, pending.action);
    try std.testing.expect(!pending.enforced);
    try std.testing.expect(!tx.isPhaseInterrupted());
    try std.testing.expect(!tx.isTerminated());
}

test "enabled interventions interrupt a phase and logging finalizes once" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    try tx.recordIntervention(.deny, 403, 1001);
    try std.testing.expect(tx.isPhaseInterrupted());
    try std.testing.expect(!tx.isTerminated());
    try std.testing.expectError(error.InterventionAlreadyRecorded, tx.recordIntervention(.deny, 404, 1002));

    try tx.processResponseHeaders(403, "HTTP/1.1");
    try std.testing.expect(!tx.isPhaseInterrupted());
    try tx.processLogging();
    try std.testing.expect(tx.isLoggingFinalized());
    try std.testing.expectError(error.InvalidLifecycle, tx.processLogging());
}

test "drop terminates inspection but still permits logging finalization" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    try tx.recordIntervention(.drop, 403, 1001);
    try std.testing.expect(tx.isTerminated());
    try std.testing.expectError(error.TransactionTerminated, tx.processResponseHeaders(403, "HTTP/1.1"));
    try tx.processLogging();
    try std.testing.expect(tx.isLoggingFinalized());
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

test "populates timing and compatibility scalars from an injectable clock" {
    var clock: TestClock = .{ .unix_nanoseconds = 0, .awake_nanoseconds = 1_000_000 };
    var builder = Builder.init(std.testing.allocator);
    builder.setClockSource(.{ .context = &clock, .nowFn = TestClock.now });
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try std.testing.expect((try tx.scalar(.time_epoch)) == null);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectEqualStrings("0", (try tx.scalar(.time_epoch)).?.value);
    try std.testing.expectEqualStrings("00:00:00", (try tx.scalar(.time)).?.value);
    try std.testing.expectEqualStrings("1", (try tx.scalar(.time_day)).?.value);
    try std.testing.expectEqualStrings("1", (try tx.scalar(.time_mon)).?.value);
    try std.testing.expectEqualStrings("1970", (try tx.scalar(.time_year)).?.value);
    try std.testing.expectEqualStrings("4", (try tx.scalar(.time_wday)).?.value);
    try std.testing.expectEqualStrings("255", (try tx.scalar(.highest_severity)).?.value);
    try std.testing.expectEqualStrings("0", (try tx.scalar(.msc_pcre_error)).?.value);
    try std.testing.expect(std.mem.startsWith(u8, (try tx.scalar(.unique_id)).?.value, "zigwaf-"));

    clock.awake_nanoseconds += 12 * std.time.ns_per_ms + 999;
    try std.testing.expectEqualStrings("12", (try tx.scalar(.duration)).?.value);
}

test "derives header, identity, match, body error, and response scalars" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("192.0.2.1", 1234, "2001:db8::1", 443);
    try tx.processUri("/submit?q=1", "POST", "HTTP/1.1");
    try tx.setIdentity("alice", "user-7");
    try tx.setCompatibilityIdentity("session-8", "shop");
    try tx.addRequestHeader("Host", "[2001:db8::2]:8443");
    try tx.addRequestHeader("Authorization", "Bearer token");
    try tx.addRequestHeader("Content-Type", "application/json; charset=utf-8");
    try tx.processRequestHeaders();
    try std.testing.expectEqualStrings("2001:db8::2", (try tx.scalar(.server_name)).?.value);
    try std.testing.expectEqualStrings("Bearer", (try tx.scalar(.auth_type)).?.value);
    try std.testing.expectEqualStrings("JSON", (try tx.scalar(.reqbody_processor)).?.value);
    try std.testing.expectEqualStrings("alice", (try tx.scalar(.remote_user)).?.value);
    try std.testing.expectEqualStrings("session-8", (try tx.scalar(.session_id)).?.value);

    try tx.recordMatch("ARGS:q", "attack", 4);
    try tx.recordMatch("REQUEST_URI", "/submit", 7);
    try std.testing.expectEqualStrings("4", (try tx.scalar(.highest_severity)).?.value);
    try tx.recordMatch("REQUEST_URI", "/submit", 1);
    try std.testing.expectEqualStrings("1", (try tx.scalar(.highest_severity)).?.value);
    try std.testing.expectEqualStrings("REQUEST_URI", (try tx.scalar(.matched_var_name)).?.value);

    try tx.writeRequestBody("invalid");
    try tx.recordRequestBodyError("JSON", "unexpected token");
    try tx.processRequestBody();
    try std.testing.expectEqualStrings("1", (try tx.scalar(.reqbody_error)).?.value);
    try std.testing.expectEqualStrings("unexpected token", (try tx.scalar(.reqbody_processor_error_msg)).?.value);
    try std.testing.expectEqualStrings("0", (try tx.scalar(.inbound_data_error)).?.value);

    try tx.addResponseHeader("Content-Type", "application/problem+json");
    try tx.processResponseHeaders(422, "HTTP/1.1");
    try std.testing.expectEqualStrings("application/problem+json", (try tx.scalar(.response_content_type)).?.value);
    try std.testing.expectEqualStrings("HTTP/1.1 422", (try tx.scalar(.status_line)).?.value);
    try tx.writeResponseBody("problem");
    try tx.recordResponseBodyError("JSON", "invalid response");
    try tx.processResponseBody();
    try std.testing.expectEqualStrings("7", (try tx.scalar(.response_content_length)).?.value);
    try std.testing.expectEqualStrings("1", (try tx.scalar(.res_body_error)).?.value);
    try std.testing.expectEqualStrings("0", (try tx.scalar(.outbound_data_error)).?.value);
}

test "publishes repeated header collections with phase gates and origins" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    var first_value = [_]u8{ 'o', 'n', 'e' };
    try tx.addRequestHeader("X-Test", &first_value);
    first_value[0] = 'x';
    try tx.addRequestHeader("x-test", "two");
    var headers = (try tx.collection(.request_headers, .{ .key = "X-TEST" })).?;
    const first = (try headers.next()).?;
    try std.testing.expectEqualStrings("one", first.value);
    try std.testing.expectEqual(variables.Origin.request_header, first.source.origin);
    try std.testing.expectEqualStrings("two", (try headers.next()).?.value);
    try std.testing.expect(try headers.next() == null);
    try std.testing.expect((try tx.collection(.response_headers, .all)) == null);

    var names = (try tx.collection(.request_headers_names, .all)).?;
    try std.testing.expectEqualStrings("X-Test", (try names.next()).?.value);
    try std.testing.expectEqualStrings("x-test", (try names.next()).?.value);

    try tx.processRequestHeaders();
    try tx.addResponseHeader("Content-Type", "text/plain");
    try std.testing.expect((try tx.collection(.response_headers, .all)) == null);
    try tx.processResponseHeaders(200, "HTTP/1.1");
    try std.testing.expectEqualStrings("text/plain", (try tx.collectionFirst(.response_headers, "content-type")).?.value);
}

test "transaction macros resolve current scalar and collection state" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/orders", "GET", "HTTP/1.1");
    try tx.addCollectionValue(.tx, "tenant", "north", .{ .origin = .rule, .offset = 0, .length = 5 });
    var compiled = try macros.Compiled.compile(std.testing.allocator, "%{REQUEST_METHOD} %{TX.tenant} %{RESPONSE_STATUS}", .{});
    defer compiled.deinit();
    const expanded = try tx.expandMacro(&compiled, std.testing.allocator);
    defer std.testing.allocator.free(expanded);
    try std.testing.expectEqualStrings("GET north ", expanded);
}

test "transaction collection targets apply exclusions, counts, replacement, and removal" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.addRequestHeader("X-One", "1");
    try tx.addRequestHeader("Authorization", "secret");

    const target: collections.Target = .{ .collection = .request_headers, .count_only = true };
    const exclusions = [_]collections.Target{.{ .collection = .request_headers, .selector = .{ .key = "authorization" } }};
    try std.testing.expectEqual(@as(usize, 1), (try tx.collectionCount(target, &exclusions)).?);

    const source: collections.Source = .{ .origin = .rule, .offset = 0, .length = 1 };
    try tx.setCollectionValue(.tx, "score", "1", source);
    try tx.setCollectionValue(.tx, "SCORE", "2", source);
    try std.testing.expectEqualStrings("2", (try tx.collectionFirst(.tx, "score")).?.value);
    try std.testing.expectEqual(@as(usize, 1), try tx.removeCollectionValues(.tx, .{ .key = "score" }));
    try std.testing.expect((try tx.collectionFirst(.tx, "score")) == null);
}

test "WAF configuration selects macro missing-value compatibility" {
    var builder = Builder.init(std.testing.allocator);
    builder.setMacroMissingPolicy(.expression);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    var compiled = try macros.Compiled.compile(std.testing.allocator, "x=%{TX.missing}", .{});
    defer compiled.deinit();
    const expanded = try tx.expandMacro(&compiled, std.testing.allocator);
    defer std.testing.allocator.free(expanded);
    try std.testing.expectEqualStrings("x=TX.missing", expanded);
}

test "argument cookie and file producers maintain derived collections and sizes" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/", "POST", "HTTP/1.1");

    const query_source: collections.Source = .{ .origin = .request_target, .offset = 3, .length = 5 };
    try tx.addArgument(.query, "q", "zig", query_source);
    try tx.addRequestCookie("Session", "abc", .{ .origin = .request_header, .offset = 20, .length = 3 });
    try std.testing.expectEqualStrings("zig", (try tx.collectionFirst(.args_get, "q")).?.value);
    try std.testing.expectEqualStrings("zig", (try tx.collectionFirst(.args, "q")).?.value);
    try std.testing.expectEqualStrings("q", (try tx.collectionFirst(.args_names, "q")).?.value);
    try std.testing.expectEqualStrings("4", (try tx.scalar(.args_combined_size)).?.value);
    try std.testing.expect((try tx.collectionFirst(.request_cookies, "session")) == null);
    try std.testing.expectEqualStrings("abc", (try tx.collectionFirst(.request_cookies, "Session")).?.value);

    try tx.processRequestHeaders();
    try tx.addArgument(.body, "name", "alice", .{ .origin = .request_body, .offset = 0, .length = 5 });
    try tx.addFileMetadata("avatar", "me.png", "/tmp/upload-1", 42, .{ .origin = .request_body, .offset = 10, .length = 42 });
    try tx.processRequestBody();
    try std.testing.expectEqualStrings("alice", (try tx.collectionFirst(.args_post, "name")).?.value);
    try std.testing.expectEqualStrings("13", (try tx.scalar(.args_combined_size)).?.value);
    try std.testing.expectEqualStrings("42", (try tx.scalar(.files_combined_size)).?.value);
    try std.testing.expectEqualStrings("me.png", (try tx.collectionFirst(.files_names, "avatar")).?.value);
    try std.testing.expectEqualStrings("/tmp/upload-1", (try tx.collectionFirst(.files_tmp_names, "avatar")).?.value);
}

test "engine initializes mutates flushes and expires persistent collections" {
    var memory = persistent.InMemoryBackend.init(std.testing.allocator);
    defer memory.deinit();
    var clock: TestClock = .{ .unix_nanoseconds = 5 * std.time.ns_per_s, .awake_nanoseconds = 0 };
    var builder = Builder.init(std.testing.allocator);
    builder.setPersistentBackend(memory.backend());
    builder.setClockSource(.{ .context = &clock, .nowFn = TestClock.now });
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;

    var first = waf.newTransaction();
    try first.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try first.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectEqual(PersistentInitialization.loaded, try first.initializePersistentCollection(.ip, "192.0.2.20"));
    try std.testing.expectEqual(PersistentInitialization.already_initialized, try first.initializePersistentCollection(.ip, "192.0.2.20"));
    try first.setPersistentCollectionValue(.ip, "score", "not-a-number");
    try first.addPersistentCollectionValue(.ip, "score", 2);
    try first.expirePersistentCollectionValue(.ip, "score", 1);
    try std.testing.expectEqualStrings("2", (try first.collectionFirst(.ip, "SCORE")).?.value);
    try first.processLogging();
    first.deinit();

    var second = waf.newTransaction();
    try second.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try second.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectEqual(PersistentInitialization.loaded, try second.initializePersistentCollection(.ip, "192.0.2.20"));
    try std.testing.expectEqualStrings("2", (try second.collectionFirst(.ip, "score")).?.value);
    second.deinit();

    clock.unix_nanoseconds += std.time.ns_per_s;
    var expired = waf.newTransaction();
    try expired.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try expired.processUri("/", "GET", "HTTP/1.1");
    _ = try expired.initializePersistentCollection(.ip, "192.0.2.20");
    try std.testing.expect((try expired.collectionFirst(.ip, "score")) == null);
    expired.deinit();
}

test "persistent engine APIs reject absent backend explicitly" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectError(error.PersistentBackendNotConfigured, tx.initializePersistentCollection(.ip, "192.0.2.20"));
}

test "persistent backend failure policy is explicit and observable" {
    var unavailable: UnavailablePersistence = .{};
    var open_builder = Builder.init(std.testing.allocator);
    open_builder.setPersistentBackend(unavailable.backend());
    open_builder.setPersistentFailurePolicy(.fail_open);
    const open_waf = try open_builder.build();
    defer open_waf.deinit() catch unreachable;
    var open_tx = open_waf.newTransaction();
    defer open_tx.deinit();
    try open_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try open_tx.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectEqual(PersistentInitialization.failed_open, try open_tx.initializePersistentCollection(.ip, "192.0.2.20"));
    try std.testing.expectEqual(PersistentFailure.unavailable, open_tx.lastPersistentFailure().?);

    var closed_builder = Builder.init(std.testing.allocator);
    closed_builder.setPersistentBackend(unavailable.backend());
    closed_builder.setPersistentFailurePolicy(.fail_closed);
    const closed_waf = try closed_builder.build();
    defer closed_waf.deinit() catch unreachable;
    var closed_tx = closed_waf.newTransaction();
    defer closed_tx.deinit();
    try closed_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try closed_tx.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectError(error.Unavailable, closed_tx.initializePersistentCollection(.ip, "192.0.2.20"));
    try std.testing.expectEqual(PersistentFailure.unavailable, closed_tx.lastPersistentFailure().?);
}

test "TX numeric mutation follows setvar prefix and overflow semantics" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    const source: collections.Source = .{ .origin = .rule, .offset = 0, .length = 0 };
    try tx.setCollectionValue(.tx, "score", "  -2tail", source);
    try tx.addTransactionCollectionValue("SCORE", 5);
    try std.testing.expectEqualStrings("3", (try tx.collectionFirst(.tx, "score")).?.value);
    try tx.setCollectionValue(.tx, "bad", "not-numeric", source);
    try tx.addTransactionCollectionValue("bad", 4);
    try std.testing.expectEqualStrings("4", (try tx.collectionFirst(.tx, "bad")).?.value);
    try tx.setCollectionValue(.tx, "maximum", "9223372036854775807", source);
    try std.testing.expectError(error.CapacityExceeded, tx.addTransactionCollectionValue("maximum", 1));
    try std.testing.expectEqualStrings("9223372036854775807", (try tx.collectionFirst(.tx, "maximum")).?.value);
}

test "compiled feature discovery is explicit" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    const compiled = waf.features();
    try std.testing.expect(compiled.has(.transaction_lifecycle));
    try std.testing.expect(compiled.has(.scalar_variables));
    try std.testing.expect(compiled.has(.atomic_hot_reload));
}

test "hot reload pins requests to retired generations until drain" {
    var initial_builder = Builder.init(std.testing.allocator);
    const runtime = try initial_builder.buildRuntime();

    var old_tx = try runtime.newTransaction();
    try old_tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try old_tx.processUri("/", "GET", "HTTP/1.1");
    try old_tx.processRequestHeaders();
    try old_tx.recordIntervention(.deny, 403, 1);
    try std.testing.expect((try old_tx.intervention()).?.enforced);

    var replacement_builder = Builder.init(std.testing.allocator);
    replacement_builder.setMode(.detection_only);
    const replacement = try replacement_builder.build();
    var retired = try runtime.reload(replacement);
    try std.testing.expectEqual(@as(usize, 1), retired.activeTransactionCount());
    try std.testing.expectError(error.TransactionsActive, retired.tryReclaim());

    var new_tx = try runtime.newTransaction();
    try new_tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try new_tx.processUri("/", "GET", "HTTP/1.1");
    try new_tx.processRequestHeaders();
    try new_tx.recordIntervention(.deny, 403, 2);
    try std.testing.expect(!(try new_tx.intervention()).?.enforced);
    old_tx.deinit();
    try retired.tryReclaim();
    try std.testing.expect(retired.isReclaimed());

    try std.testing.expectError(error.TransactionsActive, runtime.deinit());
    new_tx.deinit();
    try runtime.deinit();
}

test "runtime rejects ambiguous generation ownership" {
    var builder = Builder.init(std.testing.allocator);
    const initial = try builder.build();
    const runtime = try Runtime.init(std.testing.allocator, initial);
    defer runtime.deinit() catch unreachable;

    try std.testing.expectError(error.SameGeneration, runtime.reload(initial));

    const in_use = try builder.build();
    var tx = in_use.newTransaction();
    try std.testing.expectError(error.GenerationInUse, runtime.reload(in_use));
    tx.deinit();
    try in_use.deinit();
}

test "concurrent request pinning is safe across reload" {
    var builder = Builder.init(std.testing.allocator);
    const runtime = try builder.buildRuntime();
    const replacement = try builder.build();

    var pinned = std.atomic.Value(usize).init(0);
    var release = std.atomic.Value(bool).init(false);
    var failures = std.atomic.Value(usize).init(0);
    var workers: [4]ReloadWorker = undefined;
    var threads: [workers.len]std.Thread = undefined;
    for (&workers, &threads) |*worker, *thread| {
        worker.* = .{
            .runtime = runtime,
            .pinned = &pinned,
            .release = &release,
            .failures = &failures,
        };
        thread.* = try std.Thread.spawn(.{}, ReloadWorker.run, .{worker});
    }

    while (pinned.load(.acquire) != workers.len) std.atomic.spinLoopHint();
    var retired = try runtime.reload(replacement);
    try std.testing.expectEqual(workers.len, retired.activeTransactionCount());
    release.store(true, .release);
    for (&threads) |*thread| thread.join();

    try std.testing.expectEqual(@as(usize, 0), failures.load(.acquire));
    try retired.tryReclaim();
    try runtime.deinit();
}
