const std = @import("std");
const waf = @import("waf");

pub const abi_version: u32 = 0x0001_0000;

const Status = enum(c_int) {
    ok = 0,
    invalid_argument = 1,
    unsupported_abi = 2,
    out_of_memory = 3,
    invalid_config = 4,
    invalid_lifecycle = 5,
    limit_exceeded = 6,
    busy = 7,
    not_found = 8,
    internal = 255,
};

const WafHandle = opaque {};
const TransactionHandle = opaque {};

const Config = extern struct {
    struct_size: u32,
    abi_version: u32,
    mode: u32,
    reserved0: u32,
    max_request_target_bytes: usize,
    max_header_count: usize,
    max_header_bytes: usize,
    max_request_body_bytes: usize,
    max_response_body_bytes: usize,
    reserved: [8]u64,
};

const Features = extern struct {
    struct_size: u32,
    abi_version: u32,
    feature_bits: u64,
    highest_phase: u32,
    reserved0: u32,
    reserved: [4]u64,
};

const CIntervention = extern struct {
    struct_size: u32,
    abi_version: u32,
    action: u32,
    status: u16,
    enforced: u8,
    has_rule_id: u8,
    rule_id: u32,
    reserved: [4]u64,
};

const feature_bits: u64 = waf.FeatureSet.allCompiled().bits;

export fn zig_waf_abi_version() callconv(.c) u32 {
    return abi_version;
}

export fn zig_waf_query_features(out_features: ?*Features) callconv(.c) Status {
    const output = out_features orelse return .invalid_argument;
    if (output.struct_size < @sizeOf(Features)) return .invalid_argument;
    if (output.abi_version != abi_version) return .unsupported_abi;
    output.feature_bits = feature_bits;
    output.highest_phase = @backingInt(waf.Phase.logging);
    output.reserved0 = 0;
    output.reserved = @splat(0);
    return .ok;
}

/// Apply a caller-supplied Config to a builder; returns a non-ok Status on a
/// malformed struct, ABI mismatch, or invalid mode.
fn configureBuilder(builder: *waf.Waf.Builder, config: ?*const Config) Status {
    const input = config orelse return .ok;
    if (input.struct_size < @sizeOf(Config)) return .invalid_argument;
    if (input.abi_version != abi_version) return .unsupported_abi;
    builder.setMode(switch (input.mode) {
        0 => .enabled,
        1 => .detection_only,
        else => return .invalid_config,
    });
    builder.setLimits(.{
        .max_request_target_bytes = input.max_request_target_bytes,
        .max_header_count = input.max_header_count,
        .max_header_bytes = input.max_header_bytes,
        .max_request_body_bytes = input.max_request_body_bytes,
        .max_response_body_bytes = input.max_response_body_bytes,
    });
    return .ok;
}

export fn zig_waf_create(config: ?*const Config, out_waf: ?**WafHandle) callconv(.c) Status {
    const output = out_waf orelse return .invalid_argument;
    output.* = undefined;

    var builder = waf.Waf.Builder.init(std.heap.page_allocator);
    const configured = configureBuilder(&builder, config);
    if (configured != .ok) return configured;
    const instance = builder.build() catch |err| return mapError(err);
    output.* = @ptrCast(instance);
    return .ok;
}

/// Create a WAF whose rule set is compiled from a SecLang configuration. On a
/// parse or compile error the call fails with invalid_config; the caller can
/// use the CLI (`zig-waf validate`) to see the diagnostics.
export fn zig_waf_create_with_rules(
    config: ?*const Config,
    rules_pointer: ?[*]const u8,
    rules_len: usize,
    out_waf: ?**WafHandle,
) callconv(.c) Status {
    const output = out_waf orelse return .invalid_argument;
    output.* = undefined;
    const rules = bytes(rules_pointer, rules_len) orelse return .invalid_argument;
    const gpa = std.heap.page_allocator;

    var parsed = waf.seclang.parser.parseBytesOutcome(gpa, "c-abi-rules", rules, .{}, .{}) catch return .out_of_memory;
    defer parsed.deinit();
    const document = switch (parsed.outcome) {
        .document => |value| value,
        .diagnostic => return .invalid_config,
    };
    var documents = [_]waf.seclang.parser.Document{document};
    const plan = waf.plan.compile(gpa, &parsed.registry, &documents, .{}) catch return .invalid_config;
    defer plan.deinit();

    var builder = waf.Waf.Builder.init(gpa);
    const configured = configureBuilder(&builder, config);
    if (configured != .ok) return configured;
    builder.setRetainedPlan(plan);
    const instance = builder.build() catch |err| return mapError(err);
    output.* = @ptrCast(instance);
    return .ok;
}

export fn zig_waf_destroy(handle: ?*WafHandle) callconv(.c) Status {
    const instance = wafFromHandle(handle orelse return .invalid_argument);
    instance.deinit() catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_create(
    handle: ?*WafHandle,
    out_transaction: ?**TransactionHandle,
) callconv(.c) Status {
    const instance = wafFromHandle(handle orelse return .invalid_argument);
    const output = out_transaction orelse return .invalid_argument;
    output.* = undefined;
    const transaction = std.heap.page_allocator.create(waf.Transaction) catch return .out_of_memory;
    transaction.* = instance.newTransaction();
    output.* = @ptrCast(transaction);
    return .ok;
}

export fn zig_waf_transaction_destroy(handle: ?*TransactionHandle) callconv(.c) void {
    const transaction = transactionFromHandle(handle orelse return);
    transaction.deinit();
    std.heap.page_allocator.destroy(transaction);
}

export fn zig_waf_transaction_process_connection(
    handle: ?*TransactionHandle,
    client_address: ?[*]const u8,
    client_address_len: usize,
    client_port: u16,
    server_address: ?[*]const u8,
    server_address_len: usize,
    server_port: u16,
) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    const client = bytes(client_address, client_address_len) orelse return .invalid_argument;
    const server = bytes(server_address, server_address_len) orelse return .invalid_argument;
    transaction.processConnection(client, client_port, server, server_port) catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_process_uri(
    handle: ?*TransactionHandle,
    uri_pointer: ?[*]const u8,
    uri_len: usize,
    method_pointer: ?[*]const u8,
    method_len: usize,
    protocol_pointer: ?[*]const u8,
    protocol_len: usize,
) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    const uri = bytes(uri_pointer, uri_len) orelse return .invalid_argument;
    const method = bytes(method_pointer, method_len) orelse return .invalid_argument;
    const protocol = bytes(protocol_pointer, protocol_len) orelse return .invalid_argument;
    transaction.processUri(uri, method, protocol) catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_add_request_header(
    handle: ?*TransactionHandle,
    name_pointer: ?[*]const u8,
    name_len: usize,
    value_pointer: ?[*]const u8,
    value_len: usize,
) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    const name = bytes(name_pointer, name_len) orelse return .invalid_argument;
    const value = bytes(value_pointer, value_len) orelse return .invalid_argument;
    transaction.addRequestHeader(name, value) catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_process_request_headers(handle: ?*TransactionHandle) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    transaction.processRequestHeaders() catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_write_request_body(
    handle: ?*TransactionHandle,
    chunk_pointer: ?[*]const u8,
    chunk_len: usize,
) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    const chunk = bytes(chunk_pointer, chunk_len) orelse return .invalid_argument;
    transaction.writeRequestBody(chunk) catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_process_request_body(handle: ?*TransactionHandle) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    transaction.processRequestBody() catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_add_response_header(
    handle: ?*TransactionHandle,
    name_pointer: ?[*]const u8,
    name_len: usize,
    value_pointer: ?[*]const u8,
    value_len: usize,
) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    const name = bytes(name_pointer, name_len) orelse return .invalid_argument;
    const value = bytes(value_pointer, value_len) orelse return .invalid_argument;
    transaction.addResponseHeader(name, value) catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_process_response_headers(
    handle: ?*TransactionHandle,
    status: u16,
    protocol_pointer: ?[*]const u8,
    protocol_len: usize,
) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    const protocol = bytes(protocol_pointer, protocol_len) orelse return .invalid_argument;
    transaction.processResponseHeaders(status, protocol) catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_write_response_body(
    handle: ?*TransactionHandle,
    chunk_pointer: ?[*]const u8,
    chunk_len: usize,
) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    const chunk = bytes(chunk_pointer, chunk_len) orelse return .invalid_argument;
    transaction.writeResponseBody(chunk) catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_process_response_body(handle: ?*TransactionHandle) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    transaction.processResponseBody() catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_process_logging(handle: ?*TransactionHandle) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    transaction.processLogging() catch |err| return mapError(err);
    return .ok;
}

/// Autonomously evaluate every rule in `phase` (1=request headers … 5=logging)
/// against the current transaction state, applying matches. After this returns
/// OK, query zig_waf_transaction_intervention for the decision.
export fn zig_waf_transaction_evaluate_phase(handle: ?*TransactionHandle, phase: u32) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    if (phase < 1 or phase > 5) return .invalid_argument;
    const resolved: waf.engine.Phase = @fromBackingInt(@intCast(@as(u8, @intCast(phase))));
    transaction.evaluatePhase(std.heap.page_allocator, resolved) catch |err| return mapError(err);
    return .ok;
}

export fn zig_waf_transaction_intervention(
    handle: ?*const TransactionHandle,
    out_intervention: ?*CIntervention,
) callconv(.c) Status {
    const transaction = transactionFromConstHandle(handle orelse return .invalid_argument);
    const output = out_intervention orelse return .invalid_argument;
    if (output.struct_size < @sizeOf(CIntervention)) return .invalid_argument;
    if (output.abi_version != abi_version) return .unsupported_abi;
    const pending = (transaction.intervention() catch |err| return mapError(err)) orelse return .not_found;
    output.action = @backingInt(pending.action);
    output.status = pending.status;
    output.enforced = @intFromBool(pending.enforced);
    output.has_rule_id = @intFromBool(pending.rule_id != null);
    output.rule_id = pending.rule_id orelse 0;
    output.reserved = @splat(0);
    return .ok;
}

/// Serialize the transaction's audit record into a freshly allocated buffer.
/// `format`: 0 serial, 1 JSON, 2 legacy JSON, 3 OCSF, or 0xFFFFFFFF to use the
/// format selected by `SecAuditLogFormat` (defaulting to native/serial). On
/// success the caller owns `*out_buffer` and must release it with
/// `zig_waf_free(*out_buffer, *out_len)`.
const audit_format_configured: u32 = 0xFFFF_FFFF;

export fn zig_waf_transaction_serialize_audit_log(
    handle: ?*TransactionHandle,
    format: u32,
    out_buffer: ?*?[*]u8,
    out_len: ?*usize,
) callconv(.c) Status {
    const transaction = getTransaction(handle) orelse return .invalid_argument;
    const buffer_out = out_buffer orelse return .invalid_argument;
    const len_out = out_len orelse return .invalid_argument;
    buffer_out.* = null;
    len_out.* = 0;
    const fmt: waf.audit.Format = switch (format) {
        0 => .serial,
        1 => .json,
        2 => .legacy_json,
        3 => .ocsf,
        audit_format_configured => transaction.configuredAuditFormat(),
        else => return .invalid_argument,
    };
    const rendered = transaction.serializeAuditLog(std.heap.page_allocator, fmt) catch |err| return mapError(err);
    buffer_out.* = rendered.ptr;
    len_out.* = rendered.len;
    return .ok;
}

/// Release a buffer returned by the ABI (currently the audit-log serializer).
export fn zig_waf_free(pointer: ?[*]u8, len: usize) callconv(.c) void {
    const start = pointer orelse return;
    if (len == 0) return;
    std.heap.page_allocator.free(start[0..len]);
}

fn wafFromHandle(handle: *WafHandle) *waf.Waf {
    return @ptrCast(@alignCast(handle));
}

fn transactionFromHandle(handle: *TransactionHandle) *waf.Transaction {
    return @ptrCast(@alignCast(handle));
}

fn transactionFromConstHandle(handle: *const TransactionHandle) *const waf.Transaction {
    return @ptrCast(@alignCast(handle));
}

fn getTransaction(handle: ?*TransactionHandle) ?*waf.Transaction {
    return transactionFromHandle(handle orelse return null);
}

fn bytes(pointer: ?[*]const u8, len: usize) ?[]const u8 {
    if (len == 0) return &.{};
    const start = pointer orelse return null;
    return start[0..len];
}

fn mapError(err: anyerror) Status {
    return switch (err) {
        error.OutOfMemory => .out_of_memory,
        error.InvalidLimit,
        error.InvalidInterventionStatus,
        error.InvalidConnectionAddress,
        error.InvalidMethod,
        error.InvalidProtocol,
        error.InvalidHeader,
        error.RequestTargetTooLarge,
        => .invalid_config,
        error.InvalidLifecycle,
        error.Deinitialized,
        error.InterventionAlreadyRecorded,
        error.TransactionTerminated,
        => .invalid_lifecycle,
        error.TooManyHeaders,
        error.HeadersTooLarge,
        error.RequestBodyLimitExceeded,
        error.ResponseBodyLimitExceeded,
        error.ScalarValueTooLarge,
        error.ScalarStorageLimitExceeded,
        => .limit_exceeded,
        error.TransactionsActive => .busy,
        else => .internal,
    };
}

// ---- tests --------------------------------------------------------------
//
// Robustness of the C ABI boundary: malformed inputs must return a status
// code, never crash — a crash here is a denial of service in every connector
// (rpx dataplane, Nginx, Caddy, …) that links this library.

const testing = std.testing;

fn validConfig() Config {
    return .{
        .struct_size = @sizeOf(Config),
        .abi_version = abi_version,
        .mode = 0,
        .reserved0 = 0,
        .max_request_target_bytes = 8192,
        .max_header_count = 64,
        .max_header_bytes = 16384,
        .max_request_body_bytes = 1 << 20,
        .max_response_body_bytes = 1 << 20,
        .reserved = @splat(0),
    };
}

test "abi_version and feature query validate their struct contract" {
    try testing.expectEqual(abi_version, zig_waf_abi_version());

    // Null output and a too-small struct are rejected; a wrong ABI is flagged.
    try testing.expectEqual(Status.invalid_argument, zig_waf_query_features(null));
    var features: Features = undefined;
    features.struct_size = 0;
    features.abi_version = abi_version;
    try testing.expectEqual(Status.invalid_argument, zig_waf_query_features(&features));
    features.struct_size = @sizeOf(Features);
    features.abi_version = abi_version + 1;
    try testing.expectEqual(Status.unsupported_abi, zig_waf_query_features(&features));
    features.abi_version = abi_version;
    try testing.expectEqual(Status.ok, zig_waf_query_features(&features));
}

test "create rejects malformed config and a null output" {
    var handle: *WafHandle = undefined;
    try testing.expectEqual(Status.invalid_argument, zig_waf_create(null, null));

    var config = validConfig();
    config.struct_size = 0;
    try testing.expectEqual(Status.invalid_argument, zig_waf_create(&config, &handle));
    config = validConfig();
    config.abi_version = abi_version + 1;
    try testing.expectEqual(Status.unsupported_abi, zig_waf_create(&config, &handle));
    config = validConfig();
    config.mode = 99; // neither enabled (0) nor detection-only (1)
    try testing.expectEqual(Status.invalid_config, zig_waf_create(&config, &handle));

    // A well-formed config builds; the handle must then destroy cleanly.
    config = validConfig();
    try testing.expectEqual(Status.ok, zig_waf_create(&config, &handle));
    try testing.expectEqual(Status.ok, zig_waf_destroy(handle));
}

test "create_with_rules validates arguments and survives arbitrary rule bytes" {
    var handle: *WafHandle = undefined;
    const rules = "SecRule ARGS \"@rx x\" \"id:1,phase:1,pass,nolog\"";
    // Null output / a null rules pointer with a non-zero length are argument
    // errors, not crashes. (A null pointer with length 0 is a valid empty set.)
    try testing.expectEqual(Status.invalid_argument, zig_waf_create_with_rules(null, rules.ptr, rules.len, null));
    try testing.expectEqual(Status.invalid_argument, zig_waf_create_with_rules(null, null, 16, &handle));
    // A valid rule set compiles and builds.
    try testing.expectEqual(Status.ok, zig_waf_create_with_rules(null, rules.ptr, rules.len, &handle));
    try testing.expectEqual(Status.ok, zig_waf_destroy(handle));
    // A syntactically broken config is reported, not crashed.
    const broken = "SecRule ARGS";
    try testing.expectEqual(Status.invalid_config, zig_waf_create_with_rules(null, broken.ptr, broken.len, &handle));

    // Fuzz: arbitrary bytes must always yield a status without crashing; on the
    // rare success, the handle is destroyed.
    var prng = std.Random.DefaultPrng.init(0xAB1_C0DE_F00D);
    const random = prng.random();
    var buffer: [96]u8 = undefined;
    var iteration: usize = 0;
    while (iteration < 1500) : (iteration += 1) {
        const len = random.uintLessThan(usize, buffer.len + 1);
        for (buffer[0..len]) |*byte| {
            byte.* = switch (random.uintLessThan(u8, 8)) {
                0 => 'S',
                1 => ' ',
                2 => '"',
                3 => ',',
                4 => ':',
                5 => '\n',
                else => random.int(u8),
            };
        }
        var out: *WafHandle = undefined;
        const status = zig_waf_create_with_rules(null, buffer[0..len].ptr, len, &out);
        if (status == .ok) _ = zig_waf_destroy(out);
    }
}

test "serialize_audit_log rejects an unknown format" {
    var handle: *WafHandle = undefined;
    const rules = "SecAction \"id:1,pass,nolog\"";
    try testing.expectEqual(Status.ok, zig_waf_create_with_rules(null, rules.ptr, rules.len, &handle));
    defer _ = zig_waf_destroy(handle);
    var tx: *TransactionHandle = undefined;
    try testing.expectEqual(Status.ok, zig_waf_transaction_create(handle, &tx));
    defer zig_waf_transaction_destroy(tx);

    var buffer: ?[*]u8 = undefined;
    var len: usize = undefined;
    // 7 is not a valid format id (0..3 and the configured sentinel are).
    try testing.expectEqual(Status.invalid_argument, zig_waf_transaction_serialize_audit_log(tx, 7, &buffer, &len));
}
