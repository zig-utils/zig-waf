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
/// use the CLI (`zig-waf validate`) to see the diagnostics. `@pmFromFile` /
/// `@ipMatchFromFile` operators do not load their data files on this path (no
/// data directory is known) — use `zig_waf_create_with_rules_at` for that.
export fn zig_waf_create_with_rules(
    config: ?*const Config,
    rules_pointer: ?[*]const u8,
    rules_len: usize,
    out_waf: ?**WafHandle,
) callconv(.c) Status {
    const output = out_waf orelse return .invalid_argument;
    output.* = undefined;
    const rules = bytes(rules_pointer, rules_len) orelse return .invalid_argument;
    return compileRules(config, rules, null, output);
}

/// Like `zig_waf_create_with_rules`, but resolves `@pmFromFile` /
/// `@ipMatchFromFile` data files relative to `data_dir` (SecDataDir semantics),
/// confined to that directory. Lets a connector load file-backed operators.
export fn zig_waf_create_with_rules_at(
    config: ?*const Config,
    rules_pointer: ?[*]const u8,
    rules_len: usize,
    data_dir_pointer: ?[*]const u8,
    data_dir_len: usize,
    out_waf: ?**WafHandle,
) callconv(.c) Status {
    const output = out_waf orelse return .invalid_argument;
    output.* = undefined;
    const rules = bytes(rules_pointer, rules_len) orelse return .invalid_argument;
    const data_dir = bytes(data_dir_pointer, data_dir_len) orelse return .invalid_argument;
    if (data_dir.len == 0) return .invalid_argument;

    // A blocking, thread-pool-free io for the one-shot compile-time file reads.
    const io = std.Io.Threaded.global_single_threaded.io();
    // Canonicalize the data directory: it is the withinRoot confinement boundary
    // and must match the canonical form of each resolved data-file path.
    var dir = std.Io.Dir.cwd().openDir(io, data_dir, .{}) catch return .invalid_config;
    defer dir.close(io);
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = dir.realPath(io, &root_buffer) catch return .invalid_config;
    var provider_context: DataDirProvider = .{ .io = io, .root = root_buffer[0..root_len] };
    const provider: waf.plan.DataProvider = .{ .context = &provider_context, .readFn = DataDirProvider.read };
    return compileRules(config, rules, provider, output);
}

/// Loads operator data files relative to (and confined within) `root`.
const DataDirProvider = struct {
    io: std.Io,
    root: []const u8,

    fn read(context: *anyopaque, allocator: std.mem.Allocator, base_dir: []const u8, filename: []const u8) anyerror![]u8 {
        _ = base_dir; // all data files resolve against the configured data dir
        const self: *DataDirProvider = @ptrCast(@alignCast(context));
        return waf.seclang.include.readDataFileAlloc(allocator, self.io, self.root, self.root, filename, 8 * 1024 * 1024, false);
    }
};

/// Shared compile-and-build for the rule-set create paths.
fn compileRules(config: ?*const Config, rules: []const u8, provider: ?waf.plan.DataProvider, output: **WafHandle) Status {
    const gpa = std.heap.page_allocator;
    var parsed = waf.seclang.parser.parseBytesOutcome(gpa, "c-abi-rules", rules, .{}, .{}) catch return .out_of_memory;
    defer parsed.deinit();
    const document = switch (parsed.outcome) {
        .document => |value| value,
        .diagnostic => return .invalid_config,
    };
    var documents = [_]waf.seclang.parser.Document{document};
    const plan = waf.plan.compileWithProvider(gpa, &parsed.registry, &documents, .{}, provider) catch return .invalid_config;
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

test "create_with_rules_at loads @pmFromFile data files from the data dir" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "shells.data", .data = "bin/cat\nbin/ls\n" });
    var dir_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &dir_buffer);
    const data_dir = dir_buffer[0..dir_len];

    const rules = "SecRule ARGS \"@pmFromFile shells.data\" \"id:1,phase:1,deny,status:403,t:none\"";

    // Without a data dir the file is not loaded, so a matching arg is allowed.
    {
        var handle: *WafHandle = undefined;
        try testing.expectEqual(Status.ok, zig_waf_create_with_rules(null, rules.ptr, rules.len, &handle));
        defer _ = zig_waf_destroy(handle);
        try testing.expect(!requestBlocked(handle, "/x?c=/bin/cat"));
    }
    // With the data dir the file loads, so a matching arg is blocked while a
    // non-matching one is allowed — proving the phrases came from the file.
    {
        var handle: *WafHandle = undefined;
        try testing.expectEqual(Status.ok, zig_waf_create_with_rules_at(null, rules.ptr, rules.len, data_dir.ptr, data_dir.len, &handle));
        defer _ = zig_waf_destroy(handle);
        try testing.expect(requestBlocked(handle, "/x?c=/bin/cat"));
        try testing.expect(!requestBlocked(handle, "/x?c=hello"));
    }

    // A missing / null data dir is an argument error.
    var handle: *WafHandle = undefined;
    try testing.expectEqual(Status.invalid_argument, zig_waf_create_with_rules_at(null, rules.ptr, rules.len, null, 4, &handle));
}

/// Run a GET `uri` through phase 1 and report whether it is enforced-blocked.
fn requestBlocked(handle: *WafHandle, uri: []const u8) bool {
    var tx: *TransactionHandle = undefined;
    if (zig_waf_transaction_create(handle, &tx) != .ok) return false;
    defer zig_waf_transaction_destroy(tx);
    const ip = "127.0.0.1";
    _ = zig_waf_transaction_process_connection(tx, ip.ptr, ip.len, 1, ip.ptr, ip.len, 80);
    const method = "GET";
    const version = "HTTP/1.1";
    _ = zig_waf_transaction_process_uri(tx, uri.ptr, uri.len, method.ptr, method.len, version.ptr, version.len);
    _ = zig_waf_transaction_process_request_headers(tx);
    _ = zig_waf_transaction_evaluate_phase(tx, 1);
    var decision: CIntervention = std.mem.zeroes(CIntervention);
    decision.struct_size = @sizeOf(CIntervention);
    decision.abi_version = abi_version;
    return zig_waf_transaction_intervention(tx, &decision) == .ok and decision.enforced != 0;
}

test "the ABI's layout is pinned, so a change cannot happen silently" {
    // A connector compiled against this header links against these exact offsets and
    // sizes. Changing one without changing ZIG_WAF_ABI_VERSION would let an old
    // connector call a new library and read the wrong fields — the failure mode that
    // versioning exists to prevent, and the one nothing else here would catch.
    //
    // Adding a field inside `reserved` keeps these numbers the same on purpose: that
    // is the additive path, and it is why the reserved arrays exist.
    try std.testing.expectEqual(@as(u32, 0x00010000), abi_version);
    try std.testing.expectEqual(@as(usize, 120), @sizeOf(Config));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(Features));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(CIntervention));

    // Field offsets a header change could shift without changing a size.
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(Config, "struct_size"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(Config, "abi_version"));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(Features, "struct_size"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(Features, "feature_bits"));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(CIntervention, "struct_size"));
    try std.testing.expectEqual(@as(usize, 12), @offsetOf(CIntervention, "status"));

    // Every struct carries its own size and the version it was built against, which
    // is what makes the additive path checkable at run time rather than by
    // convention.
    var features: Features = .{ .struct_size = @sizeOf(Features), .abi_version = abi_version, .feature_bits = 0, .highest_phase = 0, .reserved0 = 0, .reserved = @splat(0) };
    try std.testing.expectEqual(Status.ok, zig_waf_query_features(&features));
    try std.testing.expectEqual(abi_version, features.abi_version);

    // A caller from the future — a larger struct than this library knows — is
    // accepted, because the fields this library reads are still where it expects
    // them. A caller from the past, with a struct too small to contain them, is not.
    features.struct_size = @sizeOf(Features) + 64;
    try std.testing.expectEqual(Status.ok, zig_waf_query_features(&features));
    features.struct_size = @sizeOf(Features) - 8;
    try std.testing.expectEqual(Status.invalid_argument, zig_waf_query_features(&features));
}

test "any call sequence yields a status rather than a crash" {
    // The rule bytes are already fuzzed above; this fuzzes the *call order*, which
    // is where a connector actually goes wrong. A data plane that calls
    // process_request_body before process_uri, evaluates a phase twice, or keeps
    // using a transaction after processing logging must get a status back — the ABI
    // is a boundary with untrusted callers on the other side, and lifecycle errors
    // are the ones a connector hits in production rather than in a unit test.
    const rules = "SecRule ARGS \"@rx attack\" \"id:1,phase:2,deny,status:403,t:none\"";
    var waf_handle: *WafHandle = undefined;
    try testing.expectEqual(Status.ok, zig_waf_create_with_rules(null, rules.ptr, rules.len, &waf_handle));
    defer _ = zig_waf_destroy(waf_handle);

    var prng = std.Random.DefaultPrng.init(0x5EED_C0DE_ABCD);
    const random = prng.random();

    var iteration: usize = 0;
    while (iteration < 2000) : (iteration += 1) {
        var transaction: *TransactionHandle = undefined;
        if (zig_waf_transaction_create(waf_handle, &transaction) != .ok) continue;
        defer zig_waf_transaction_destroy(transaction);

        // A random-length sequence of lifecycle calls in a random order.
        var step: usize = 0;
        const steps = random.uintLessThan(usize, 12);
        while (step < steps) : (step += 1) {
            const body = "user=attack";
            const status = switch (random.uintLessThan(u8, 11)) {
                0 => zig_waf_transaction_process_connection(transaction, "192.0.2.1", 9, 1234, "198.51.100.1", 12, 443),
                1 => zig_waf_transaction_process_uri(transaction, "/?a=attack", 10, "GET", 3, "HTTP/1.1", 8),
                2 => zig_waf_transaction_add_request_header(transaction, "Host", 4, "example.com", 11),
                3 => zig_waf_transaction_process_request_headers(transaction),
                4 => zig_waf_transaction_write_request_body(transaction, body.ptr, body.len),
                5 => zig_waf_transaction_process_request_body(transaction),
                6 => zig_waf_transaction_add_response_header(transaction, "Server", 6, "test", 4),
                7 => zig_waf_transaction_process_response_headers(transaction, 200, "HTTP/1.1", 8),
                8 => zig_waf_transaction_process_response_body(transaction),
                9 => zig_waf_transaction_process_logging(transaction),
                else => zig_waf_transaction_evaluate_phase(transaction, random.uintLessThan(u32, 7)),
            };
            // Every status is one of the defined ones — an out-of-order call is
            // reported, never undefined behaviour.
            switch (status) {
                .ok, .invalid_argument, .unsupported_abi, .out_of_memory, .invalid_config, .invalid_lifecycle, .limit_exceeded, .busy, .not_found, .internal => {},
            }

            // Interrogating a transaction at any point is safe, whatever state it is
            // in: a connector reads the decision when it has one, not only when the
            // library expects the question.
            var intervention: CIntervention = .{
                .struct_size = @sizeOf(CIntervention),
                .abi_version = abi_version,
                .action = 0,
                .status = 0,
                .enforced = 0,
                .has_rule_id = 0,
                .rule_id = 0,
                .reserved = @splat(0),
            };
            _ = zig_waf_transaction_intervention(transaction, &intervention);
        }
    }
}
