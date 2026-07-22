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

export fn zig_waf_create(config: ?*const Config, out_waf: ?**WafHandle) callconv(.c) Status {
    const output = out_waf orelse return .invalid_argument;
    output.* = undefined;

    var builder = waf.Waf.Builder.init(std.heap.page_allocator);
    if (config) |input| {
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
    }
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
        error.InvalidLifecycle, error.Deinitialized => .invalid_lifecycle,
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
