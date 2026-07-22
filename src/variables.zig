//! Bounded, transaction-local scalar variable storage.

const std = @import("std");

pub const inline_value_capacity = 256;

pub const Name = enum {
    args_combined_size,
    auth_type,
    duration,
    files_combined_size,
    full_request,
    full_request_length,
    highest_severity,
    inbound_data_error,
    matched_var,
    matched_var_name,
    modsec_build,
    msc_pcre_error,
    msc_pcre_limits_exceeded,
    multipart_boundary_quoted,
    multipart_boundary_whitespace,
    multipart_crlf_lf_lines,
    multipart_data_after,
    multipart_data_before,
    multipart_file_limit_exceeded,
    multipart_header_folding,
    multipart_invalid_header_folding,
    multipart_invalid_part,
    multipart_invalid_quoting,
    multipart_lf_line,
    multipart_missing_semicolon,
    multipart_strict_error,
    multipart_unmatched_boundary,
    outbound_data_error,
    path_info,
    query_string,
    remote_addr,
    remote_host,
    remote_port,
    remote_user,
    reqbody_error,
    reqbody_error_msg,
    reqbody_processor,
    reqbody_processor_error,
    reqbody_processor_error_msg,
    request_basename,
    request_body,
    request_body_length,
    request_filename,
    request_line,
    request_method,
    request_protocol,
    request_uri,
    request_uri_raw,
    res_body_error,
    res_body_error_msg,
    res_body_processor,
    res_body_processor_error,
    res_body_processor_error_msg,
    response_body,
    response_content_length,
    response_content_type,
    response_protocol,
    response_status,
    server_addr,
    server_name,
    server_port,
    session_id,
    status,
    status_line,
    time,
    time_day,
    time_epoch,
    time_hour,
    time_min,
    time_mon,
    time_sec,
    time_wday,
    time_year,
    unique_id,
    urlencoded_error,
    user_id,
    webapp_id,

    pub fn secLangName(self: Name) []const u8 {
        return switch (self) {
            .args_combined_size => "ARGS_COMBINED_SIZE",
            .auth_type => "AUTH_TYPE",
            .duration => "DURATION",
            .files_combined_size => "FILES_COMBINED_SIZE",
            .full_request => "FULL_REQUEST",
            .full_request_length => "FULL_REQUEST_LENGTH",
            .highest_severity => "HIGHEST_SEVERITY",
            .inbound_data_error => "INBOUND_DATA_ERROR",
            .matched_var => "MATCHED_VAR",
            .matched_var_name => "MATCHED_VAR_NAME",
            .modsec_build => "MODSEC_BUILD",
            .msc_pcre_error => "MSC_PCRE_ERROR",
            .msc_pcre_limits_exceeded => "MSC_PCRE_LIMITS_EXCEEDED",
            .multipart_boundary_quoted => "MULTIPART_BOUNDARY_QUOTED",
            .multipart_boundary_whitespace => "MULTIPART_BOUNDARY_WHITESPACE",
            .multipart_crlf_lf_lines => "MULTIPART_CRLF_LF_LINES",
            .multipart_data_after => "MULTIPART_DATA_AFTER",
            .multipart_data_before => "MULTIPART_DATA_BEFORE",
            .multipart_file_limit_exceeded => "MULTIPART_FILE_LIMIT_EXCEEDED",
            .multipart_header_folding => "MULTIPART_HEADER_FOLDING",
            .multipart_invalid_header_folding => "MULTIPART_INVALID_HEADER_FOLDING",
            .multipart_invalid_part => "MULTIPART_INVALID_PART",
            .multipart_invalid_quoting => "MULTIPART_INVALID_QUOTING",
            .multipart_lf_line => "MULTIPART_LF_LINE",
            .multipart_missing_semicolon => "MULTIPART_MISSING_SEMICOLON",
            .multipart_strict_error => "MULTIPART_STRICT_ERROR",
            .multipart_unmatched_boundary => "MULTIPART_UNMATCHED_BOUNDARY",
            .outbound_data_error => "OUTBOUND_DATA_ERROR",
            .path_info => "PATH_INFO",
            .query_string => "QUERY_STRING",
            .remote_addr => "REMOTE_ADDR",
            .remote_host => "REMOTE_HOST",
            .remote_port => "REMOTE_PORT",
            .remote_user => "REMOTE_USER",
            .reqbody_error => "REQBODY_ERROR",
            .reqbody_error_msg => "REQBODY_ERROR_MSG",
            .reqbody_processor => "REQBODY_PROCESSOR",
            .reqbody_processor_error => "REQBODY_PROCESSOR_ERROR",
            .reqbody_processor_error_msg => "REQBODY_PROCESSOR_ERROR_MSG",
            .request_basename => "REQUEST_BASENAME",
            .request_body => "REQUEST_BODY",
            .request_body_length => "REQUEST_BODY_LENGTH",
            .request_filename => "REQUEST_FILENAME",
            .request_line => "REQUEST_LINE",
            .request_method => "REQUEST_METHOD",
            .request_protocol => "REQUEST_PROTOCOL",
            .request_uri => "REQUEST_URI",
            .request_uri_raw => "REQUEST_URI_RAW",
            .res_body_error => "RES_BODY_ERROR",
            .res_body_error_msg => "RES_BODY_ERROR_MSG",
            .res_body_processor => "RES_BODY_PROCESSOR",
            .res_body_processor_error => "RES_BODY_PROCESSOR_ERROR",
            .res_body_processor_error_msg => "RES_BODY_PROCESSOR_ERROR_MSG",
            .response_body => "RESPONSE_BODY",
            .response_content_length => "RESPONSE_CONTENT_LENGTH",
            .response_content_type => "RESPONSE_CONTENT_TYPE",
            .response_protocol => "RESPONSE_PROTOCOL",
            .response_status => "RESPONSE_STATUS",
            .server_addr => "SERVER_ADDR",
            .server_name => "SERVER_NAME",
            .server_port => "SERVER_PORT",
            .session_id => "SESSIONID",
            .status => "STATUS",
            .status_line => "STATUS_LINE",
            .time => "TIME",
            .time_day => "TIME_DAY",
            .time_epoch => "TIME_EPOCH",
            .time_hour => "TIME_HOUR",
            .time_min => "TIME_MIN",
            .time_mon => "TIME_MON",
            .time_sec => "TIME_SEC",
            .time_wday => "TIME_WDAY",
            .time_year => "TIME_YEAR",
            .unique_id => "UNIQUE_ID",
            .urlencoded_error => "URLENCODED_ERROR",
            .user_id => "USERID",
            .webapp_id => "WEBAPPID",
        };
    }

    pub fn parse(input: []const u8) ?Name {
        // ModSecurity accepts both historical spellings for this flag.
        if (std.ascii.eqlIgnoreCase(input, "MULTIPART_SEMICOLON_MISSING")) {
            return .multipart_missing_semicolon;
        }
        inline for (std.meta.tags(Name)) |candidate| {
            if (std.ascii.eqlIgnoreCase(input, candidate.secLangName())) return candidate;
        }
        return null;
    }

    pub fn minimumAvailability(self: Name) Availability {
        return switch (self) {
            .remote_addr, .remote_host, .remote_port, .server_addr, .server_port => .connection,
            .files_combined_size,
            .full_request,
            .full_request_length,
            .inbound_data_error,
            .multipart_boundary_quoted,
            .multipart_boundary_whitespace,
            .multipart_crlf_lf_lines,
            .multipart_data_after,
            .multipart_data_before,
            .multipart_file_limit_exceeded,
            .multipart_header_folding,
            .multipart_invalid_header_folding,
            .multipart_invalid_part,
            .multipart_invalid_quoting,
            .multipart_lf_line,
            .multipart_missing_semicolon,
            .multipart_strict_error,
            .multipart_unmatched_boundary,
            .reqbody_error,
            .reqbody_error_msg,
            .reqbody_processor_error,
            .reqbody_processor_error_msg,
            .request_body,
            .request_body_length,
            => .request_body,
            .response_content_type, .response_protocol, .response_status, .status, .status_line => .response_headers,
            .outbound_data_error,
            .res_body_error,
            .res_body_error_msg,
            .res_body_processor,
            .res_body_processor_error,
            .res_body_processor_error_msg,
            .response_body,
            .response_content_length,
            => .response_body,
            else => .request_headers,
        };
    }

    pub fn defaultOrigin(self: Name) Origin {
        return switch (self) {
            .remote_addr, .remote_host, .remote_port, .server_addr, .server_port => .connection,
            .auth_type, .reqbody_processor, .server_name => .request_header,
            .path_info,
            .query_string,
            .request_basename,
            .request_filename,
            .request_line,
            .request_method,
            .request_protocol,
            .request_uri,
            .request_uri_raw,
            => .request_target,
            .files_combined_size,
            .full_request,
            .full_request_length,
            .inbound_data_error,
            .multipart_boundary_quoted,
            .multipart_boundary_whitespace,
            .multipart_crlf_lf_lines,
            .multipart_data_after,
            .multipart_data_before,
            .multipart_file_limit_exceeded,
            .multipart_header_folding,
            .multipart_invalid_header_folding,
            .multipart_invalid_part,
            .multipart_invalid_quoting,
            .multipart_lf_line,
            .multipart_missing_semicolon,
            .multipart_strict_error,
            .multipart_unmatched_boundary,
            .reqbody_error,
            .reqbody_error_msg,
            .reqbody_processor_error,
            .reqbody_processor_error_msg,
            .request_body,
            .request_body_length,
            => .request_body,
            .response_content_type, .response_protocol, .response_status, .status, .status_line => .response_header,
            .outbound_data_error,
            .res_body_error,
            .res_body_error_msg,
            .res_body_processor,
            .res_body_processor_error,
            .res_body_processor_error_msg,
            .response_body,
            .response_content_length,
            => .response,
            .duration,
            .time,
            .time_day,
            .time_epoch,
            .time_hour,
            .time_min,
            .time_mon,
            .time_sec,
            .time_wday,
            .time_year,
            => .timing,
            .highest_severity, .matched_var, .matched_var_name => .rule,
            .modsec_build, .msc_pcre_error, .msc_pcre_limits_exceeded => .compatibility,
            .args_combined_size, .urlencoded_error => .parser,
            .unique_id => .engine,
            else => .connector,
        };
    }
};

pub const Origin = enum {
    connection,
    request_target,
    request_header,
    request_body,
    response_header,
    response,
    timing,
    parser,
    compatibility,
    engine,
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

test "stable scalar union round trips without duplicate SecLang names" {
    const names = std.meta.tags(Name);
    try std.testing.expectEqual(@as(usize, 81), names.len);
    for (names, 0..) |name, index| {
        try std.testing.expectEqual(name, Name.parse(name.secLangName()).?);
        const lowercase = try std.ascii.allocLowerString(std.testing.allocator, name.secLangName());
        defer std.testing.allocator.free(lowercase);
        try std.testing.expectEqual(name, Name.parse(lowercase).?);
        for (names[0..index]) |prior| {
            try std.testing.expect(!std.ascii.eqlIgnoreCase(name.secLangName(), prior.secLangName()));
        }
        _ = name.minimumAvailability();
        _ = name.defaultOrigin();
    }

    try std.testing.expectEqual(Name.multipart_missing_semicolon, Name.parse("MULTIPART_SEMICOLON_MISSING").?);
    try std.testing.expect(Name.parse("RESPONSE_BODY_LENGTH") == null);
}
