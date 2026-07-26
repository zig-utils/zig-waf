//! Audit-log record model and serializers.
//!
//! An `AuditRecord` is a borrowed snapshot of the audit-relevant facts of a
//! finished transaction; the engine assembles one and hands it to a writer. The
//! serializers here own only the *format*, not collection or clock access, so
//! they are pure and deterministic given a record.
//!
//! The native serial format is pinned to ModSecurity's `toOldAuditLogFormat`
//! (the classic dashed-boundary sections `--<boundary>-A--` … `--<boundary>-Z--`)
//! and honors the same A–K part selection. Parts D/G/I/J are emitted as empty
//! section markers when selected, matching ModSecurity, which reserves them.

const std = @import("std");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// The audit parts to include, keyed 'A'..'K'. A and Z are always emitted (the
/// header and terminator); B–K are selectable. Mirrors SecAuditLogParts.
pub const Parts = struct {
    bits: u16 = 0,

    pub fn has(self: Parts, part: u8) bool {
        if (part < 'B' or part > 'K') return part == 'A' or part == 'Z';
        return self.bits & (@as(u16, 1) << @intCast(part - 'B')) != 0;
    }

    /// Build from a letter set such as "ABCFHZ".
    pub fn fromLetters(letters: []const u8) Parts {
        var parts: Parts = .{};
        for (letters) |letter| {
            if (letter >= 'B' and letter <= 'K') {
                parts.bits |= @as(u16, 1) << @intCast(letter - 'B');
            }
        }
        return parts;
    }
};

pub const AuditRecord = struct {
    /// The section boundary (ModSecurity's "trailer"): a per-transaction id.
    boundary: []const u8,
    /// Seconds since the Unix epoch for the audit-header timestamp (part A).
    timestamp: i64,
    /// Optional human-formatted timestamp for the JSON `timestamp` field; the
    /// serial format always derives its own from `timestamp`.
    timestamp_string: ?[]const u8 = null,
    /// Whether the transaction was interrupted (JSON `is_interrupted`).
    is_interrupted: bool = false,

    unique_id: []const u8,
    client_ip: []const u8,
    client_port: u16,
    server_ip: []const u8,
    server_port: u16,

    // Request line + headers + body (parts B, C).
    method: []const u8,
    uri: []const u8,
    http_version: []const u8,
    request_headers: []const Header = &.{},
    request_body: ?[]const u8 = null,

    // Response line + headers + body (parts E, F).
    response_status: u16 = 0,
    response_headers: []const Header = &.{},
    response_body: ?[]const u8 = null,

    // Rule messages for the trailer (part H), producer info.
    messages: []const []const u8 = &.{},
    producer: []const u8 = "zig-waf",
    /// The rule-engine mode string (JSON legacy `engine_mode`).
    rule_engine: []const u8 = "",

    // Extra facts used by the OCSF format.
    /// Producer version (OCSF metadata.log_version).
    version: []const u8 = "",
    /// Server identity (OCSF ServerID observable).
    server_id: []const u8 = "",
    /// Highest matched-rule severity, as a label (OCSF severity).
    highest_severity: []const u8 = "",
    /// Preformatted request arguments as "k=v,k=v" (OCSF http_request.args).
    args: []const u8 = "",
    /// Request body length in bytes (OCSF http_request.length).
    request_length: i64 = 0,
};

/// The audit-log output formats.
pub const Format = enum { serial, json, legacy_json, ocsf };

/// Serialize `record` in `format`, appending to `out`.
pub fn write(out: *std.ArrayList(u8), allocator: std.mem.Allocator, record: AuditRecord, parts: Parts, format: Format) !void {
    switch (format) {
        .serial => try writeSerial(out, allocator, record, parts),
        .json => try writeJson(out, allocator, record, parts),
        .legacy_json => try writeLegacyJson(out, allocator, record, parts),
        .ocsf => try writeOcsf(out, allocator, record, parts),
    }
}

const months = [_][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

/// The UTC calendar breakdown of an epoch timestamp.
pub const Civil = struct {
    year: u16,
    month: u4,
    day: u5,
    hour: u5,
    minute: u6,
    second: u6,
};

/// Break `epoch_seconds` into UTC calendar components. UTC keeps every derived
/// timestamp and path deterministic and free of the host time-zone database.
pub fn civil(epoch_seconds: i64) Civil {
    const secs: u64 = @intCast(@max(epoch_seconds, 0));
    const epoch_day = std.time.epoch.EpochDay{ .day = @intCast(secs / std.time.epoch.secs_per_day) };
    const day_seconds = std.time.epoch.DaySeconds{ .secs = @intCast(secs % std.time.epoch.secs_per_day) };
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return .{
        .year = year_day.year,
        .month = month_day.month.numeric(),
        .day = month_day.day_index + 1,
        .hour = day_seconds.getHoursIntoDay(),
        .minute = day_seconds.getMinutesIntoHour(),
        .second = day_seconds.getSecondsIntoMinute(),
    };
}

/// Append `epoch_seconds` (UTC) as ModSecurity's audit timestamp,
/// `[dd/Mmm/yyyy:hh:mm:ss +0000]`.
pub fn writeTimestamp(out: *std.ArrayList(u8), allocator: std.mem.Allocator, epoch_seconds: i64) !void {
    const c = civil(epoch_seconds);
    try appendFmt(out, allocator, "[{d:0>2}/{s}/{d}:{d:0>2}:{d:0>2}:{d:0>2} +0000]", .{
        c.day, months[c.month - 1], c.year, c.hour, c.minute, c.second,
    });
}

/// Serialize `record` in the native serial (ModSecurity legacy) audit format,
/// appending to `out`.
pub fn writeSerial(out: *std.ArrayList(u8), allocator: std.mem.Allocator, record: AuditRecord, parts: Parts) !void {
    // Part A — audit-log header (always present).
    try writeBoundary(out, allocator, record.boundary, 'A');
    try writeTimestamp(out, allocator, record.timestamp);
    try appendFmt(out, allocator, " {s} {s} {d} {s} {d}\n", .{
        record.unique_id,
        record.client_ip,
        record.client_port,
        record.server_ip,
        record.server_port,
    });

    // Part B — request headers.
    if (parts.has('B')) {
        try writeBoundary(out, allocator, record.boundary, 'B');
        try appendFmt(out, allocator, "{s} {s} HTTP/{s}\n", .{ record.method, record.uri, record.http_version });
        for (record.request_headers) |header| {
            try appendFmt(out, allocator, "{s}: {s}\n", .{ header.name, header.value });
        }
        try out.append(allocator, '\n');
    }

    // Part C — request body.
    if (parts.has('C')) {
        if (record.request_body) |body| if (body.len != 0) {
            try writeBoundary(out, allocator, record.boundary, 'C');
            try appendFmt(out, allocator, "{s}\n\n", .{body});
        };
    }

    // Part E — response body.
    if (parts.has('E')) {
        if (record.response_body) |body| if (body.len != 0) {
            try writeBoundary(out, allocator, record.boundary, 'E');
            try appendFmt(out, allocator, "{s}\n\n", .{body});
        };
    }

    // Part F — response headers.
    if (parts.has('F')) {
        try writeBoundary(out, allocator, record.boundary, 'F');
        try appendFmt(out, allocator, "HTTP/{s} {d}\n", .{ record.http_version, record.response_status });
        for (record.response_headers) |header| {
            try appendFmt(out, allocator, "{s}: {s}\n", .{ header.name, header.value });
        }
        try out.append(allocator, '\n');
    }

    // Part H — trailer with rule messages.
    if (parts.has('H')) {
        try writeBoundary(out, allocator, record.boundary, 'H');
        for (record.messages) |message| {
            try appendFmt(out, allocator, "{s}\n", .{message});
        }
        try appendFmt(out, allocator, "Producer: {s}.\n", .{record.producer});
        try out.append(allocator, '\n');
    }

    // Reserved sections emit an empty marker when selected, matching ModSecurity.
    for ([_]u8{ 'D', 'G', 'I', 'J', 'K' }) |part| {
        if (parts.has(part)) {
            try writeBoundary(out, allocator, record.boundary, part);
            try out.append(allocator, '\n');
        }
    }

    // Part Z — terminator (always present).
    try writeBoundary(out, allocator, record.boundary, 'Z');
    try out.append(allocator, '\n');
}

fn writeBoundary(out: *std.ArrayList(u8), allocator: std.mem.Allocator, boundary: []const u8, part: u8) !void {
    try appendFmt(out, allocator, "--{s}-{c}--\n", .{ boundary, part });
}

/// Serialize `record` as a single JSON object matching Coraza's structured
/// audit-log schema: `{"transaction":{...},"messages":[...]}`. Field values are
/// gated by the same A–K part selection (headers/body only when their part is
/// selected). Go marshals header maps in nondeterministic key order, so this is
/// schema-compatible, not byte-identical.
pub fn writeJson(out: *std.ArrayList(u8), allocator: std.mem.Allocator, record: AuditRecord, parts: Parts) !void {
    const gpa = allocator;
    try out.appendSlice(gpa, "{\"transaction\":{");
    try appendJsonField(out, gpa, "timestamp", record.timestamp_string orelse "", true);
    try appendFmt(out, gpa, ",\"unix_timestamp\":{d}", .{record.timestamp});
    try out.append(gpa, ',');
    try appendJsonField(out, gpa, "id", record.unique_id, true);
    try out.append(gpa, ',');
    try appendJsonField(out, gpa, "client_ip", record.client_ip, true);
    try appendFmt(out, gpa, ",\"client_port\":{d}", .{record.client_port});
    try out.append(gpa, ',');
    try appendJsonField(out, gpa, "host_ip", record.server_ip, true);
    try appendFmt(out, gpa, ",\"host_port\":{d}", .{record.server_port});

    // request object (method/uri/version always; headers gated by B, body by C).
    try out.appendSlice(gpa, ",\"request\":{");
    try appendJsonField(out, gpa, "method", record.method, true);
    try out.append(gpa, ',');
    try appendJsonField(out, gpa, "uri", record.uri, true);
    try out.append(gpa, ',');
    try appendJsonField(out, gpa, "http_version", record.http_version, true);
    try out.appendSlice(gpa, ",\"headers\":");
    try appendHeaderObject(out, gpa, if (parts.has('B')) record.request_headers else &.{});
    try out.appendSlice(gpa, ",\"body\":");
    try appendJsonString(out, gpa, if (parts.has('C')) (record.request_body orelse "") else "");
    try out.append(gpa, '}');

    // response object (status always; headers gated by F, body by E).
    try appendFmt(out, gpa, ",\"response\":{{\"status\":{d}", .{record.response_status});
    try out.appendSlice(gpa, ",\"headers\":");
    try appendHeaderObject(out, gpa, if (parts.has('F')) record.response_headers else &.{});
    try out.appendSlice(gpa, ",\"body\":");
    try appendJsonString(out, gpa, if (parts.has('E')) (record.response_body orelse "") else "");
    try out.append(gpa, '}');

    // producer object.
    try out.appendSlice(gpa, ",\"producer\":{");
    try appendJsonField(out, gpa, "connector", record.producer, true);
    try out.append(gpa, '}');

    try appendFmt(out, gpa, ",\"is_interrupted\":{}", .{record.is_interrupted});
    try out.appendSlice(gpa, "},\"messages\":[");
    for (record.messages, 0..) |message, index| {
        if (index != 0) try out.append(gpa, ',');
        try out.appendSlice(gpa, "{\"message\":");
        try appendJsonString(out, gpa, message);
        try out.append(gpa, '}');
    }
    try out.appendSlice(gpa, "]}");
}

fn appendJsonField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, name: []const u8, value: []const u8, quoted: bool) !void {
    try out.append(allocator, '"');
    try out.appendSlice(allocator, name);
    try out.appendSlice(allocator, "\":");
    if (quoted) {
        try appendJsonString(out, allocator, value);
    } else {
        try out.appendSlice(allocator, value);
    }
}

/// Emit headers as a JSON object mapping each name to an array of its values,
/// grouping repeated names (matching Coraza's map[string][]string).
fn appendHeaderObject(out: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const Header) !void {
    try out.append(allocator, '{');
    var written: usize = 0;
    for (headers, 0..) |header, index| {
        // Skip a name already emitted by an earlier occurrence.
        var seen = false;
        var prior: usize = 0;
        while (prior < index) : (prior += 1) {
            if (std.mem.eql(u8, headers[prior].name, header.name)) {
                seen = true;
                break;
            }
        }
        if (seen) continue;
        if (written != 0) try out.append(allocator, ',');
        written += 1;
        try appendJsonString(out, allocator, header.name);
        try out.appendSlice(allocator, ":[");
        var value_count: usize = 0;
        for (headers) |candidate| {
            if (!std.mem.eql(u8, candidate.name, header.name)) continue;
            if (value_count != 0) try out.append(allocator, ',');
            value_count += 1;
            try appendJsonString(out, allocator, candidate.value);
        }
        try out.append(allocator, ']');
    }
    try out.append(allocator, '}');
}

/// Serialize `record` in Coraza's legacy JSON audit format: a flatter object
/// with `remote_address`/`local_address` naming and header maps whose repeated
/// values are joined with ", " into a single string.
pub fn writeLegacyJson(out: *std.ArrayList(u8), allocator: std.mem.Allocator, record: AuditRecord, parts: Parts) !void {
    const gpa = allocator;
    try out.appendSlice(gpa, "{\"transaction\":{");
    try appendJsonField(out, gpa, "time", record.timestamp_string orelse "", true);
    try out.append(gpa, ',');
    try appendJsonField(out, gpa, "transaction_id", record.unique_id, true);
    try out.append(gpa, ',');
    try appendJsonField(out, gpa, "remote_address", record.client_ip, true);
    try appendFmt(out, gpa, ",\"remote_port\":{d}", .{record.client_port});
    try out.append(gpa, ',');
    try appendJsonField(out, gpa, "local_address", record.server_ip, true);
    try appendFmt(out, gpa, ",\"local_port\":{d}", .{record.server_port});
    try out.append(gpa, '}');

    // request
    try out.appendSlice(gpa, ",\"request\":{\"request_line\":");
    // The request line embeds attacker-controlled method/uri/version, so it must
    // be built and then JSON-escaped rather than interpolated raw into a literal.
    const request_line = try std.fmt.allocPrint(gpa, "{s} {s} HTTP/{s}", .{ record.method, record.uri, record.http_version });
    defer gpa.free(request_line);
    try appendJsonString(out, gpa, request_line);
    try out.appendSlice(gpa, ",\"headers\":");
    try appendHeaderObjectJoined(out, gpa, if (parts.has('B')) record.request_headers else &.{});
    try out.append(gpa, '}');

    // response
    try appendFmt(out, gpa, ",\"response\":{{\"status\":{d}", .{record.response_status});
    try out.appendSlice(gpa, ",\"protocol\":");
    const protocol = try std.fmt.allocPrint(gpa, "HTTP/{s}", .{record.http_version});
    defer gpa.free(protocol);
    try appendJsonString(out, gpa, protocol);
    try out.appendSlice(gpa, ",\"headers\":");
    try appendHeaderObjectJoined(out, gpa, if (parts.has('F')) record.response_headers else &.{});
    try out.append(gpa, '}');

    // audit_data
    try out.appendSlice(gpa, ",\"audit_data\":{\"messages\":[");
    for (record.messages, 0..) |message, index| {
        if (index != 0) try out.append(gpa, ',');
        try appendJsonString(out, gpa, message);
    }
    try out.appendSlice(gpa, "],\"producer\":[");
    try appendJsonString(out, gpa, record.producer);
    try out.appendSlice(gpa, "],");
    try appendJsonField(out, gpa, "engine_mode", record.rule_engine, true);
    try out.appendSlice(gpa, "}}");
}

/// Serialize `record` as an OCSF (Open Cybersecurity Schema Framework) v1.2.0
/// "Web Resources Activity" event, matching Coraza's OCSF formatter. Emits the
/// class/category/type identifiers, allowed/denied action, HTTP request and
/// response objects, endpoints, enrichments per rule message, and observables.
pub fn writeOcsf(out: *std.ArrayList(u8), allocator: std.mem.Allocator, record: AuditRecord, parts: Parts) !void {
    const gpa = allocator;
    const denied = record.is_interrupted;
    try out.append(gpa, '{');
    // Classification (OCSF Web Resources Activity: class 6004, category 6).
    try appendFmt(out, gpa, "\"activity_id\":1,\"activity_name\":\"Read\"", .{});
    try appendFmt(out, gpa, ",\"category_uid\":6,\"category_name\":\"Application Activity\"", .{});
    try appendFmt(out, gpa, ",\"class_uid\":6004,\"class_name\":\"Web Resources Activity\"", .{});
    try appendFmt(out, gpa, ",\"type_uid\":600401,\"type_name\":\"Read\"", .{});
    try appendFmt(out, gpa, ",\"time\":{d},\"start_time\":{d}", .{ record.timestamp, record.timestamp });
    try appendFmt(out, gpa, ",\"action_id\":{d},\"action\":\"{s}\"", .{
        @as(u8, if (denied) 2 else 1),
        @as([]const u8, if (denied) "Denied" else "Allowed"),
    });
    try appendFmt(out, gpa, ",\"timezone_offset\":0", .{});
    // Severity (severity_id 99 = Other; the label carries the rule severity).
    try out.appendSlice(gpa, ",\"severity_id\":99,\"severity\":");
    try appendJsonString(out, gpa, record.highest_severity);

    // metadata
    try out.appendSlice(gpa, ",\"metadata\":{\"version\":\"1.2.0\",\"log_provider\":");
    try appendJsonString(out, gpa, record.producer);
    try out.appendSlice(gpa, ",\"log_version\":");
    try appendJsonString(out, gpa, record.version);
    try appendFmt(out, gpa, ",\"logged_time\":{d}", .{record.timestamp * std.time.us_per_s});
    try out.appendSlice(gpa, ",\"product\":{\"vendor_name\":\"zig-waf Web Application Firewall\"}}");

    // http_request
    try out.appendSlice(gpa, ",\"http_request\":{\"http_method\":");
    try appendJsonString(out, gpa, record.method);
    try out.appendSlice(gpa, ",\"version\":");
    try appendJsonString(out, gpa, record.http_version);
    try out.appendSlice(gpa, ",\"uid\":");
    try appendJsonString(out, gpa, record.unique_id);
    try out.appendSlice(gpa, ",\"url\":{\"url_string\":");
    try appendJsonString(out, gpa, record.uri);
    try out.appendSlice(gpa, "},\"args\":");
    try appendJsonString(out, gpa, record.args);
    try appendFmt(out, gpa, ",\"length\":{d}", .{record.request_length});
    if (findHeader(record.request_headers, "user-agent")) |ua| {
        try out.appendSlice(gpa, ",\"user_agent\":");
        try appendJsonString(out, gpa, ua);
    }
    if (findHeader(record.request_headers, "referer")) |ref| {
        try out.appendSlice(gpa, ",\"referrer\":");
        try appendJsonString(out, gpa, ref);
    }
    try out.appendSlice(gpa, ",\"http_headers\":");
    try appendHeaderArray(out, gpa, if (parts.has('B')) record.request_headers else &.{});
    try out.append(gpa, '}');

    // http_response
    try appendFmt(out, gpa, ",\"http_response\":{{\"code\":{d},\"http_headers\":", .{record.response_status});
    try appendHeaderArray(out, gpa, if (parts.has('F')) record.response_headers else &.{});
    try out.append(gpa, '}');

    // endpoints
    try out.appendSlice(gpa, ",\"src_endpoint\":{\"ip\":");
    try appendJsonString(out, gpa, record.client_ip);
    try appendFmt(out, gpa, ",\"port\":{d}}}", .{record.client_port});
    try out.appendSlice(gpa, ",\"dst_endpoint\":{\"ip\":");
    try appendJsonString(out, gpa, record.server_ip);
    try appendFmt(out, gpa, ",\"port\":{d}}}", .{record.server_port});

    // web_resources
    try out.appendSlice(gpa, ",\"web_resources\":[{\"url_string\":");
    try appendJsonString(out, gpa, record.uri);
    try out.appendSlice(gpa, "}]");

    // enrichments (one per rule message) and the primary message.
    try out.appendSlice(gpa, ",\"enrichments\":[");
    for (record.messages, 0..) |message, index| {
        if (index != 0) try out.append(gpa, ',');
        try out.appendSlice(gpa, "{\"name\":");
        try appendJsonString(out, gpa, message);
        try out.appendSlice(gpa, ",\"value\":");
        try appendJsonString(out, gpa, message);
        try out.appendSlice(gpa, ",\"data\":");
        try appendJsonString(out, gpa, message);
        try out.append(gpa, '}');
    }
    try out.append(gpa, ']');
    if (record.messages.len != 0) {
        try out.appendSlice(gpa, ",\"message\":");
        try appendJsonString(out, gpa, record.messages[0]);
    }

    // observables (server id).
    try out.appendSlice(gpa, ",\"observables\":[");
    if (record.server_id.len != 0) {
        try out.appendSlice(gpa, "{\"name\":\"ServerID\",\"type\":\"ServerID\",\"type_id\":99,\"value\":");
        try appendJsonString(out, gpa, record.server_id);
        try out.append(gpa, '}');
    }
    try out.appendSlice(gpa, "]}");
}

fn findHeader(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

/// Emit headers as a JSON array of {name,value} objects (OCSF HttpHeader list).
fn appendHeaderArray(out: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const Header) !void {
    try out.append(allocator, '[');
    for (headers, 0..) |header, index| {
        if (index != 0) try out.append(allocator, ',');
        try out.appendSlice(allocator, "{\"name\":");
        try appendJsonString(out, allocator, header.name);
        try out.appendSlice(allocator, ",\"value\":");
        try appendJsonString(out, allocator, header.value);
        try out.append(allocator, '}');
    }
    try out.append(allocator, ']');
}

/// Emit headers as a JSON object mapping each name to a single string, joining
/// repeated values with ", " (Coraza legacy map[string]string).
fn appendHeaderObjectJoined(out: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const Header) !void {
    try out.append(allocator, '{');
    var written: usize = 0;
    for (headers, 0..) |header, index| {
        var seen = false;
        var prior: usize = 0;
        while (prior < index) : (prior += 1) {
            if (std.mem.eql(u8, headers[prior].name, header.name)) {
                seen = true;
                break;
            }
        }
        if (seen) continue;
        if (written != 0) try out.append(allocator, ',');
        written += 1;
        try appendJsonString(out, allocator, header.name);
        try out.append(allocator, ':');
        // Join all values for this name with ", ".
        var joined: std.ArrayList(u8) = .empty;
        defer joined.deinit(allocator);
        var value_count: usize = 0;
        for (headers) |candidate| {
            if (!std.mem.eql(u8, candidate.name, header.name)) continue;
            if (value_count != 0) try joined.appendSlice(allocator, ", ");
            value_count += 1;
            try joined.appendSlice(allocator, candidate.value);
        }
        try appendJsonString(out, allocator, joined.items);
    }
    try out.append(allocator, '}');
}

/// Append `value` as a JSON string literal with the mandatory escapes.
///
/// A request may contain any bytes at all — a URI, a header, or a body is not
/// required to be UTF-8, and an attacker chooses them. JSON strings *are* required
/// to be UTF-8, so a byte sequence that is not valid UTF-8 is replaced with U+FFFD
/// rather than copied through. Copying it through produced a document a log consumer
/// could not parse, which let a request make the record of its own attack
/// unreadable.
fn appendJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try out.append(allocator, '"');
    var index: usize = 0;
    while (index < value.len) {
        const byte = value[index];
        switch (byte) {
            '"' => {
                try out.appendSlice(allocator, "\\\"");
                index += 1;
            },
            '\\' => {
                try out.appendSlice(allocator, "\\\\");
                index += 1;
            },
            '\n' => {
                try out.appendSlice(allocator, "\\n");
                index += 1;
            },
            '\r' => {
                try out.appendSlice(allocator, "\\r");
                index += 1;
            },
            '\t' => {
                try out.appendSlice(allocator, "\\t");
                index += 1;
            },
            0x08 => {
                try out.appendSlice(allocator, "\\b");
                index += 1;
            },
            0x0C => {
                try out.appendSlice(allocator, "\\f");
                index += 1;
            },
            0...7, 0x0B, 0x0E...0x1F => {
                try appendFmt(out, allocator, "\\u{x:0>4}", .{byte});
                index += 1;
            },
            // Printable ASCII minus the quote (0x22) and backslash (0x5C), which the
            // cases above already handled.
            0x20...0x21, 0x23...0x5B, 0x5D...0x7F => {
                try out.append(allocator, byte);
                index += 1;
            },
            else => {
                // A multi-byte sequence is copied only if it is well-formed; anything
                // else becomes the replacement character, one per offending byte, so
                // the value's length still reflects that bytes were there.
                const sequence_len = std.unicode.utf8ByteSequenceLength(byte) catch {
                    try out.appendSlice(allocator, "\u{fffd}");
                    index += 1;
                    continue;
                };
                if (index + sequence_len > value.len or
                    !std.unicode.utf8ValidateSlice(value[index..][0..sequence_len]))
                {
                    try out.appendSlice(allocator, "\u{fffd}");
                    index += 1;
                    continue;
                }
                try out.appendSlice(allocator, value[index..][0..sequence_len]);
                index += sequence_len;
            },
        }
    }
    try out.append(allocator, '"');
}

fn appendFmt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const rendered = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(rendered);
    try out.appendSlice(allocator, rendered);
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

fn serialize(allocator: std.mem.Allocator, record: AuditRecord, parts: Parts) ![]u8 {
    var buffer: std.ArrayList(u8) = .empty;
    errdefer buffer.deinit(allocator);
    try writeSerial(&buffer, allocator, record, parts);
    return buffer.toOwnedSlice(allocator);
}

test "the UTC timestamp matches the Apache/ModSecurity layout" {
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(testing.allocator);
    // 2021-07-15 13:14:15 UTC = 1626354855.
    try writeTimestamp(&buffer, testing.allocator, 1626354855);
    try testing.expectEqualStrings("[15/Jul/2021:13:14:15 +0000]", buffer.items);
}

test "part letters build the expected selection" {
    const parts = Parts.fromLetters("ABFHZ");
    try testing.expect(parts.has('A'));
    try testing.expect(parts.has('B'));
    try testing.expect(parts.has('F'));
    try testing.expect(parts.has('H'));
    try testing.expect(parts.has('Z'));
    try testing.expect(!parts.has('C'));
    try testing.expect(!parts.has('E'));
}

test "a serial record renders A/B/F/H/Z sections in order" {
    const record: AuditRecord = .{
        .boundary = "abc123",
        .timestamp = 1626354855,
        .unique_id = "zigwaf-xyz",
        .client_ip = "192.0.2.10",
        .client_port = 44321,
        .server_ip = "198.51.100.5",
        .server_port = 443,
        .method = "POST",
        .uri = "/login",
        .http_version = "1.1",
        .request_headers = &.{
            .{ .name = "Host", .value = "example.com" },
            .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
        },
        .response_status = 403,
        .response_headers = &.{.{ .name = "Content-Type", .value = "text/html" }},
        .messages = &.{"[id \"942100\"] SQL injection detected"},
    };
    const parts = Parts.fromLetters("ABFHZ");
    const out = try serialize(testing.allocator, record, parts);
    defer testing.allocator.free(out);

    const expected =
        "--abc123-A--\n" ++
        "[15/Jul/2021:13:14:15 +0000] zigwaf-xyz 192.0.2.10 44321 198.51.100.5 443\n" ++
        "--abc123-B--\n" ++
        "POST /login HTTP/1.1\n" ++
        "Host: example.com\n" ++
        "Content-Type: application/x-www-form-urlencoded\n" ++
        "\n" ++
        "--abc123-F--\n" ++
        "HTTP/1.1 403\n" ++
        "Content-Type: text/html\n" ++
        "\n" ++
        "--abc123-H--\n" ++
        "[id \"942100\"] SQL injection detected\n" ++
        "Producer: zig-waf.\n" ++
        "\n" ++
        // ModSecurity terminates the record with a blank line after Z.
        "--abc123-Z--\n\n";
    try testing.expectEqualStrings(expected, out);
}

test "request and response bodies render only when part and content are present" {
    const record: AuditRecord = .{
        .boundary = "b",
        .timestamp = 0,
        .unique_id = "id",
        .client_ip = "1.1.1.1",
        .client_port = 1,
        .server_ip = "2.2.2.2",
        .server_port = 2,
        .method = "POST",
        .uri = "/",
        .http_version = "1.1",
        .request_body = "a=1&b=2",
        .response_body = "", // empty body: section suppressed even when selected
    };
    const out = try serialize(testing.allocator, record, Parts.fromLetters("CEZ"));
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "--b-C--\na=1&b=2\n\n") != null);
    // Empty response body → no E section.
    try testing.expect(std.mem.indexOf(u8, out, "--b-E--") == null);
}

fn serializeJson(allocator: std.mem.Allocator, record: AuditRecord, parts: Parts) ![]u8 {
    var buffer: std.ArrayList(u8) = .empty;
    errdefer buffer.deinit(allocator);
    try writeJson(&buffer, allocator, record, parts);
    return buffer.toOwnedSlice(allocator);
}

test "the JSON format parses back into the expected structure" {
    const record: AuditRecord = .{
        .boundary = "b",
        .timestamp = 1626354855,
        .timestamp_string = "15/Jul/2021:13:14:15",
        .unique_id = "zigwaf-xyz",
        .client_ip = "192.0.2.10",
        .client_port = 44321,
        .server_ip = "198.51.100.5",
        .server_port = 443,
        .method = "POST",
        .uri = "/login",
        .http_version = "1.1",
        .request_headers = &.{
            .{ .name = "Host", .value = "example.com" },
            .{ .name = "Accept", .value = "a" },
            .{ .name = "Accept", .value = "b" },
        },
        .request_body = "user=alice&pw=\"x\"",
        .response_status = 403,
        .response_headers = &.{.{ .name = "Content-Type", .value = "text/html" }},
        .response_body = "denied",
        .messages = &.{ "rule 942100", "rule 949110" },
        .is_interrupted = true,
    };
    const out = try serializeJson(testing.allocator, record, Parts.fromLetters("ABCEFHZ"));
    defer testing.allocator.free(out);

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out, .{});
    defer parsed.deinit();
    const tx = parsed.value.object.get("transaction").?.object;
    try testing.expectEqualStrings("zigwaf-xyz", tx.get("id").?.string);
    try testing.expectEqual(@as(i64, 44321), tx.get("client_port").?.integer);
    try testing.expectEqual(@as(i64, 1626354855), tx.get("unix_timestamp").?.integer);
    try testing.expect(tx.get("is_interrupted").?.bool);

    const req = tx.get("request").?.object;
    try testing.expectEqualStrings("POST", req.get("method").?.string);
    // The escaped body round-trips exactly.
    try testing.expectEqualStrings("user=alice&pw=\"x\"", req.get("body").?.string);
    // Repeated header names group into a single array.
    const accept = req.get("headers").?.object.get("Accept").?.array;
    try testing.expectEqual(@as(usize, 2), accept.items.len);
    try testing.expectEqualStrings("b", accept.items[1].string);

    const res = tx.get("response").?.object;
    try testing.expectEqual(@as(i64, 403), res.get("status").?.integer);
    try testing.expectEqualStrings("denied", res.get("body").?.string);

    const messages = parsed.value.object.get("messages").?.array;
    try testing.expectEqual(@as(usize, 2), messages.items.len);
    try testing.expectEqualStrings("rule 942100", messages.items[0].object.get("message").?.string);
}

test "the legacy JSON format joins repeated headers and uses remote_/local_ naming" {
    const record: AuditRecord = .{
        .boundary = "b",
        .timestamp = 1626354855,
        .timestamp_string = "15/Jul/2021:13:14:15",
        .unique_id = "id-1",
        .client_ip = "192.0.2.10",
        .client_port = 5000,
        .server_ip = "198.51.100.5",
        .server_port = 443,
        .method = "GET",
        .uri = "/",
        .http_version = "1.1",
        .request_headers = &.{
            .{ .name = "Accept", .value = "a" },
            .{ .name = "Accept", .value = "b" },
        },
        .response_status = 200,
        .messages = &.{"m1"},
        .rule_engine = "DetectionOnly",
    };
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(testing.allocator);
    try writeLegacyJson(&buffer, testing.allocator, record, Parts.fromLetters("ABFHZ"));

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buffer.items, .{});
    defer parsed.deinit();
    const tx = parsed.value.object.get("transaction").?.object;
    try testing.expectEqualStrings("192.0.2.10", tx.get("remote_address").?.string);
    try testing.expectEqual(@as(i64, 5000), tx.get("remote_port").?.integer);
    try testing.expectEqualStrings("198.51.100.5", tx.get("local_address").?.string);
    const req = parsed.value.object.get("request").?.object;
    try testing.expectEqualStrings("GET / HTTP/1.1", req.get("request_line").?.string);
    // Repeated header values join into one string.
    try testing.expectEqualStrings("a, b", req.get("headers").?.object.get("Accept").?.string);
    const audit_data = parsed.value.object.get("audit_data").?.object;
    try testing.expectEqualStrings("DetectionOnly", audit_data.get("engine_mode").?.string);
    try testing.expectEqualStrings("m1", audit_data.get("messages").?.array.items[0].string);
}

test "the OCSF format emits a Web Resources Activity event" {
    const record: AuditRecord = .{
        .boundary = "b",
        .timestamp = 1626354855,
        .unique_id = "tx-9",
        .client_ip = "192.0.2.10",
        .client_port = 5000,
        .server_ip = "198.51.100.5",
        .server_port = 443,
        .method = "POST",
        .uri = "/login",
        .http_version = "1.1",
        .request_headers = &.{
            .{ .name = "User-Agent", .value = "curl/8" },
            .{ .name = "Host", .value = "example.com" },
        },
        .response_status = 403,
        .messages = &.{"SQLi at 942100"},
        .is_interrupted = true,
        .highest_severity = "CRITICAL",
        .server_id = "node-1",
        .request_length = 42,
    };
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(testing.allocator);
    try writeOcsf(&buffer, testing.allocator, record, Parts.fromLetters("ABFHZ"));

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buffer.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try testing.expectEqual(@as(i64, 6004), obj.get("class_uid").?.integer);
    try testing.expectEqual(@as(i64, 600401), obj.get("type_uid").?.integer);
    // Interrupted → Denied.
    try testing.expectEqual(@as(i64, 2), obj.get("action_id").?.integer);
    try testing.expectEqualStrings("Denied", obj.get("action").?.string);
    const req = obj.get("http_request").?.object;
    try testing.expectEqualStrings("POST", req.get("http_method").?.string);
    try testing.expectEqualStrings("curl/8", req.get("user_agent").?.string);
    try testing.expectEqual(@as(i64, 42), req.get("length").?.integer);
    try testing.expectEqualStrings("/login", req.get("url").?.object.get("url_string").?.string);
    try testing.expectEqual(@as(i64, 403), obj.get("http_response").?.object.get("code").?.integer);
    try testing.expectEqualStrings("192.0.2.10", obj.get("src_endpoint").?.object.get("ip").?.string);
    try testing.expectEqualStrings("CRITICAL", obj.get("severity").?.string);
    try testing.expectEqualStrings("SQLi at 942100", obj.get("message").?.string);
    try testing.expectEqualStrings("node-1", obj.get("observables").?.array.items[0].object.get("value").?.string);
}

test "JSON body fields are suppressed when their part is not selected" {
    const record: AuditRecord = .{
        .boundary = "b",
        .timestamp = 0,
        .unique_id = "id",
        .client_ip = "1.1.1.1",
        .client_port = 1,
        .server_ip = "2.2.2.2",
        .server_port = 2,
        .method = "GET",
        .uri = "/",
        .http_version = "1.1",
        .request_body = "secret",
        .response_body = "hidden",
    };
    // No C/E parts → bodies must be empty in the JSON.
    const out = try serializeJson(testing.allocator, record, Parts.fromLetters("ABFHZ"));
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "secret") == null);
    try testing.expect(std.mem.indexOf(u8, out, "hidden") == null);
}

test "selected reserved parts emit empty markers" {
    const record: AuditRecord = .{
        .boundary = "x",
        .timestamp = 0,
        .unique_id = "id",
        .client_ip = "1.1.1.1",
        .client_port = 1,
        .server_ip = "2.2.2.2",
        .server_port = 2,
        .method = "GET",
        .uri = "/",
        .http_version = "1.1",
    };
    const out = try serialize(testing.allocator, record, Parts.fromLetters("DKZ"));
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "--x-D--\n\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "--x-K--\n\n") != null);
    try testing.expect(std.mem.endsWith(u8, out, "--x-Z--\n\n"));
}

test "serializers survive tricky bytes and JSON formats stay parseable" {
    // Feed escaping-hostile ASCII (quotes, backslashes, control chars, slashes)
    // through every string field. The JSON-family formats must always emit
    // parseable JSON — a strong oracle for escaping correctness — and no format
    // may crash or leak. Bytes stay within ASCII so any invalid-JSON output is a
    // real escaping defect, not an invalid-UTF-8 input artifact.
    var prng = std.Random.DefaultPrng.init(0xA11D_0FF5_E7C0);
    const random = prng.random();
    var buffers: [12][40]u8 = undefined;
    var iteration: usize = 0;
    while (iteration < 2000) : (iteration += 1) {
        var strings: [12][]const u8 = undefined;
        for (&buffers, &strings) |*buffer, *string| {
            const len = random.uintLessThan(usize, buffer.len + 1);
            for (buffer[0..len]) |*byte| {
                byte.* = switch (random.uintLessThan(u8, 12)) {
                    0 => '"',
                    1 => '\\',
                    2 => '\n',
                    3 => '\r',
                    4 => '\t',
                    5 => 0x00,
                    6 => 0x1f,
                    7 => '/',
                    else => @as(u8, @intCast(0x20 + random.uintLessThan(u8, 0x5f))), // printable ASCII
                };
            }
            string.* = buffer[0..len];
        }
        var request_headers = [_]Header{.{ .name = strings[8], .value = strings[9] }};
        var response_headers = [_]Header{.{ .name = strings[10], .value = strings[11] }};
        var messages = [_][]const u8{ strings[6], strings[7] };
        const record: AuditRecord = .{
            .boundary = strings[0],
            .timestamp = 1700000000,
            .unique_id = strings[1],
            .client_ip = "192.0.2.1",
            .client_port = 1234,
            .server_ip = "198.51.100.1",
            .server_port = 443,
            .method = strings[2],
            .uri = strings[3],
            .http_version = strings[4],
            .request_headers = &request_headers,
            .request_body = strings[5],
            .response_status = 200,
            .response_headers = &response_headers,
            .response_body = strings[5],
            .messages = &messages,
            .rule_engine = strings[0],
            .version = strings[1],
            .server_id = strings[2],
        };
        const parts = Parts.fromLetters("ABCEFHKZ");
        inline for (.{ Format.serial, Format.json, Format.legacy_json, Format.ocsf }) |format| {
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(testing.allocator);
            try write(&out, testing.allocator, record, parts, format);
            if (format != .serial) {
                var parsed = std.json.parseFromSlice(std.json.Value, testing.allocator, out.items, .{}) catch {
                    return error.SerializerEmittedInvalidJson;
                };
                parsed.deinit();
            }
        }
    }
}

test "a request that is not UTF-8 still produces parseable JSON" {
    // A URI, header, or body is not required to be UTF-8 and an attacker chooses its
    // bytes; a JSON string is required to be UTF-8. Copying the bytes through
    // produced a document a log consumer could not parse — letting a request make
    // the record of its own attack unreadable. Found by `zig build fuzz-audit`.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    // A lone continuation byte, a truncated sequence, and an overlong-looking lead.
    try appendJsonString(&out, testing.allocator, "a\x80b\xC3z\xF0\x9F");
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.items, .{});
    defer parsed.deinit();
    try testing.expect(std.mem.indexOf(u8, parsed.value.string, "a") != null);
    try testing.expect(std.mem.indexOf(u8, parsed.value.string, "\u{fffd}") != null);

    // Well-formed multi-byte text is preserved exactly rather than being mangled by
    // the same pass.
    out.clearRetainingCapacity();
    try appendJsonString(&out, testing.allocator, "naïve → 日本語");
    var kept = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.items, .{});
    defer kept.deinit();
    try testing.expectEqualStrings("naïve → 日本語", kept.value.string);

    // And the escapes that were already correct still are.
    out.clearRetainingCapacity();
    try appendJsonString(&out, testing.allocator, "quote\" back\\ tab\t null\x00");
    var escaped = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.items, .{});
    defer escaped.deinit();
    try testing.expectEqualStrings("quote\" back\\ tab\t null\x00", escaped.value.string);
}
