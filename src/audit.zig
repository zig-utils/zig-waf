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
};

const months = [_][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

/// Append `epoch_seconds` (UTC) as ModSecurity's audit timestamp,
/// `[dd/Mmm/yyyy:hh:mm:ss +0000]`. UTC keeps the output deterministic and free
/// of the host time-zone database.
pub fn writeTimestamp(out: *std.ArrayList(u8), allocator: std.mem.Allocator, epoch_seconds: i64) !void {
    const secs: u64 = @intCast(@max(epoch_seconds, 0));
    const epoch_day = std.time.epoch.EpochDay{ .day = @intCast(secs / std.time.epoch.secs_per_day) };
    const day_seconds = std.time.epoch.DaySeconds{ .secs = @intCast(secs % std.time.epoch.secs_per_day) };
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    try appendFmt(out, allocator, "[{d:0>2}/{s}/{d}:{d:0>2}:{d:0>2}:{d:0>2} +0000]", .{
        month_day.day_index + 1,
        months[month_day.month.numeric() - 1],
        year_day.year,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
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

/// Append `value` as a JSON string literal with the mandatory escapes.
fn appendJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try out.append(allocator, '"');
    for (value) |byte| {
        switch (byte) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            0x08 => try out.appendSlice(allocator, "\\b"),
            0x0C => try out.appendSlice(allocator, "\\f"),
            0...7, 0x0B, 0x0E...0x1F => try appendFmt(out, allocator, "\\u{x:0>4}", .{byte}),
            else => try out.append(allocator, byte),
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
