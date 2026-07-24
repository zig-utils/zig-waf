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
