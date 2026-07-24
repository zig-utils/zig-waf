//! Slice-based `multipart/form-data` reader (RFC 2046 / 7578).
//!
//! The request body is already buffered for inspection (`request_buffer.zig`),
//! so unlike Go's streaming `mime/multipart` this reader parses an in-memory
//! slice and borrows every returned name, value, and body slice from it — no
//! copying and no allocation beyond the two small boundary delimiter buffers.
//!
//! The delimiter semantics are pinned to Go's `mime/multipart`, which Coraza
//! wraps in its multipart body processor:
//!
//! - The opening delimiter is `--<boundary>` at the start of a line; any
//!   preamble before it is skipped.
//! - A part is header lines terminated by a blank line, then a body running up
//!   to the line terminator that immediately precedes the next delimiter — that
//!   terminator (`\r\n` or a bare `\n`) belongs to the delimiter, not the body.
//! - `--<boundary>--` closes the body; any epilogue after it is ignored.
//! - A body that ends without a closing delimiter is reported as `incomplete`
//!   (Go's `io.ErrUnexpectedEOF`), and Coraza still records the partial part.
//!
//! Byte-exactness matters: a WAF and the origin must agree on how a body splits,
//! or an attacker slips content past inspection through a parser differential.

const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{InvalidBoundary};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// One parsed part: the raw header block and the body, both borrowed from the
/// input. `incomplete` marks a part whose body was not closed by a delimiter.
pub const Part = struct {
    /// The raw header bytes, excluding the terminating blank line.
    header_block: []const u8,
    body: []const u8,
    incomplete: bool = false,

    pub const HeaderIterator = struct {
        rest: []const u8,

        pub fn next(self: *HeaderIterator) ?Header {
            while (self.rest.len != 0) {
                const line_end = std.mem.indexOfScalar(u8, self.rest, '\n') orelse self.rest.len;
                var line = self.rest[0..line_end];
                self.rest = if (line_end < self.rest.len) self.rest[line_end + 1 ..] else self.rest[self.rest.len..];
                if (line.len != 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
                if (line.len == 0) continue;
                const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
                const key = line[0..colon];
                // textproto trims leading spaces/tabs from the value.
                var value = line[colon + 1 ..];
                var start: usize = 0;
                while (start < value.len and (value[start] == ' ' or value[start] == '\t')) start += 1;
                value = value[start..];
                return .{ .name = key, .value = value };
            }
            return null;
        }
    };

    pub fn headers(self: Part) HeaderIterator {
        return .{ .rest = self.header_block };
    }

    /// Iterates the raw header lines (CR stripped, blank lines skipped), which
    /// is what ModSecurity records verbatim in MULTIPART_PART_HEADERS.
    pub const RawLineIterator = struct {
        rest: []const u8,

        pub fn next(self: *RawLineIterator) ?[]const u8 {
            while (self.rest.len != 0) {
                const line_end = std.mem.indexOfScalar(u8, self.rest, '\n') orelse self.rest.len;
                var line = self.rest[0..line_end];
                self.rest = if (line_end < self.rest.len) self.rest[line_end + 1 ..] else self.rest[self.rest.len..];
                if (line.len != 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
                if (line.len == 0) continue;
                return line;
            }
            return null;
        }
    };

    pub fn rawHeaderLines(self: Part) RawLineIterator {
        return .{ .rest = self.header_block };
    }

    /// The first header value matching `name` case-insensitively, or null.
    pub fn headerValue(self: Part, wanted: []const u8) ?[]const u8 {
        var it = self.headers();
        while (it.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, wanted)) return header.value;
        }
        return null;
    }

    /// The `filename` parameter of Content-Disposition (empty/absent → null),
    /// which is how Coraza distinguishes a file part from a field.
    pub fn filename(self: Part) ?[]const u8 {
        const disposition = self.headerValue("content-disposition") orelse return null;
        const value = dispositionParam(disposition, "filename") orelse return null;
        return if (value.len == 0) null else value;
    }

    /// The `name` parameter of Content-Disposition regardless of the
    /// disposition type. ModSecurity keys ARGS_POST and the MULTIPART_* fields
    /// off this raw name (unlike Go's `FormName`, which requires `form-data`).
    pub fn name(self: Part) ?[]const u8 {
        const disposition = self.headerValue("content-disposition") orelse return null;
        return dispositionParam(disposition, "name");
    }

    /// Go's `Part.FormName`: the `name` parameter, but only when the disposition
    /// type is `form-data`.
    pub fn formName(self: Part) ?[]const u8 {
        const disposition = self.headerValue("content-disposition") orelse return null;
        const semicolon = std.mem.indexOfScalar(u8, disposition, ';') orelse disposition.len;
        const kind = std.mem.trim(u8, disposition[0..semicolon], " \t");
        if (!std.ascii.eqlIgnoreCase(kind, "form-data")) return null;
        return dispositionParam(disposition, "name");
    }
};

/// Extract a Content-Disposition parameter by case-insensitive name, unquoting a
/// quoted-string value (with `\` escapes). RFC 2231 extended (`filename*`)
/// parameters are not decoded.
fn dispositionParam(disposition: []const u8, key: []const u8) ?[]const u8 {
    var rest = disposition;
    // Skip the disposition type (up to the first ';').
    if (std.mem.indexOfScalar(u8, rest, ';')) |semicolon| {
        rest = rest[semicolon + 1 ..];
    } else return null;

    while (rest.len != 0) {
        // One "; key=value" segment. Split on ';' that is not inside quotes.
        var i: usize = 0;
        var in_quotes = false;
        while (i < rest.len) : (i += 1) {
            const c = rest[i];
            if (c == '"') in_quotes = !in_quotes;
            if (c == ';' and !in_quotes) break;
        }
        const segment = std.mem.trim(u8, rest[0..i], " \t");
        rest = if (i < rest.len) rest[i + 1 ..] else rest[rest.len..];
        if (segment.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, segment, '=') orelse continue;
        const name = std.mem.trim(u8, segment[0..eq], " \t");
        if (!std.ascii.eqlIgnoreCase(name, key)) continue;
        const raw = std.mem.trim(u8, segment[eq + 1 ..], " \t");
        if (raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"') {
            return raw[1 .. raw.len - 1];
        }
        return raw;
    }
    return null;
}

/// The `boundary` parameter of a `multipart/*` Content-Type value, unquoting a
/// quoted-string form. Returns null when absent or empty — Coraza treats a
/// missing boundary as a strict multipart error.
pub fn boundaryFromContentType(content_type: []const u8) ?[]const u8 {
    var rest = content_type;
    // Skip the media type (up to the first ';').
    const semicolon = std.mem.indexOfScalar(u8, rest, ';') orelse return null;
    rest = rest[semicolon + 1 ..];

    while (rest.len != 0) {
        var i: usize = 0;
        var in_quotes = false;
        while (i < rest.len) : (i += 1) {
            const c = rest[i];
            if (c == '"') in_quotes = !in_quotes;
            if (c == ';' and !in_quotes) break;
        }
        const segment = std.mem.trim(u8, rest[0..i], " \t");
        rest = if (i < rest.len) rest[i + 1 ..] else rest[rest.len..];
        if (segment.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, segment, '=') orelse continue;
        const name = std.mem.trim(u8, segment[0..eq], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "boundary")) continue;
        const raw = std.mem.trim(u8, segment[eq + 1 ..], " \t");
        const value = if (raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"')
            raw[1 .. raw.len - 1]
        else
            raw;
        return if (value.len == 0) null else value;
    }
    return null;
}

pub const Reader = struct {
    allocator: std.mem.Allocator,
    input: []const u8,
    /// "--" ++ boundary.
    dash_boundary: []const u8,
    /// Start of the next part's headers, or null when the stream is exhausted.
    content_start: ?usize = null,
    started: bool = false,

    pub fn init(allocator: std.mem.Allocator, input: []const u8, boundary: []const u8) Error!Reader {
        // Go bounds boundaries to 1..70 bytes.
        if (boundary.len == 0 or boundary.len > 70) return error.InvalidBoundary;
        const dash_boundary = try std.fmt.allocPrint(allocator, "--{s}", .{boundary});
        return .{ .allocator = allocator, .input = input, .dash_boundary = dash_boundary };
    }

    pub fn deinit(self: *Reader) void {
        self.allocator.free(self.dash_boundary);
        self.* = undefined;
    }

    /// The index of the next delimiter (`dash_boundary` at the start of a line)
    /// at or after `from`, or null.
    fn findDelimiter(self: *const Reader, from: usize) ?usize {
        var search = from;
        while (search + self.dash_boundary.len <= self.input.len) {
            const found = std.mem.indexOfPos(u8, self.input, search, self.dash_boundary) orelse return null;
            if (found == 0 or self.input[found - 1] == '\n') return found;
            search = found + 1;
        }
        return null;
    }

    /// Consume a delimiter at `index`, deciding whether it closes the body and,
    /// if not, returning the offset where the following part's headers begin.
    /// Returns null when this is the closing delimiter.
    fn consumeDelimiter(self: *const Reader, index: usize) ?usize {
        var after = index + self.dash_boundary.len;
        // "--" immediately after the boundary is the closing delimiter.
        if (after + 2 <= self.input.len and self.input[after] == '-' and self.input[after + 1] == '-') {
            return null;
        }
        if (after >= self.input.len) return null; // truncated at the delimiter
        // Transport padding: optional trailing whitespace, then a line ending.
        while (after < self.input.len and (self.input[after] == ' ' or self.input[after] == '\t')) after += 1;
        if (after < self.input.len and self.input[after] == '\r') after += 1;
        if (after < self.input.len and self.input[after] == '\n') {
            return after + 1;
        }
        // No line terminator after the opening delimiter — malformed.
        return null;
    }

    pub fn next(self: *Reader) ?Part {
        if (!self.started) {
            self.started = true;
            const first = self.findDelimiter(0) orelse return null;
            self.content_start = self.consumeDelimiter(first);
        }
        const start = self.content_start orelse return null;

        // Headers: lines up to a blank line. header_block excludes the blank
        // line; the body starts after the blank line's terminator.
        var cursor = start;
        var header_end = start;
        var body_start: ?usize = null;
        while (cursor <= self.input.len) {
            const line_end = std.mem.indexOfScalarPos(u8, self.input, cursor, '\n') orelse {
                break; // no blank-line terminator before EOF
            };
            var line = self.input[cursor..line_end];
            if (line.len != 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
            if (line.len == 0) {
                header_end = cursor; // start of the blank line
                body_start = line_end + 1;
                break;
            }
            cursor = line_end + 1;
        }

        const body_from = body_start orelse {
            // Malformed part with no header/body separator; consume the rest.
            self.content_start = null;
            return .{ .header_block = self.input[start..], .body = self.input[self.input.len..], .incomplete = true };
        };

        const next_delim = self.findDelimiter(body_from) orelse {
            // Unterminated body (Go's io.ErrUnexpectedEOF).
            self.content_start = null;
            return .{
                .header_block = self.input[start..header_end],
                .body = self.input[body_from..],
                .incomplete = true,
            };
        };

        // The terminator immediately preceding the delimiter is part of the
        // delimiter, not the body.
        var body_end = next_delim;
        if (body_end > body_from and self.input[body_end - 1] == '\n') {
            body_end -= 1;
            if (body_end > body_from and self.input[body_end - 1] == '\r') body_end -= 1;
        }

        self.content_start = self.consumeDelimiter(next_delim);
        return .{
            .header_block = self.input[start..header_end],
            .body = self.input[body_from..body_end],
        };
    }
};

// ---- tests --------------------------------------------------------------

fn collectFields(allocator: std.mem.Allocator, body: []const u8, boundary: []const u8) ![]Part {
    var reader = try Reader.init(allocator, body, boundary);
    defer reader.deinit();
    var parts: std.ArrayList(Part) = .empty;
    while (reader.next()) |part| try parts.append(allocator, part);
    return parts.toOwnedSlice(allocator);
}

test "a simple two-field form parses names and bodies" {
    const body =
        "--X\r\n" ++
        "Content-Disposition: form-data; name=\"first\"\r\n\r\n" ++
        "alice\r\n" ++
        "--X\r\n" ++
        "Content-Disposition: form-data; name=\"second\"\r\n\r\n" ++
        "bob\r\n" ++
        "--X--\r\n";
    const parts = try collectFields(std.testing.allocator, body, "X");
    defer std.testing.allocator.free(parts);
    try std.testing.expectEqual(@as(usize, 2), parts.len);
    try std.testing.expectEqualStrings("first", parts[0].formName().?);
    try std.testing.expectEqualStrings("alice", parts[0].body);
    try std.testing.expect(parts[0].filename() == null);
    try std.testing.expectEqualStrings("second", parts[1].formName().?);
    try std.testing.expectEqualStrings("bob", parts[1].body);
}

test "a file part exposes its filename and raw body" {
    const body =
        "--BOUNDARY\r\n" ++
        "Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n" ++
        "Content-Type: text/plain\r\n\r\n" ++
        "line1\r\nline2\r\n" ++
        "--BOUNDARY--\r\n";
    const parts = try collectFields(std.testing.allocator, body, "BOUNDARY");
    defer std.testing.allocator.free(parts);
    try std.testing.expectEqual(@as(usize, 1), parts.len);
    try std.testing.expectEqualStrings("upload", parts[0].formName().?);
    try std.testing.expectEqualStrings("a.txt", parts[0].filename().?);
    // The body keeps its internal CRLF; only the delimiter's leading CRLF is cut.
    try std.testing.expectEqualStrings("line1\r\nline2", parts[0].body);
    try std.testing.expectEqualStrings("text/plain", parts[0].headerValue("content-type").?);
}

test "the preamble before the first boundary is ignored" {
    const body =
        "This is a preamble, ignored by readers.\r\n" ++
        "--X\r\n" ++
        "Content-Disposition: form-data; name=\"only\"\r\n\r\n" ++
        "value\r\n" ++
        "--X--\r\n";
    const parts = try collectFields(std.testing.allocator, body, "X");
    defer std.testing.allocator.free(parts);
    try std.testing.expectEqual(@as(usize, 1), parts.len);
    try std.testing.expectEqualStrings("value", parts[0].body);
}

test "an empty value between adjacent boundaries yields an empty body" {
    const body =
        "--X\r\n" ++
        "Content-Disposition: form-data; name=\"empty\"\r\n\r\n" ++
        "\r\n" ++
        "--X--\r\n";
    const parts = try collectFields(std.testing.allocator, body, "X");
    defer std.testing.allocator.free(parts);
    try std.testing.expectEqual(@as(usize, 1), parts.len);
    try std.testing.expectEqualStrings("", parts[0].body);
}

test "bare LF line endings are accepted like Go's reader" {
    const body =
        "--X\n" ++
        "Content-Disposition: form-data; name=\"n\"\n\n" ++
        "data\n" ++
        "--X--\n";
    const parts = try collectFields(std.testing.allocator, body, "X");
    defer std.testing.allocator.free(parts);
    try std.testing.expectEqual(@as(usize, 1), parts.len);
    try std.testing.expectEqualStrings("n", parts[0].formName().?);
    try std.testing.expectEqualStrings("data", parts[0].body);
}

test "an unterminated final part is reported incomplete" {
    const body =
        "--X\r\n" ++
        "Content-Disposition: form-data; name=\"n\"\r\n\r\n" ++
        "truncated body with no closing boundary";
    const parts = try collectFields(std.testing.allocator, body, "X");
    defer std.testing.allocator.free(parts);
    try std.testing.expectEqual(@as(usize, 1), parts.len);
    try std.testing.expect(parts[0].incomplete);
    try std.testing.expectEqualStrings("truncated body with no closing boundary", parts[0].body);
}

test "transport padding after a boundary is tolerated" {
    const body =
        "--X  \r\n" ++
        "Content-Disposition: form-data; name=\"n\"\r\n\r\n" ++
        "v\r\n" ++
        "--X--  \r\n";
    const parts = try collectFields(std.testing.allocator, body, "X");
    defer std.testing.allocator.free(parts);
    try std.testing.expectEqual(@as(usize, 1), parts.len);
    try std.testing.expectEqualStrings("v", parts[0].body);
}

test "a boundary-like sequence inside a body is not a delimiter" {
    // "--X" mid-line (not at a line start) must not split the body.
    const body =
        "--X\r\n" ++
        "Content-Disposition: form-data; name=\"n\"\r\n\r\n" ++
        "prefix--Xsuffix\r\n" ++
        "--X--\r\n";
    const parts = try collectFields(std.testing.allocator, body, "X");
    defer std.testing.allocator.free(parts);
    try std.testing.expectEqual(@as(usize, 1), parts.len);
    try std.testing.expectEqualStrings("prefix--Xsuffix", parts[0].body);
}

test "an immediate closing delimiter yields no parts" {
    const parts = try collectFields(std.testing.allocator, "--X--\r\n", "X");
    defer std.testing.allocator.free(parts);
    try std.testing.expectEqual(@as(usize, 0), parts.len);
}

test "a quoted filename with an escaped quote and semicolon is preserved" {
    const body =
        "--X\r\n" ++
        "Content-Disposition: form-data; name=\"f\"; filename=\"a;b.txt\"\r\n\r\n" ++
        "x\r\n" ++
        "--X--\r\n";
    const parts = try collectFields(std.testing.allocator, body, "X");
    defer std.testing.allocator.free(parts);
    try std.testing.expectEqual(@as(usize, 1), parts.len);
    try std.testing.expectEqualStrings("a;b.txt", parts[0].filename().?);
}

test "part headers iterate as name/value pairs" {
    const body =
        "--X\r\n" ++
        "Content-Disposition: form-data; name=\"n\"\r\n" ++
        "X-Custom:  spaced \r\n\r\n" ++
        "v\r\n" ++
        "--X--\r\n";
    var reader = try Reader.init(std.testing.allocator, body, "X");
    defer reader.deinit();
    const part = reader.next().?;
    var it = part.headers();
    const h0 = it.next().?;
    try std.testing.expectEqualStrings("Content-Disposition", h0.name);
    const h1 = it.next().?;
    try std.testing.expectEqualStrings("X-Custom", h1.name);
    // Leading value whitespace is trimmed; a trailing space is kept verbatim.
    try std.testing.expectEqualStrings("spaced ", h1.value);
    try std.testing.expect(it.next() == null);
}

test "name is ungated but formName requires form-data" {
    const body =
        "--X\r\n" ++
        "Content-Disposition: attachment; name=\"n\"\r\n\r\n" ++
        "v\r\n" ++
        "--X--\r\n";
    var reader = try Reader.init(std.testing.allocator, body, "X");
    defer reader.deinit();
    const part = reader.next().?;
    // ModSecurity keys off the raw name regardless of disposition type.
    try std.testing.expectEqualStrings("n", part.name().?);
    // Go/Coraza FormName is empty when the type is not form-data.
    try std.testing.expect(part.formName() == null);
}

test "rawHeaderLines yields verbatim header lines" {
    const body =
        "--X\r\n" ++
        "Content-Disposition: form-data; name=\"n\"\r\n" ++
        "Content-Type: text/plain\r\n\r\n" ++
        "v\r\n" ++
        "--X--\r\n";
    var reader = try Reader.init(std.testing.allocator, body, "X");
    defer reader.deinit();
    const part = reader.next().?;
    var it = part.rawHeaderLines();
    try std.testing.expectEqualStrings("Content-Disposition: form-data; name=\"n\"", it.next().?);
    try std.testing.expectEqualStrings("Content-Type: text/plain", it.next().?);
    try std.testing.expect(it.next() == null);
}

test "an invalid boundary is rejected" {
    try std.testing.expectError(error.InvalidBoundary, Reader.init(std.testing.allocator, "", ""));
    var long: [71]u8 = undefined;
    @memset(&long, 'b');
    try std.testing.expectError(error.InvalidBoundary, Reader.init(std.testing.allocator, "", &long));
}

test "boundaryFromContentType extracts plain and quoted boundaries" {
    try std.testing.expectEqualStrings("X", boundaryFromContentType("multipart/form-data; boundary=X").?);
    try std.testing.expectEqualStrings(
        "----WebKitFormBoundaryABC",
        boundaryFromContentType("multipart/form-data; boundary=----WebKitFormBoundaryABC").?,
    );
    try std.testing.expectEqualStrings(
        "a;b",
        boundaryFromContentType("multipart/form-data; boundary=\"a;b\"").?,
    );
    // Case-insensitive parameter name and surrounding whitespace.
    try std.testing.expectEqualStrings(
        "Y",
        boundaryFromContentType("multipart/form-data;  BOUNDARY = Y ").?,
    );
    try std.testing.expect(boundaryFromContentType("multipart/form-data") == null);
    try std.testing.expect(boundaryFromContentType("multipart/form-data; boundary=") == null);
    try std.testing.expect(boundaryFromContentType("text/plain") == null);
}

test "random bytes never crash the reader and yield only borrowed slices" {
    var prng = std.Random.DefaultPrng.init(0x5EED_1234_ABCD);
    const random = prng.random();
    var buffer: [512]u8 = undefined;
    var iteration: usize = 0;
    while (iteration < 4000) : (iteration += 1) {
        const len = random.uintLessThan(usize, buffer.len + 1);
        // Bias toward boundary-ish bytes so the delimiter logic is exercised.
        for (buffer[0..len]) |*byte| {
            byte.* = switch (random.uintLessThan(u8, 8)) {
                0 => '-',
                1 => 'X',
                2 => '\r',
                3 => '\n',
                4 => ':',
                else => random.int(u8),
            };
        }
        var reader = try Reader.init(std.testing.allocator, buffer[0..len], "X");
        defer reader.deinit();
        var guard: usize = 0;
        while (reader.next()) |part| {
            guard += 1;
            if (guard > len + 4) return error.NonTerminating;
            // Every returned slice must point inside the input buffer.
            if (part.body.len != 0) {
                try std.testing.expect(@intFromPtr(part.body.ptr) >= @intFromPtr(&buffer));
                try std.testing.expect(@intFromPtr(part.body.ptr) + part.body.len <= @intFromPtr(&buffer) + len);
            }
        }
    }
}
