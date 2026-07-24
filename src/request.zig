//! Request-target parsing: query-string arguments and cookies with the pinned
//! Coraza `application/x-www-form-urlencoded` decoding. Parsing borrows the
//! input; decoding writes into a caller buffer, so the request path performs no
//! implicit allocation and no blocking I/O.

const std = @import("std");

/// The default query-string argument separator. ModSecurity exposes it through
/// `SecArgumentSeparator`; Coraza defaults to `&`.
pub const default_separator: u8 = '&';

pub const Pair = struct {
    key: []const u8,
    value: []const u8,
};

/// Iterates raw (undecoded) query-string arguments exactly like Coraza
/// `doParseQuery`: split on the separator, skip empty segments, and split each
/// segment on its first `=` (a segment with no `=` has an empty value).
pub const QueryIterator = struct {
    rest: []const u8,
    separator: u8,

    pub fn next(self: *QueryIterator) ?Pair {
        while (self.rest.len != 0) {
            var segment = self.rest;
            if (std.mem.indexOfScalar(u8, segment, self.separator)) |i| {
                segment = self.rest[0..i];
                self.rest = self.rest[i + 1 ..];
            } else {
                self.rest = "";
            }
            if (segment.len == 0) continue;
            if (std.mem.indexOfScalar(u8, segment, '=')) |i| {
                return .{ .key = segment[0..i], .value = segment[i + 1 ..] };
            }
            return .{ .key = segment, .value = "" };
        }
        return null;
    }
};

pub fn parseQuery(query: []const u8, separator: u8) QueryIterator {
    return .{ .rest = query, .separator = separator };
}

/// Decode one `x-www-form-urlencoded` token into `dest`, which must be at least
/// `input.len` bytes; the decoded slice is never longer than the input. `+`
/// becomes a space, `%XX` decodes a byte, and a malformed or truncated `%` is
/// preserved literally, matching the pinned Coraza `queryUnescape`.
pub fn queryUnescape(dest: []u8, input: []const u8) []u8 {
    std.debug.assert(dest.len >= input.len);
    var out: usize = 0;
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const ci = input[i];
        if (ci == '+') {
            dest[out] = ' ';
            out += 1;
            continue;
        }
        if (ci == '%') {
            // Coraza requires both hex digits in range; otherwise the `%` is
            // preserved literally.
            if (i + 2 >= input.len) {
                dest[out] = '%';
                out += 1;
                continue;
            }
            const hi = hexDigit(input[i + 1]);
            const lo = hexDigit(input[i + 2]);
            if (hi == null or lo == null) {
                dest[out] = '%';
                out += 1;
                continue;
            }
            dest[out] = (hi.? << 4) | lo.?;
            out += 1;
            i += 2;
            continue;
        }
        dest[out] = ci;
        out += 1;
    }
    return dest[0..out];
}

fn hexDigit(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

/// Iterates raw cookies from a `Cookie:` header value in the Netscape format:
/// `name=value` pairs separated by `;`, with optional surrounding spaces. A
/// pair with no `=` yields an empty value; a leading `$`-prefixed attribute is
/// preserved as an ordinary cookie, matching ModSecurity's byte-oriented split.
pub const CookieIterator = struct {
    rest: []const u8,

    pub fn next(self: *CookieIterator) ?Pair {
        while (self.rest.len != 0) {
            var segment = self.rest;
            if (std.mem.indexOfScalar(u8, segment, ';')) |i| {
                segment = self.rest[0..i];
                self.rest = self.rest[i + 1 ..];
            } else {
                self.rest = "";
            }
            segment = std.mem.trim(u8, segment, " \t");
            if (segment.len == 0) continue;
            if (std.mem.indexOfScalar(u8, segment, '=')) |i| {
                return .{ .key = segment[0..i], .value = segment[i + 1 ..] };
            }
            return .{ .key = segment, .value = "" };
        }
        return null;
    }
};

pub fn parseCookies(header: []const u8) CookieIterator {
    return .{ .rest = header };
}

test "query parsing splits, skips empty segments, and decodes" {
    var it = parseQuery("a=1&b=two&&c&d=%41%42+z", default_separator);
    var buffer: [64]u8 = undefined;

    const a = it.next().?;
    try std.testing.expectEqualStrings("a", a.key);
    try std.testing.expectEqualStrings("1", a.value);

    const b = it.next().?;
    try std.testing.expectEqualStrings("b", b.key);
    try std.testing.expectEqualStrings("two", b.value);

    // The empty segment between && is skipped; `c` has no `=`, so an empty value.
    const c = it.next().?;
    try std.testing.expectEqualStrings("c", c.key);
    try std.testing.expectEqualStrings("", c.value);

    const d = it.next().?;
    try std.testing.expectEqualStrings("d", d.key);
    try std.testing.expectEqualStrings("AB z", queryUnescape(&buffer, d.value));

    try std.testing.expect(it.next() == null);
}

test "query decoding preserves malformed and truncated percent escapes" {
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings("a%zzb", queryUnescape(&buffer, "a%zzb"));
    try std.testing.expectEqualStrings("end%", queryUnescape(&buffer, "end%"));
    try std.testing.expectEqualStrings("end%4", queryUnescape(&buffer, "end%4"));
    try std.testing.expectEqualStrings("a b", queryUnescape(&buffer, "a+b"));
    try std.testing.expectEqualStrings("\x00\xff", queryUnescape(&buffer, "%00%ff"));
}

test "custom separator parses semicolon-delimited queries" {
    var it = parseQuery("a=1;b=2", ';');
    try std.testing.expectEqualStrings("1", it.next().?.value);
    try std.testing.expectEqualStrings("2", it.next().?.value);
    try std.testing.expect(it.next() == null);
}

test "cookie parsing splits on semicolons and trims spaces" {
    var it = parseCookies("SESSION=abc; theme=dark ; flag");
    const first = it.next().?;
    try std.testing.expectEqualStrings("SESSION", first.key);
    try std.testing.expectEqualStrings("abc", first.value);
    const second = it.next().?;
    try std.testing.expectEqualStrings("theme", second.key);
    try std.testing.expectEqualStrings("dark", second.value);
    const third = it.next().?;
    try std.testing.expectEqualStrings("flag", third.key);
    try std.testing.expectEqualStrings("", third.value);
    try std.testing.expect(it.next() == null);
}
