//! Executable retained upstream operator corpus evidence.

const std = @import("std");
const operators = @import("waf").operators;
const checksums = @embedFile("fixtures/operators/coraza/SHA256SUMS");

const Corpus = struct {
    name: []const u8,
    source: []const u8,
};

const corpora = [_]Corpus{
    corpus("beginsWith"),
    corpus("contains"),
    corpus("containsWord"),
    corpus("endsWith"),
    corpus("eq"),
    corpus("ge"),
    corpus("gt"),
    corpus("le"),
    corpus("lt"),
    corpus("streq"),
    corpus("strmatch"),
    corpus("within"),
};

const pm_corpus = corpus("pm");
const ip_corpus = corpus("ipMatch");
const byte_range_corpus = corpus("validateByteRange");
const utf8_corpus = corpus("validateUtf8Encoding");
const url_encoding_corpus = corpus("validateUrlEncoding");

/// Every retained fixture file, for digest pinning.
const all_files = [_]Corpus{
    corpus("beginsWith"),           corpus("contains"),            corpus("containsWord"),
    corpus("endsWith"),             corpus("eq"),                  corpus("ge"),
    corpus("gt"),                   corpus("le"),                  corpus("lt"),
    corpus("streq"),                corpus("strmatch"),            corpus("within"),
    corpus("pm"),                   corpus("ipMatch"),             corpus("validateByteRange"),
    corpus("validateUtf8Encoding"), corpus("validateUrlEncoding"),
};

fn corpus(comptime name: []const u8) Corpus {
    return .{
        .name = name,
        .source = @embedFile("fixtures/operators/coraza/" ++ name ++ ".json"),
    };
}

const Fixture = struct {
    input: []const u8,
    param: []const u8,
    ret: i64,
    name: []const u8,
    type: []const u8,
};

/// Decode the pinned Coraza fixture escaping for byte-exact inputs: a
/// backslash-u-0000 sequence becomes a NUL and a backslash-x-HH sequence
/// becomes the raw byte. Strings without such escapes return unchanged.
fn decodeFixture(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const unquote = std.mem.indexOf(u8, encoded, "\\x") != null;
    var decoded: std.ArrayList(u8) = .empty;
    errdefer decoded.deinit(allocator);
    var index: usize = 0;
    while (index < encoded.len) {
        if (std.mem.startsWith(u8, encoded[index..], "\\u0000")) {
            try decoded.append(allocator, 0);
            index += 6;
            continue;
        }
        if (unquote and encoded[index] == '\\' and index + 3 < encoded.len and encoded[index + 1] == 'x') {
            const hi = hexNibble(encoded[index + 2]);
            const lo = hexNibble(encoded[index + 3]);
            if (hi != null and lo != null) {
                try decoded.append(allocator, hi.? * 16 + lo.?);
                index += 4;
                continue;
            }
        }
        try decoded.append(allocator, encoded[index]);
        index += 1;
    }
    return decoded.toOwnedSlice(allocator);
}

fn hexNibble(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

test "retained Coraza operator fixture digests are pinned" {
    var lines = std.mem.tokenizeScalar(u8, checksums, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        try std.testing.expect(line.len > 66);
        try std.testing.expectEqualStrings("  ", line[64..66]);
        const basename = std.fs.path.basename(line[66..]);
        try std.testing.expect(std.mem.endsWith(u8, basename, ".json"));
        const name = basename[0 .. basename.len - ".json".len];
        const source = for (all_files) |candidate| {
            if (std.mem.eql(u8, candidate.name, name)) break candidate.source;
        } else return error.UnexpectedFixtureChecksum;

        var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
        const encoded = std.fmt.bytesToHex(digest, .lower);
        try std.testing.expectEqualStrings(line[0..64], &encoded);
        count += 1;
    }
    try std.testing.expectEqual(all_files.len, count);
}

test "all retained Coraza operator fixtures match evaluation" {
    var case_count: usize = 0;
    for (corpora) |source| {
        const kind = operators.resolve(source.name) orelse return error.MissingOperator;
        var parsed = try std.json.parseFromSlice([]Fixture, std.testing.allocator, source.source, .{});
        defer parsed.deinit();
        for (parsed.value) |fixture| {
            case_count += 1;
            const expected = fixture.ret == 1;
            const actual = operators.evaluate(kind, .coraza, fixture.param, fixture.input);
            std.testing.expectEqual(expected, actual) catch |err| {
                std.debug.print(
                    "Coraza operator mismatch in {s}: param={s} input={s} expected={d}\n",
                    .{ source.name, fixture.param, fixture.input, fixture.ret },
                );
                return err;
            };
        }
    }
    try std.testing.expectEqual(@as(usize, 118), case_count);
}

test "retained Coraza pm corpus matches the Aho-Corasick automaton" {
    var parsed = try std.json.parseFromSlice([]Fixture, std.testing.allocator, pm_corpus.source, .{});
    defer parsed.deinit();
    var case_count: usize = 0;
    for (parsed.value) |fixture| {
        case_count += 1;
        var operator = try operators.PhraseOperator.compile(std.testing.allocator, fixture.param, .{});
        defer operator.deinit();
        const expected = fixture.ret == 1;
        std.testing.expectEqual(expected, operator.matches(fixture.input)) catch |err| {
            std.debug.print("pm mismatch: param={s} input={s} expected={d}\n", .{ fixture.param, fixture.input, fixture.ret });
            return err;
        };
    }
    try std.testing.expectEqual(@as(usize, 15), case_count);
}

test "retained Coraza ipMatch corpus matches the CIDR matcher" {
    var parsed = try std.json.parseFromSlice([]Fixture, std.testing.allocator, ip_corpus.source, .{});
    defer parsed.deinit();
    var case_count: usize = 0;
    for (parsed.value) |fixture| {
        case_count += 1;
        var matcher = try operators.compileIpMatch(std.testing.allocator, fixture.param, .{});
        defer matcher.deinit();
        const expected = fixture.ret == 1;
        std.testing.expectEqual(expected, matcher.matches(fixture.input)) catch |err| {
            std.debug.print("ipMatch mismatch: param={s} input={s} expected={d}\n", .{ fixture.param, fixture.input, fixture.ret });
            return err;
        };
    }
    try std.testing.expectEqual(@as(usize, 3623), case_count);
}

test "retained Coraza validation corpora match the validators" {
    // validateByteRange
    var br = try std.json.parseFromSlice([]Fixture, std.testing.allocator, byte_range_corpus.source, .{});
    defer br.deinit();
    var br_count: usize = 0;
    for (br.value) |fixture| {
        br_count += 1;
        const input = try decodeFixture(std.testing.allocator, fixture.input);
        defer std.testing.allocator.free(input);
        var op = try operators.ByteRangeOperator.compile(fixture.param);
        try expectMatch(fixture, op.matches(input), "validateByteRange");
    }
    try std.testing.expectEqual(@as(usize, 6), br_count);

    // validateUtf8Encoding (no argument)
    var utf8 = try std.json.parseFromSlice([]Fixture, std.testing.allocator, utf8_corpus.source, .{});
    defer utf8.deinit();
    var utf8_count: usize = 0;
    for (utf8.value) |fixture| {
        utf8_count += 1;
        const input = try decodeFixture(std.testing.allocator, fixture.input);
        defer std.testing.allocator.free(input);
        try expectMatch(fixture, operators.validateUtf8Encoding(input), "validateUtf8Encoding");
    }
    try std.testing.expectEqual(@as(usize, 32), utf8_count);

    // validateUrlEncoding (no argument)
    var url = try std.json.parseFromSlice([]Fixture, std.testing.allocator, url_encoding_corpus.source, .{});
    defer url.deinit();
    var url_count: usize = 0;
    for (url.value) |fixture| {
        url_count += 1;
        const input = try decodeFixture(std.testing.allocator, fixture.input);
        defer std.testing.allocator.free(input);
        try expectMatch(fixture, operators.validateUrlEncoding(input), "validateUrlEncoding");
    }
    try std.testing.expectEqual(@as(usize, 15), url_count);
}

fn expectMatch(fixture: Fixture, actual: bool, name: []const u8) !void {
    const expected = fixture.ret == 1;
    std.testing.expectEqual(expected, actual) catch |err| {
        std.debug.print("{s} mismatch: param={s} input={s} expected={d}\n", .{ name, fixture.param, fixture.input, fixture.ret });
        return err;
    };
}
