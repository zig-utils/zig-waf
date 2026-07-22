//! Executable retained upstream transformation corpus evidence.

const std = @import("std");
const transformations = @import("waf").transformations;
const checksums = @embedFile("fixtures/transformations/coraza/SHA256SUMS");

const Corpus = struct {
    name: []const u8,
    source: []const u8,
};

const corpora = [_]Corpus{
    corpus("base64Decode"),
    corpus("base64DecodeExt"),
    corpus("base64Encode"),
    corpus("cmdLine"),
    corpus("compressWhitespace"),
    corpus("cssDecode"),
    corpus("escapeSeqDecode"),
    corpus("hexDecode"),
    corpus("hexEncode"),
    corpus("htmlEntityDecode"),
    corpus("jsDecode"),
    corpus("length"),
    corpus("lowercase"),
    corpus("md5"),
    corpus("normalisePath"),
    corpus("normalisePathWin"),
    corpus("parityEven7bit"),
    corpus("parityOdd7bit"),
    corpus("parityZero7bit"),
    corpus("removeComments"),
    corpus("removeCommentsChar"),
    corpus("removeNulls"),
    corpus("removeWhitespace"),
    corpus("replaceComments"),
    corpus("replaceNulls"),
    corpus("sha1"),
    corpus("sqlHexDecode"),
    corpus("trim"),
    corpus("trimLeft"),
    corpus("trimRight"),
    corpus("uppercase"),
    corpus("urlDecode"),
    corpus("urlDecodeUni"),
    corpus("urlEncode"),
    corpus("utf8toUnicode"),
};

fn corpus(comptime name: []const u8) Corpus {
    return .{
        .name = name,
        .source = @embedFile("fixtures/transformations/coraza/" ++ name ++ ".json"),
    };
}

const Fixture = struct {
    input: []const u8,
    output: []const u8,
    name: []const u8,
    ret: i64,
    type: []const u8,
};

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
        if (unquote and encoded[index] == '\\') {
            if (index + 1 == encoded.len) return invalidUnquote(allocator, &decoded);
            const escaped = encoded[index + 1];
            if (escaped == 'x') {
                if (index + 3 >= encoded.len or hexNibble(encoded[index + 2]) == null or hexNibble(encoded[index + 3]) == null)
                    return invalidUnquote(allocator, &decoded);
                try decoded.append(allocator, hexNibble(encoded[index + 2]).? * 16 + hexNibble(encoded[index + 3]).?);
                index += 4;
                continue;
            }
            const simple: ?u8 = switch (escaped) {
                'a' => 0x07,
                'b' => 0x08,
                'f' => 0x0c,
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'v' => 0x0b,
                '\\', '"', '\'', '?' => escaped,
                else => null,
            };
            if (simple) |byte| {
                try decoded.append(allocator, byte);
                index += 2;
                continue;
            }
            if (escaped >= '0' and escaped <= '7') {
                var digits: usize = 1;
                var value: u16 = escaped - '0';
                while (digits < 3 and index + 1 + digits < encoded.len and isOctal(encoded[index + 1 + digits])) : (digits += 1)
                    value = value * 8 + encoded[index + 1 + digits] - '0';
                if (value > 255) return invalidUnquote(allocator, &decoded);
                try decoded.append(allocator, @intCast(value));
                index += 1 + digits;
                continue;
            }
            return invalidUnquote(allocator, &decoded);
        }
        try decoded.append(allocator, encoded[index]);
        index += 1;
    }
    return decoded.toOwnedSlice(allocator);
}

fn invalidUnquote(allocator: std.mem.Allocator, decoded: *std.ArrayList(u8)) ![]u8 {
    decoded.deinit(allocator);
    decoded.* = .empty;
    return allocator.alloc(u8, 0);
}

fn isOctal(byte: u8) bool {
    return byte >= '0' and byte <= '7';
}

fn hexNibble(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

test "retained Coraza transformation fixture digests are pinned" {
    var lines = std.mem.tokenizeScalar(u8, checksums, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        try std.testing.expect(line.len > 66);
        try std.testing.expectEqualStrings("  ", line[64..66]);
        const basename = std.fs.path.basename(line[66..]);
        try std.testing.expect(std.mem.endsWith(u8, basename, ".json"));
        const name = basename[0 .. basename.len - ".json".len];
        const source = for (corpora) |candidate| {
            if (std.mem.eql(u8, candidate.name, name)) break candidate.source;
        } else return error.UnexpectedFixtureChecksum;

        var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
        const encoded = std.fmt.bytesToHex(digest, .lower);
        try std.testing.expectEqualStrings(line[0..64], &encoded);
        count += 1;
    }
    try std.testing.expectEqual(corpora.len, count);
}

test "all retained Coraza transformation fixtures match byte output" {
    try std.testing.expectEqual(transformations.specs.len, corpora.len);
    var executor = try transformations.Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer executor.deinit();
    var case_count: usize = 0;
    for (corpora) |source| {
        const resolution = transformations.resolve(source.name) orelse return error.MissingTransformation;
        const kind = switch (resolution) {
            .builtin => |value| value,
            .reset => return error.InvalidCorpusTransformation,
        };
        var parsed = try std.json.parseFromSlice([]Fixture, std.testing.allocator, source.source, .{});
        defer parsed.deinit();
        for (parsed.value) |fixture| {
            case_count += 1;
            const input = try decodeFixture(std.testing.allocator, fixture.input);
            defer std.testing.allocator.free(input);
            const expected = try decodeFixture(std.testing.allocator, fixture.output);
            defer std.testing.allocator.free(expected);
            const strict_error = kind == .hex_decode and std.mem.startsWith(u8, fixture.name, "invalid");
            if (strict_error) {
                try std.testing.expectError(error.InvalidInput, executor.apply(kind, input));
                continue;
            }
            const actual = executor.apply(kind, input) catch |err| {
                std.debug.print("unexpected {s} fixture error in {s}: {s}\n", .{ @errorName(err), source.name, fixture.name });
                return err;
            };
            std.testing.expectEqualSlices(u8, expected, actual.bytes) catch |err| {
                std.debug.print("Coraza fixture mismatch in {s}: {s}\n", .{ source.name, fixture.name });
                return err;
            };
        }
    }
    try std.testing.expectEqual(@as(usize, 355), case_count);
}
