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

/// Every retained fixture file, for digest pinning.
const all_files = [_]Corpus{
    corpus("beginsWith"), corpus("contains"), corpus("containsWord"),
    corpus("endsWith"),   corpus("eq"),       corpus("ge"),
    corpus("gt"),         corpus("le"),       corpus("lt"),
    corpus("streq"),      corpus("strmatch"), corpus("within"),
    corpus("pm"),         corpus("ipMatch"),
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
