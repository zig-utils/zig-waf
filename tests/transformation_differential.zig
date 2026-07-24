//! Systematic differential vectors for every stable transformation kind and
//! alias. The exact-output vectors pin byte semantics that are independent of
//! the retained Coraza corpus; the per-kind invariants prove maximum-bound and
//! expansion behavior stays deterministic and allocation-bounded for all kinds.

const std = @import("std");
const transformations = @import("waf").transformations;

const Kind = transformations.Kind;
const Profile = transformations.Profile;
const Executor = transformations.Executor;

const Category = enum {
    empty,
    unchanged,
    malformed,
    binary,
    expansion,
};

const Vector = struct {
    kind: Kind,
    profile: Profile,
    category: Category,
    input: []const u8,
    output: []const u8,
    changed: bool,
};

fn v(kind: Kind, profile: Profile, category: Category, input: []const u8, output: []const u8, changed: bool) Vector {
    return .{ .kind = kind, .profile = profile, .category = category, .input = input, .output = output, .changed = changed };
}

/// Raw binary digests of the empty string, pinned to the compatibility contract.
const md5_empty = &[_]u8{
    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
};
const sha1_empty = &[_]u8{
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
    0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
};

const vectors = [_]Vector{
    // Encoding, decoding, representation.
    v(.base64_decode, .modsecurity, .expansion, "VGVzdA==", "Test", true),
    v(.base64_decode, .modsecurity, .empty, "", "", false),
    v(.base64_decode_ext, .modsecurity, .malformed, "VG Vz dA==", "Test", true),
    v(.base64_encode, .modsecurity, .expansion, "Test", "VGVzdA==", true),
    v(.base64_encode, .modsecurity, .binary, "\x00\xff", "AP8=", true),
    v(.hex_decode, .modsecurity, .expansion, "414243", "ABC", true),
    v(.hex_decode, .modsecurity, .malformed, "414", "A", true),
    v(.hex_encode, .modsecurity, .expansion, "AB", "4142", true),
    v(.hex_encode, .modsecurity, .binary, "\x00\xff", "00ff", true),
    v(.sql_hex_decode, .modsecurity, .expansion, "0x414243", "ABC", true),
    v(.sql_hex_decode, .modsecurity, .unchanged, "0xGG", "0xGG", false),
    v(.url_decode, .modsecurity, .malformed, "a%zzb", "a%zzb", false),
    v(.url_decode, .modsecurity, .binary, "%00%ff", "\x00\xff", true),
    v(.url_decode_uni, .modsecurity, .malformed, "%u00", "%u00", false),
    v(.url_encode, .modsecurity, .expansion, "a<b", "a%3cb", true),
    v(.url_encode, .modsecurity, .binary, "a b", "a+b", true),
    v(.url_encode, .modsecurity, .binary, "\x00", "%00", true),
    // ModSecurity tolerates the missing semicolon for its known named entities.
    v(.html_entity_decode, .modsecurity, .malformed, "&amp", "&", true),
    v(.css_decode, .modsecurity, .malformed, "\\", "", true),
    v(.js_decode, .modsecurity, .binary, "\\x41", "A", true),
    v(.escape_seq_decode, .modsecurity, .malformed, "\\q", "q", true),
    v(.utf8_to_unicode, .coraza, .binary, "\xff", "%ufffd", true),
    v(.length, .modsecurity, .expansion, "abc\x00", "4", true),
    v(.length, .modsecurity, .empty, "", "0", true),

    // Canonicalization and filtering.
    v(.lowercase, .modsecurity, .unchanged, "already lower", "already lower", false),
    v(.lowercase, .modsecurity, .binary, "A\xffZ", "a\xffz", true),
    v(.uppercase, .modsecurity, .binary, "a\xffz", "A\xffZ", true),
    v(.trim, .modsecurity, .unchanged, "value", "value", false),
    v(.trim_left, .modsecurity, .unchanged, "value ", "value ", false),
    v(.trim_right, .modsecurity, .unchanged, " value", " value", false),
    v(.compress_whitespace, .modsecurity, .binary, "a\t\nb", "a b", true),
    v(.remove_whitespace, .modsecurity, .binary, " \ta\rb", "ab", true),
    v(.remove_nulls, .modsecurity, .binary, "a\x00b", "ab", true),
    v(.replace_nulls, .modsecurity, .binary, "a\x00b", "a b", true),
    // An unterminated comment collapses to the pinned trailing-space sentinel.
    v(.remove_comments, .modsecurity, .malformed, "a/*b", "a ", true),
    v(.remove_comments_char, .modsecurity, .unchanged, "abc", "abc", false),
    v(.replace_comments, .modsecurity, .malformed, "a/*b*/c", "a c", true),
    v(.cmd_line, .modsecurity, .binary, "\"c\"md", "cmd", true),
    v(.normalise_path, .modsecurity, .malformed, "a/./b", "a/b", true),
    v(.normalise_path_win, .modsecurity, .binary, "a\\b", "a/b", true),
    v(.parity_even_7bit, .modsecurity, .binary, "AC", &[_]u8{ 0x41, 0xc3 }, true),
    v(.parity_odd_7bit, .modsecurity, .binary, "AC", &[_]u8{ 0xc1, 0x43 }, true),
    v(.parity_zero_7bit, .modsecurity, .binary, &[_]u8{ 0xff, 0x41 }, &[_]u8{ 0x7f, 0x41 }, true),

    // Compatibility digests: empty-input identity is a fixed 16/20-byte value.
    v(.md5, .modsecurity, .expansion, "", md5_empty, true),
    v(.sha1, .modsecurity, .expansion, "", sha1_empty, true),
};

test "differential vectors match pinned byte output for every category" {
    for (vectors) |vector| {
        var executor = try Executor.initWithProfile(std.testing.allocator, .{}, vector.profile);
        defer executor.deinit();
        const result = executor.apply(vector.kind, vector.input) catch |err| {
            std.debug.print("unexpected {s} error for {s}\n", .{ @errorName(err), vector.kind.canonicalName() });
            return err;
        };
        std.testing.expectEqualSlices(u8, vector.output, result.bytes) catch |err| {
            std.debug.print("byte mismatch for {s} ({s})\n", .{ vector.kind.canonicalName(), @tagName(vector.category) });
            return err;
        };
        std.testing.expectEqual(vector.changed, result.changed) catch |err| {
            std.debug.print("changed mismatch for {s} ({s})\n", .{ vector.kind.canonicalName(), @tagName(vector.category) });
            return err;
        };
    }
}

test "every stable kind and alias is exercised by a differential vector" {
    var covered = std.mem.zeroes([transformations.specs.len]bool);
    for (vectors) |vector| covered[@backingInt(vector.kind)] = true;
    for (transformations.specs) |spec| {
        if (!covered[@backingInt(spec.kind)]) {
            std.debug.print("missing differential vector for {s}\n", .{spec.name});
            return error.MissingDifferentialVector;
        }
    }
    for (transformations.aliases) |alias| {
        const resolution = transformations.resolve(alias.name) orelse return error.UnresolvedAlias;
        try std.testing.expectEqual(alias.kind, resolution.builtin);
        try std.testing.expect(covered[@backingInt(alias.kind)]);
    }
}

test "maximum-bound input stays deterministic and allocation-bounded for every kind" {
    // A modest maximum keeps expanding kinds inside their output ceiling while
    // still forcing full-length traversal of every state machine.
    const max_input = 4096;
    const limits = transformations.Limits{
        .max_input_bytes = max_input,
        .max_output_bytes = max_input * 8,
        .max_pipeline_steps = 8,
        .max_cumulative_output_bytes = max_input * 64,
        .max_cache_entries = 8,
        .max_cache_bytes = max_input * 8,
    };

    const input = try std.testing.allocator.alloc(u8, max_input);
    defer std.testing.allocator.free(input);
    // A mixed payload that touches percent, entity, hex, comment, and NUL paths.
    for (input, 0..) |*byte, index| byte.* = @intCast(index % 256);

    inline for (.{ Profile.modsecurity, Profile.coraza }) |profile| {
        var executor = try Executor.initWithProfile(std.testing.allocator, limits, profile);
        defer executor.deinit();
        for (transformations.specs) |spec| {
            const result = executor.apply(spec.kind, input) catch |err| switch (err) {
                // Deterministic, distinguishable limit and input errors are allowed;
                // an unbounded or corrupt result is not.
                error.OutputTooLarge, error.InvalidInput => continue,
                else => return err,
            };
            try std.testing.expect(result.bytes.len <= limits.max_output_bytes);
        }
    }
}
