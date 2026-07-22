//! Stable SecLang transformation inventory and canonical name resolution.

const std = @import("std");

pub const Kind = enum(u8) {
    base64_decode,
    base64_decode_ext,
    base64_encode,
    cmd_line,
    compress_whitespace,
    css_decode,
    escape_seq_decode,
    hex_decode,
    hex_encode,
    html_entity_decode,
    js_decode,
    length,
    lowercase,
    md5,
    normalise_path,
    normalise_path_win,
    parity_even_7bit,
    parity_odd_7bit,
    parity_zero_7bit,
    remove_comments,
    remove_comments_char,
    remove_nulls,
    remove_whitespace,
    replace_comments,
    replace_nulls,
    sha1,
    sql_hex_decode,
    trim,
    trim_left,
    trim_right,
    uppercase,
    url_decode,
    url_decode_uni,
    url_encode,
    utf8_to_unicode,

    pub fn canonicalName(self: Kind) []const u8 {
        return specs[@backingInt(self)].name;
    }
};

pub const Resolution = union(enum) {
    reset,
    builtin: Kind,

    pub fn canonicalName(self: Resolution) []const u8 {
        return switch (self) {
            .reset => "none",
            .builtin => |kind| kind.canonicalName(),
        };
    }
};

pub const Spec = struct {
    kind: Kind,
    name: []const u8,
};

pub const specs = [_]Spec{
    .{ .kind = .base64_decode, .name = "base64Decode" },
    .{ .kind = .base64_decode_ext, .name = "base64DecodeExt" },
    .{ .kind = .base64_encode, .name = "base64Encode" },
    .{ .kind = .cmd_line, .name = "cmdLine" },
    .{ .kind = .compress_whitespace, .name = "compressWhitespace" },
    .{ .kind = .css_decode, .name = "cssDecode" },
    .{ .kind = .escape_seq_decode, .name = "escapeSeqDecode" },
    .{ .kind = .hex_decode, .name = "hexDecode" },
    .{ .kind = .hex_encode, .name = "hexEncode" },
    .{ .kind = .html_entity_decode, .name = "htmlEntityDecode" },
    .{ .kind = .js_decode, .name = "jsDecode" },
    .{ .kind = .length, .name = "length" },
    .{ .kind = .lowercase, .name = "lowercase" },
    .{ .kind = .md5, .name = "md5" },
    .{ .kind = .normalise_path, .name = "normalisePath" },
    .{ .kind = .normalise_path_win, .name = "normalisePathWin" },
    .{ .kind = .parity_even_7bit, .name = "parityEven7bit" },
    .{ .kind = .parity_odd_7bit, .name = "parityOdd7bit" },
    .{ .kind = .parity_zero_7bit, .name = "parityZero7bit" },
    .{ .kind = .remove_comments, .name = "removeComments" },
    .{ .kind = .remove_comments_char, .name = "removeCommentsChar" },
    .{ .kind = .remove_nulls, .name = "removeNulls" },
    .{ .kind = .remove_whitespace, .name = "removeWhitespace" },
    .{ .kind = .replace_comments, .name = "replaceComments" },
    .{ .kind = .replace_nulls, .name = "replaceNulls" },
    .{ .kind = .sha1, .name = "sha1" },
    .{ .kind = .sql_hex_decode, .name = "sqlHexDecode" },
    .{ .kind = .trim, .name = "trim" },
    .{ .kind = .trim_left, .name = "trimLeft" },
    .{ .kind = .trim_right, .name = "trimRight" },
    .{ .kind = .uppercase, .name = "uppercase" },
    .{ .kind = .url_decode, .name = "urlDecode" },
    .{ .kind = .url_decode_uni, .name = "urlDecodeUni" },
    .{ .kind = .url_encode, .name = "urlEncode" },
    .{ .kind = .utf8_to_unicode, .name = "utf8toUnicode" },
};

comptime {
    for (specs, 0..) |spec, index| {
        if (@backingInt(spec.kind) != index) @compileError("transformation specs must follow enum order");
    }
}

pub fn resolve(name: []const u8) ?Resolution {
    if (std.ascii.eqlIgnoreCase(name, "none")) return .reset;
    for (specs) |spec| {
        if (std.ascii.eqlIgnoreCase(name, spec.name)) return .{ .builtin = spec.kind };
    }
    if (std.ascii.eqlIgnoreCase(name, "normalizePath")) return .{ .builtin = .normalise_path };
    if (std.ascii.eqlIgnoreCase(name, "normalizePathWin")) return .{ .builtin = .normalise_path_win };
    return null;
}

test "stable transformation union and aliases resolve canonically" {
    try std.testing.expectEqual(@as(usize, 35), specs.len);
    for (specs) |spec| {
        try std.testing.expectEqual(spec.kind, (resolve(spec.name) orelse return error.MissingTransformation).builtin);
        const uppercase = try std.ascii.allocUpperString(std.testing.allocator, spec.name);
        defer std.testing.allocator.free(uppercase);
        try std.testing.expectEqual(spec.kind, (resolve(uppercase) orelse return error.MissingTransformation).builtin);
        try std.testing.expectEqualStrings(spec.name, spec.kind.canonicalName());
    }
    try std.testing.expectEqual(Resolution.reset, resolve("NoNe").?);
    try std.testing.expectEqual(Kind.normalise_path, resolve("normalizePath").?.builtin);
    try std.testing.expectEqual(Kind.normalise_path_win, resolve("NORMALIZEPATHWIN").?.builtin);
    try std.testing.expect(resolve("notAStableTransformation") == null);
}
