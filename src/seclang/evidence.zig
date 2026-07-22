//! Embedded machine-readable evidence for the SecLang frontend boundary.

const std = @import("std");

pub const json = @embedFile("../compatibility/evidence/seclang-parser.json");

test "SecLang compatibility evidence is valid and identifies WAF-10" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings("WAF-10", object.get("issue").?.string);
    try std.testing.expectEqual(@as(i64, 58), object.get("corpus").?.object.get("files").?.integer);
    try std.testing.expectEqual(@as(i64, 0), object.get("corpus").?.object.get("unexplainedExclusions").?.integer);
}
