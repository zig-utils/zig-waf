//! Machine-readable compatibility evidence validation.

const std = @import("std");

pub const source = @embedFile("compatibility/features.json");

pub const Status = enum {
    planned,
    partial,
    implemented,
    verified,
};

pub const Matrix = struct {
    schema_version: u32,
    baselines: Baselines,
    features: []Feature,

    pub const Baselines = struct {
        modsecurity: []const u8,
        coraza: []const u8,
        crs: []const u8,
        libinjection: []const u8,
        zig: []const u8,
    };

    pub const Feature = struct {
        id: []const u8,
        area: []const u8,
        name: []const u8,
        status: Status,
        issue: []const u8,
        modsecurity: bool,
        coraza: bool,
        crs_required: bool,
        evidence: []const []const u8,
        notes: []const u8,
    };
};

test "compatibility matrix is valid and evidence-bearing" {
    const parsed = try std.json.parseFromSlice(Matrix, std.testing.allocator, source, .{});
    defer parsed.deinit();
    const matrix = parsed.value;

    try std.testing.expectEqual(@as(u32, 1), matrix.schema_version);
    try std.testing.expect(matrix.features.len > 0);
    try std.testing.expectEqualStrings("3.0.16", matrix.baselines.modsecurity);
    try std.testing.expectEqualStrings("3.7.0", matrix.baselines.coraza);
    try std.testing.expectEqualStrings("4.28.0", matrix.baselines.crs);

    for (matrix.features, 0..) |feature, index| {
        try std.testing.expect(feature.id.len > 0);
        try std.testing.expect(feature.name.len > 0);
        try std.testing.expect(std.mem.startsWith(u8, feature.issue, "https://github.com/zig-utils/"));
        if (feature.status == .implemented or feature.status == .verified) {
            try std.testing.expect(feature.evidence.len > 0);
        }
        for (matrix.features[0..index]) |prior| {
            try std.testing.expect(!std.mem.eql(u8, feature.id, prior.id));
        }
    }
}
