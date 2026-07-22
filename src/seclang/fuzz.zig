//! Reusable single-input oracle for parser fuzzers.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");
const parser = @import("parser.zig");

pub fn fuzzOne(allocator: std.mem.Allocator, input: []const u8) !void {
    var parsed = parser.parseBytesOutcome(allocator, "fuzz.conf", input, .{}, .{}) catch |failure| switch (failure) {
        error.InvalidUtf8 => return,
        else => |other| return other,
    };
    defer parsed.deinit();
    switch (parsed.outcome) {
        .document => |document| {
            const registered = parsed.registry.get(document.source_id) orelse return error.InvalidFuzzSource;
            if (!std.mem.eql(u8, registered.bytes, input)) return error.FuzzOwnershipMismatch;
            for (document.directives.items) |directive| {
                try parsed.registry.validateSpan(directive.name_span);
                try parsed.registry.validateSpan(directive.physical);
                for (directive.arguments) |argument| try parsed.registry.validateSpan(argument.physical);
            }
        },
        .diagnostic => |value| {
            try parsed.registry.validateSpan(value.primary);
            const rendered = try diagnostic.renderHuman(allocator, &parsed.registry, value, .{ .max_bytes = 1024 });
            defer allocator.free(rendered);
            if (rendered.len == 0 or rendered.len > 1024) return error.InvalidFuzzDiagnostic;
        },
    }
}

test "fuzz oracle accepts valid malformed and arbitrary bytes" {
    const cases = [_][]const u8{
        "SecAction pass",
        "SecRule ARGS",
        "SecRule ARGS \\",
        "SecAction \"unterminated",
        "SecRule ARGS|!TX:key \"!@rx [a-z]+\" \"id:1,msg:'a,b',deny\"",
        "\x00\xff\x80",
    };
    for (cases) |input| try fuzzOne(std.testing.allocator, input);
}
