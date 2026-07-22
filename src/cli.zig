const std = @import("std");
const waf = @import("waf");

pub fn main() void {
    std.debug.print("zig-waf {s}\n", .{waf.version});
}
