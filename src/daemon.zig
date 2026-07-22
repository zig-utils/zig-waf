const std = @import("std");
const waf = @import("waf");

pub fn main() void {
    std.debug.print("zig-wafd {s}: proxy startup is not enabled in this development build\n", .{waf.version});
}
