const std = @import("std");
const waf = @import("waf");

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const iterations = try std.fmt.parseInt(usize, arguments.next() orelse "10000", 10);
    const seed = try std.fmt.parseInt(u64, arguments.next() orelse "11400714819323198485", 10);
    if (arguments.next() != null) return error.UnexpectedArgument;

    try waf.operator_fuzz.fuzzDeterministic(init.gpa, iterations, seed);
    std.debug.print("operator fuzz iterations={d} seed={d}\n", .{ iterations, seed });
}
