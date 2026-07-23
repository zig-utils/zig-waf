const std = @import("std");
const waf = @import("waf");

const structured_seed = "%uFF01%41+&NotEqualTilde;\\x41\\123/*comment*/0x4142../a//b\\c==";
const marker_alphabet = "%+&;#xXuU\\/'\"*-.=0123456789abcdefABCDEF \t\r\n";

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const iterations = try std.fmt.parseInt(usize, arguments.next() orelse "10000", 10);
    const seed = try std.fmt.parseInt(u64, arguments.next() orelse "16045690984503098046", 10);
    if (arguments.next() != null) return error.UnexpectedArgument;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var buffer = try init.gpa.alloc(u8, 4096);
    defer init.gpa.free(buffer);

    for (0..iterations) |iteration| {
        const length = random.uintLessThan(usize, buffer.len + 1);
        const input = buffer[0..length];
        switch (iteration % 5) {
            0 => random.bytes(input),
            1 => {
                for (input) |*byte| byte.* = marker_alphabet[random.uintLessThan(usize, marker_alphabet.len)];
            },
            2 => {
                for (input, 0..) |*byte, index| {
                    byte.* = structured_seed[index % structured_seed.len];
                    if (random.uintLessThan(u8, 32) == 0) byte.* = random.int(u8);
                }
            },
            3 => @memset(input, switch ((iteration / 5) % 8) {
                0 => '%',
                1 => '\\',
                2 => '&',
                3 => '/',
                4 => 0,
                5 => 0xff,
                6 => 'A',
                else => ' ',
            }),
            4 => {
                for (input, 0..) |*byte, index| byte.* = @truncate(index);
            },
            else => unreachable,
        }
        try waf.transformation_fuzz.fuzzOne(init.gpa, input);
    }
    std.debug.print("transformation fuzz iterations={d} seed={d} max_input_bytes={d}\n", .{ iterations, seed, buffer.len });
}
