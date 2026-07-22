const std = @import("std");
const waf = @import("waf");

const structured_seed =
    "SecRule ARGS|!REQUEST_HEADERS:authorization \"!@rx (?i)(select|union)\" " ++
    "\"id:42,phase:2,msg:'fuzz, seed',setvar:tx.score=+1,deny\"\n";
const ascii_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \\n\\r\\t\\\"'\\,#@!&|:%{}[]()*?+-_./";

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const iterations = try std.fmt.parseInt(usize, arguments.next() orelse "10000", 10);
    const seed = try std.fmt.parseInt(u64, arguments.next() orelse "6840335614489015467", 10);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var buffer = try init.gpa.alloc(u8, 8192);
    defer init.gpa.free(buffer);

    for (0..iterations) |iteration| {
        const mode = iteration % 4;
        const length = random.uintLessThan(usize, buffer.len + 1);
        const input = buffer[0..length];
        switch (mode) {
            0 => random.bytes(input),
            1 => {
                for (input) |*byte| byte.* = ascii_alphabet[random.uintLessThan(usize, ascii_alphabet.len)];
            },
            2 => {
                for (input, 0..) |*byte, index| {
                    byte.* = structured_seed[index % structured_seed.len];
                    if (random.uintLessThan(u8, 16) == 0)
                        byte.* = ascii_alphabet[random.uintLessThan(usize, ascii_alphabet.len)];
                }
            },
            3 => {
                for (input, 0..) |*byte, index| byte.* = switch (index % 8) {
                    0 => '"',
                    1, 2 => '\\',
                    3 => '\n',
                    4 => '\'',
                    5 => ',',
                    6 => '|',
                    else => 'a',
                };
            },
            else => unreachable,
        }
        try waf.seclang.fuzz.fuzzOne(init.gpa, input);
    }
    std.debug.print("parser fuzz iterations={d} seed={d} max_input_bytes={d}\n", .{ iterations, seed, buffer.len });
}
