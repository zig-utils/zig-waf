const std = @import("std");
const waf = @import("waf");

const structured_seed =
    "SecRuleEngine DetectionOnly\n" ++
    "SecRequestBodyAccess On\n" ++
    "SecRequestBodyLimit 1048576\n" ++
    "SecResponseBodyMimeTypesClear\n" ++
    "SecResponseBodyMimeType application/json text/plain\n" ++
    "SecAuditEngine RelevantOnly\n" ++
    "SecAuditLogParts ABIJDEFHZ\n" ++
    "SecDefaultAction \"phase:2,pass,t:lowercase\"\n" ++
    "SecRule ARGS|REQUEST_HEADERS:host \"@contains attack\" \"id:42,msg:'%{REQUEST_URI}',deny,chain\"\n" ++
    "SecRule TX:score \"@pm one two\" \"capture,setvar:tx.hit=1\"\n";
const ascii_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n\r\t\"'\\,#@!&|:%{}[]()*?+-_./";

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const iterations = try std.fmt.parseInt(usize, arguments.next() orelse "10000", 10);
    const seed = try std.fmt.parseInt(u64, arguments.next() orelse "11936128518282651045", 10);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var buffer = try init.gpa.alloc(u8, 8192);
    defer init.gpa.free(buffer);

    for (0..iterations) |iteration| {
        const length = random.uintLessThan(usize, buffer.len + 1);
        const input = buffer[0..length];
        switch (iteration % 4) {
            0 => random.bytes(input),
            1 => {
                for (input) |*byte| byte.* = ascii_alphabet[random.uintLessThan(usize, ascii_alphabet.len)];
            },
            2 => {
                for (input, 0..) |*byte, index| {
                    byte.* = structured_seed[index % structured_seed.len];
                    if (random.uintLessThan(u8, 20) == 0)
                        byte.* = ascii_alphabet[random.uintLessThan(usize, ascii_alphabet.len)];
                }
            },
            3 => {
                for (input, 0..) |*byte, index| byte.* = switch (index % 10) {
                    0 => 'S',
                    1 => 'e',
                    2 => 'c',
                    3 => 'R',
                    4 => '\\',
                    5 => '"',
                    6 => ',',
                    7 => '|',
                    8 => '\n',
                    else => 'a',
                };
            },
            else => unreachable,
        }
        try waf.plan_fuzz.fuzzOne(init.gpa, input);
    }
    std.debug.print("plan fuzz iterations={d} seed={d} max_input_bytes={d}\n", .{ iterations, seed, buffer.len });
}
