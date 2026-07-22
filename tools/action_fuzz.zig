const std = @import("std");
const waf = @import("waf");

const structured_seed =
    "SecDefaultAction \"phase:2,pass,log,auditlog\"\n" ++
    "SecRule ARGS @rx \"id:42,msg:'%{TX.score}',tag:'fuzz',capture,setvar:'tx.score=+1',setenv:'FLAG=%{TX.score}'\"\n" ++
    "SecRule TX @rx \"id:43,chain,setvar:'tx.chain=head'\"\n" ++
    "SecRule REQUEST_URI @rx \"setvar:'tx.chain=%{TX.chain}-tail',nolog\"\n" ++
    "SecRule ARGS @rx \"id:44,deny,status:403,skip:1,ctl:auditEngine=On,ctl:auditLogParts=ABCFHZ\"\n" ++
    "SecRule ARGS @rx \"id:45,redirect:'https://example.test/%{REQUEST_URI}',ctl:ruleRemoveById=100-200\"\n" ++
    "SecRule ARGS @rx \"id:46,proxy:'https://upstream.test',ctl:ruleRemoveTargetByTag=fuzz;ARGS:secret\"\n";
const ascii_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n\r\t\"'\\,#@!&|:%{}[]()*?+-_./";

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const iterations = try std.fmt.parseInt(usize, arguments.next() orelse "10000", 10);
    const seed = try std.fmt.parseInt(u64, arguments.next() orelse "13907095936298285211", 10);
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
                    if (random.uintLessThan(u8, 24) == 0)
                        byte.* = ascii_alphabet[random.uintLessThan(usize, ascii_alphabet.len)];
                }
            },
            3 => {
                for (input, 0..) |*byte, index| byte.* = switch (index % 8) {
                    0 => '%',
                    1 => '{',
                    2 => 'T',
                    3 => 'X',
                    4 => '.',
                    5 => 'a',
                    6 => '}',
                    else => 0,
                };
            },
            else => unreachable,
        }
        try waf.action_fuzz.fuzzOne(init.gpa, input);
    }
    std.debug.print("action fuzz iterations={d} seed={d} max_input_bytes={d}\n", .{ iterations, seed, buffer.len });
}
