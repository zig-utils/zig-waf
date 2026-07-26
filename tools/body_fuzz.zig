const std = @import("std");
const waf = @import("waf");

/// Body shapes worth mutating: each is a valid document for one processor, so a
/// mutation lands near a parser's interesting edges rather than in the middle of
/// random bytes it rejects immediately.
const seeds = [_][]const u8{
    "{\"user\":\"alice\",\"roles\":[\"a\",\"b\"],\"n\":{\"deep\":{\"deeper\":1}}}",
    "{\"dup\":1,\"dup\":2}",
    "user=alice&pass=secret&redirect=%2Fadmin&odd=%zz",
    "--FUZZ\r\nContent-Disposition: form-data; name=\"a\"; filename=\"../../x\"\r\n\r\nbytes\r\n--FUZZ--\r\n",
    "<root attr=\"value\"><child>text</child><![CDATA[raw]]></root>",
    "<!DOCTYPE d [<!ENTITY e \"expand\">]><d>&e;</d>",
};

const alphabet = "{}[]\",:=&;-_./%0123456789abcdefghijklmnopqrstuvwxyzABCXYZ<>\r\n \t\\'@";

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const iterations = try std.fmt.parseInt(usize, arguments.next() orelse "5000", 10);
    const seed = try std.fmt.parseInt(u64, arguments.next() orelse "9151314442816847872", 10);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    // Bounded so a fuzz case stays fast; the processors' own limits are what the
    // oracle is checking, not how large a body Zig can allocate.
    var buffer = try init.gpa.alloc(u8, 4096);
    defer init.gpa.free(buffer);

    for (0..iterations) |iteration| {
        const length = 1 + random.uintLessThan(usize, buffer.len);
        const input = buffer[0..length];
        // The first byte picks the processor, so a mutation can hand the same bytes
        // to a different parser — where the interesting disagreements are.
        input[0] = random.int(u8);
        const body = input[1..];
        switch (iteration % 3) {
            // Pure noise: every processor's rejection path.
            0 => random.bytes(body),
            // Structured bytes: shapes that get far enough in to matter.
            1 => {
                const chosen = seeds[random.uintLessThan(usize, seeds.len)];
                for (body, 0..) |*byte, index| {
                    byte.* = chosen[index % chosen.len];
                    if (random.uintLessThan(u8, 16) == 0)
                        byte.* = alphabet[random.uintLessThan(usize, alphabet.len)];
                }
            },
            // Nesting: the shape that overflowed the JSON flattener's stack.
            else => {
                const opener: u8 = if (random.boolean()) '[' else '{';
                const closer: u8 = if (opener == '[') ']' else '}';
                const half = body.len / 2;
                @memset(body[0..half], opener);
                @memset(body[half..], closer);
            },
        }
        try waf.body_fuzz.fuzzOne(init.gpa, input);
    }

    std.debug.print(
        "body fuzz iterations={d} seed={d} max_body_bytes={d}\n",
        .{ iterations, seed, buffer.len },
    );
}
