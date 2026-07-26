const std = @import("std");
const waf = @import("waf");

/// Bytes chosen to break out of an encoding: JSON string and structure characters,
/// the native format's boundary marker, line breaks, and control bytes.
const escape_alphabet = "\"\\{}[],:\n\r\t- Aabc\x00\x01\x7f%&=/?<>'";

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const iterations = try std.fmt.parseInt(usize, arguments.next() orelse "5000", 10);
    const seed = try std.fmt.parseInt(u64, arguments.next() orelse "7043215681320074321", 10);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var buffer = try init.gpa.alloc(u8, 512);
    defer init.gpa.free(buffer);

    for (0..iterations) |iteration| {
        const length = 4 + random.uintLessThan(usize, buffer.len - 4);
        const input = buffer[0..length];
        switch (iteration % 3) {
            // Pure noise, including bytes no encoder expects.
            0 => random.bytes(input),
            // Characters that mean something to an encoder, so the fuzzer spends its
            // time on the boundary rather than on bytes that pass through untouched.
            1 => for (input) |*byte| {
                byte.* = escape_alphabet[random.uintLessThan(usize, escape_alphabet.len)];
            },
            // A plausible record fragment, so a mutation lands inside structure the
            // serializer produces rather than beside it.
            else => {
                const seed_text = "{\"transaction\":{\"id\":\"x\"},\"request\":{\"uri\":\"/a\"}}--- A--";
                for (input, 0..) |*byte, index| {
                    byte.* = seed_text[index % seed_text.len];
                    if (random.uintLessThan(u8, 8) == 0)
                        byte.* = escape_alphabet[random.uintLessThan(usize, escape_alphabet.len)];
                }
            },
        }
        try waf.audit_fuzz.fuzzOne(init.gpa, input);
    }

    std.debug.print(
        "audit fuzz iterations={d} seed={d} max_field_bytes={d}\n",
        .{ iterations, seed, buffer.len },
    );
}
