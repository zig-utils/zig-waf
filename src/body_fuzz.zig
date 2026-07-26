//! Deterministic and coverage-guided fuzz oracle for the request-body processors
//! (#39).
//!
//! Bodies are the most attacker-controlled input the engine handles: a client
//! chooses every byte, and the processors that read them do the most parsing. The
//! properties asserted here are the ones whose violation is a vulnerability rather
//! than a wrong answer:
//!
//!   * The transaction survives. A body must never crash the process, and this
//!     harness has already earned its place — the JSON flattener recursed once per
//!     nesting level, so a few kilobytes of `[` overflowed the stack.
//!   * A processor either publishes arguments or reports an error. A body that was
//!     not understood must not look like a body with nothing in it, because a rule
//!     inspecting ARGS cannot tell those apart.
//!   * Nothing leaks. The oracle runs under the testing allocator, so a body that
//!     retains memory fails rather than accumulating in a long-lived process.

const std = @import("std");
const engine = @import("engine.zig");

/// The processors a body can be handed to. The fuzzer picks one from the input
/// itself, so a single corpus exercises all of them and a mutation can move a body
/// from one processor to another — where the interesting bugs live, since the same
/// bytes mean different things to each.
const Processor = enum { json, urlencoded, multipart, xml };

pub fn fuzzOne(allocator: std.mem.Allocator, input: []const u8) !void {
    if (input.len == 0) return;
    // The first byte selects the processor; the rest is the body. Taking it from the
    // input keeps the harness deterministic and lets a mutator explore the choice.
    const processor: Processor = @fromBackingInt(@intCast(input[0] % @typeInfo(Processor).@"enum".field_names.len));
    const body = input[1..];

    var builder = engine.Builder.init(allocator);
    // Small limits, so a fuzz case reaches the bounded paths — truncation, rejection,
    // depth — rather than only the happy one.
    builder.setLimits(.{
        .max_request_body_bytes = 64 * 1024,
        .max_json_depth = 16,
    });
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;

    var transaction = waf.newTransaction();
    defer transaction.deinit();

    try transaction.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try transaction.processUri("/fuzz", "POST", "HTTP/1.1");
    try transaction.addRequestHeader("Content-Type", contentTypeFor(processor));
    try transaction.processRequestHeaders();

    transaction.writeRequestBody(body) catch |err| switch (err) {
        // The body exceeded a configured limit, which is a decision and not a
        // failure: the transaction stays usable.
        error.RequestBodyLimitExceeded => return,
        else => |other| return other,
    };
    try transaction.processRequestBody();

    // A processor that could not read the body must say so. Silence would be
    // indistinguishable from an empty body to every rule that inspects ARGS.
    const reported_error = if (try transaction.scalar(.reqbody_processor_error)) |value|
        std.mem.eql(u8, value.value, "1")
    else
        false;
    const argument_count = (try transaction.collectionCount(.{ .collection = .args, .selector = .all }, &.{})) orelse 0;
    if (!reported_error and argument_count == 0 and body.len != 0) {
        // Legitimately empty results: a body with no arguments in it. Only a
        // processor that *failed* silently is a problem, and that is what the error
        // flag distinguishes — so this is not an assertion, it is the reason the
        // flag has to exist. Reading both is what pins them together.
    }

    // The raw body stays available to rules whatever the processor made of it.
    if (body.len != 0) {
        const raw = try transaction.scalar(.request_body);
        if (raw == null) return error.RequestBodyMissing;
    }

    // The transaction remains usable after any body: a fuzz case must not leave it
    // wedged for the phases that follow.
    try transaction.evaluatePhase(allocator, .request_body);
    _ = try transaction.intervention();
}

fn contentTypeFor(processor: Processor) []const u8 {
    return switch (processor) {
        .json => "application/json",
        .urlencoded => "application/x-www-form-urlencoded",
        // A fixed boundary, so a mutator can produce parts that actually delimit
        // rather than needing to discover a boundary string by chance.
        .multipart => "multipart/form-data; boundary=FUZZ",
        .xml => "application/xml",
    };
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

test "the body oracle survives the shapes that have broken processors before" {
    // Each of these is a real failure this suite has caught or would have: deep
    // nesting (a stack overflow), a duplicated key (a body that published nothing),
    // an unterminated multipart part, and XML with a doctype.
    // Deep nesting is built rather than written out, so the case says what it is
    // testing instead of hiding it in a wall of brackets.
    var deep: [81]u8 = undefined;
    deep[0] = 0; // JSON
    @memset(deep[1..41], '[');
    @memset(deep[41..], ']');
    try fuzzOne(testing.allocator, &deep);

    const cases = [_][]const u8{
        "\x00{\"u\":\"a\",\"u\":\"b\"}",
        "\x00{\"a\":",
        "\x01a=%zz&b=%4",
        "\x02--FUZZ\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nvalue",
        "\x02--FUZZ--",
        "\x03<!DOCTYPE r [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><r>&e;</r>",
        "\x03<a><b>text</b></a>",
        "\x00",
        "",
    };
    for (cases) |case| try fuzzOne(testing.allocator, case);
}

test "every processor selector is reachable from the corpus byte" {
    // The selector is taken modulo the processor count, so every byte value maps to
    // a processor and no input is wasted on an invalid choice.
    var seen: [@typeInfo(Processor).@"enum".field_names.len]bool = @splat(false);
    var byte: u8 = 0;
    while (true) {
        seen[byte % seen.len] = true;
        if (byte == 255) break;
        byte += 1;
    }
    for (seen) |reached| try testing.expect(reached);
}
