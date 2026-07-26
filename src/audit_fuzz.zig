//! Fuzz oracle for audit serialization (#39).
//!
//! An audit record is built entirely from attacker-controlled bytes — the request
//! line, headers, body, and the matched values quoted into rule messages. The
//! property that matters is not that the record looks right but that a request
//! cannot *escape its encoding*: a URI containing a quote, a newline, or a control
//! byte must not close a JSON string or start a line that reads as a new record.
//! That is log injection, and it lets an attacker forge entries in the record of
//! their own attack.
//!
//! So the oracle checks the structural property in each format rather than the
//! text: the JSON formats must parse as JSON, and the native serial format's
//! boundaries must stay where the reader expects them.

const std = @import("std");
const engine = @import("engine.zig");
const audit = @import("audit.zig");

pub fn fuzzOne(allocator: std.mem.Allocator, input: []const u8) !void {
    if (input.len < 4) return;

    var builder = engine.Builder.init(allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;

    var transaction = waf.newTransaction();
    defer transaction.deinit();

    // Slice the input into the fields an attacker controls. Each is used verbatim,
    // so whatever the fuzzer produces reaches the serializer exactly as a client
    // could have sent it.
    const quarter = input.len / 4;
    const uri = input[0..quarter];
    const header_value = input[quarter .. quarter * 2];
    const body = input[quarter * 2 .. quarter * 3];
    const response_value = input[quarter * 3 ..];

    transaction.processConnection("192.0.2.1", 1234, "198.51.100.1", 443) catch return;
    // A URI the engine rejects (control bytes, oversize) is a decision, not a
    // failure: there is nothing to serialize, so the case ends here.
    transaction.processUri(uri, "GET", "HTTP/1.1") catch return;
    transaction.addRequestHeader("X-Fuzz", header_value) catch {};
    transaction.processRequestHeaders() catch return;
    transaction.writeRequestBody(body) catch {};
    transaction.processRequestBody() catch {};
    transaction.addResponseHeader("X-Echo", response_value) catch {};
    transaction.processResponseHeaders(200, "HTTP/1.1") catch {};
    transaction.processLogging() catch {};

    for ([_]audit.Format{ .serial, .json, .legacy_json, .ocsf }) |format| {
        const record = transaction.serializeAuditLog(allocator, format) catch |err| switch (err) {
            error.OutOfMemory => return err,
            // A record the engine declines to produce is fine; one that produces
            // malformed bytes is not, which is what the checks below are for.
            else => continue,
        };
        defer allocator.free(record);
        if (record.len == 0) continue;

        switch (format) {
            .json, .legacy_json, .ocsf => {
                // The whole point: a request must not be able to escape the encoding
                // that contains it. If any of these fail to parse, some byte from the
                // request closed a string or a structure it should not have.
                var parsed = std.json.parseFromSlice(std.json.Value, allocator, record, .{}) catch
                    return error.AuditRecordIsNotValidJson;
                parsed.deinit();
            },
            .serial => {
                // The native format is boundary-delimited, so a record must not
                // contain a bare boundary marker that would split it in two for a
                // reader.
                if (std.mem.indexOf(u8, record[1..], "--- A--") != null)
                    return error.AuditRecordContainsBoundary;
            },
        }
    }
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

test "a request cannot escape the encoding of the record that describes it" {
    // Each of these is an attempt to break out: quotes and backslashes for JSON, a
    // newline for a line-oriented reader, control bytes, and a literal boundary
    // marker for the native format.
    const cases = [_][]const u8{
        "\"}{\\\"injected\\\":true}",
        "a\nb\nc\nd",
        "\x00\x01\x02\x03",
        "--- A--\n--- B--\n",
        "{\"already\":\"json\"}",
        "\\\\\\\\\"\"\"\"",
        "aaaabbbbccccdddd",
    };
    for (cases) |case| try fuzzOne(testing.allocator, case);
}
