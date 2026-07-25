//! zig-waf command-line interface.
//!
//! Subcommands operate on SecLang configuration from outside the engine, so
//! operators can check rule sets in CI before deploying them. `validate` parses,
//! compiles, and directive-validates one or more configs, printing human
//! diagnostics and exiting non-zero if any file is rejected.

const std = @import("std");
const waf = @import("waf");

const max_config_bytes = 32 * 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next(); // argv[0]

    const command = args.next() orelse {
        usage();
        std.process.exit(2);
    };

    if (std.mem.eql(u8, command, "validate")) {
        try validate(gpa, io, &args);
    } else if (std.mem.eql(u8, command, "version")) {
        std.debug.print("zig-waf {s}\n", .{waf.version});
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        usage();
    } else {
        std.debug.print("zig-waf: unknown command '{s}'\n\n", .{command});
        usage();
        std.process.exit(2);
    }
}

fn usage() void {
    std.debug.print(
        \\zig-waf — WAF engine CLI
        \\
        \\usage:
        \\  zig-waf validate <file.conf>...   parse, compile, and validate SecLang configs
        \\  zig-waf version                   print the engine version
        \\  zig-waf help                      show this help
        \\
    , .{});
}

fn validate(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    var files: usize = 0;
    var failures: usize = 0;
    while (args.next()) |path| {
        files += 1;
        if (!try validateFile(gpa, io, path)) failures += 1;
    }
    if (files == 0) {
        std.debug.print("zig-waf validate: no files given\n", .{});
        std.process.exit(2);
    }
    std.debug.print("validated {d} file(s), {d} failed\n", .{ files, failures });
    if (failures != 0) std.process.exit(1);
}

/// Validate a single config; returns true when it parses, compiles, and passes
/// directive validation. Diagnostics are printed to stderr.
fn validateFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) !bool {
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_config_bytes)) catch |err| {
        std.debug.print("{s}: cannot read: {t}\n", .{ path, err });
        return false;
    };
    defer gpa.free(bytes);

    var parsed = try waf.seclang.parser.parseBytesOutcome(gpa, path, bytes, .{}, .{});
    defer parsed.deinit();

    switch (parsed.outcome) {
        .diagnostic => |value| {
            const rendered = try waf.seclang.diagnostic.renderHuman(gpa, &parsed.registry, value, .{});
            defer gpa.free(rendered);
            std.debug.print("{s}", .{rendered});
            return false;
        },
        .document => |document| {
            var documents = [_]waf.seclang.parser.Document{document};
            const compiled = waf.plan.compile(gpa, &parsed.registry, &documents, .{}) catch |failure| {
                std.debug.print("{s}: plan compilation failed: {t}\n", .{ path, failure });
                return false;
            };
            defer compiled.deinit();
            switch (waf.directives.validatePlan(compiled, .full())) {
                .valid => {
                    std.debug.print("{s}: ok ({d} rule(s))\n", .{ path, compiled.rules.len });
                    return true;
                },
                .diagnostic => |diagnostic| {
                    const location = try compiled.sourceLocation(diagnostic.primary.source, diagnostic.primary.start);
                    std.debug.print("{s}:{d}:{d}: {s}: {s}\n", .{
                        path,                 location.line,      location.column,
                        diagnostic.code.id(), diagnostic.message,
                    });
                    return false;
                },
            }
        },
    }
}
