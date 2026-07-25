//! zig-waf command-line interface.
//!
//! Subcommands operate on SecLang configuration from outside the engine, so
//! operators can check rule sets in CI before deploying them. `validate` parses,
//! compiles, and directive-validates one or more configs, printing human
//! diagnostics and exiting non-zero if any file is rejected.

const std = @import("std");
const waf = @import("waf");

const max_config_bytes = 32 * 1024 * 1024;
const max_data_file_bytes = 8 * 1024 * 1024;

/// Loads `@pmFromFile` / `@ipMatchFromFile` data files for the compiler,
/// resolving each relative to the referencing rule file and confining reads to
/// `root` (the config file's directory).
const DataFileProvider = struct {
    io: std.Io,
    root: []const u8,

    fn read(context: *anyopaque, allocator: std.mem.Allocator, base_dir: []const u8, filename: []const u8) anyerror![]u8 {
        const self: *DataFileProvider = @ptrCast(@alignCast(context));
        return waf.seclang.include.readDataFileAlloc(allocator, self.io, self.root, base_dir, filename, max_data_file_bytes, false);
    }

    fn provider(self: *DataFileProvider) waf.plan.DataProvider {
        return .{ .context = self, .readFn = read };
    }
};

/// Report a malformed or value-missing flag and exit; used by `test` argument
/// parsing where a bad flag is a usage error, not a runtime condition.
fn flagError(flag: []const u8) noreturn {
    std.debug.print("zig-waf test: {s} requires a value\n", .{flag});
    std.process.exit(2);
}

/// The configuration root for data-file resolution: the canonical directory
/// holding `path`. Returns null if the path cannot be canonicalised (callers
/// then compile without file-backed operator support).
fn configRoot(io: std.Io, gpa: std.mem.Allocator, path: []const u8) ?[]u8 {
    const canonical = std.Io.Dir.cwd().realPathFileAlloc(io, path, gpa) catch return null;
    defer gpa.free(canonical);
    const directory = std.fs.path.dirname(canonical) orelse return null;
    return gpa.dupe(u8, directory) catch null;
}

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
    } else if (std.mem.eql(u8, command, "explain")) {
        try explain(gpa, io, &args);
    } else if (std.mem.eql(u8, command, "test")) {
        try testRequest(gpa, io, &args);
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
        \\  zig-waf explain <file.conf>       list the compiled rules (phase, id, action, location)
        \\  zig-waf test <file.conf> [METHOD] [URI] [BODY] [CONTENT-TYPE] [--status N] [--response-body TEXT] [--response-type CT]
        \\      run a request (and optional simulated response) through the engine and report the decision
        \\  zig-waf version                   print the engine version
        \\  zig-waf help                      show this help
        \\
    , .{});
}

/// Compile a config and print one line per rule: index, phase, id, disruptive
/// action, and source location — a quick view of what a rule set resolves to.
fn explain(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    const path = args.next() orelse {
        std.debug.print("zig-waf explain: expected a config file\n", .{});
        std.process.exit(2);
    };
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_config_bytes)) catch |err| {
        std.debug.print("{s}: cannot read: {t}\n", .{ path, err });
        std.process.exit(1);
    };
    defer gpa.free(bytes);

    var parsed = try waf.seclang.parser.parseBytesOutcome(gpa, path, bytes, .{}, .{});
    defer parsed.deinit();
    const document = switch (parsed.outcome) {
        .diagnostic => |value| {
            const rendered = try waf.seclang.diagnostic.renderHuman(gpa, &parsed.registry, value, .{});
            defer gpa.free(rendered);
            std.debug.print("{s}", .{rendered});
            std.process.exit(1);
        },
        .document => |document| document,
    };
    var documents = [_]waf.seclang.parser.Document{document};
    const compiled = waf.plan.compile(gpa, &parsed.registry, &documents, .{}) catch |failure| {
        std.debug.print("{s}: plan compilation failed: {t}\n", .{ path, failure });
        std.process.exit(1);
    };
    defer compiled.deinit();

    std.debug.print("{s}: {d} rule(s)\n", .{ path, compiled.rules.len });
    for (compiled.rules, 0..) |rule, index| {
        const location = try compiled.sourceLocation(rule.source.source, rule.source.start);
        var id_buf: [24]u8 = undefined;
        const id = if (rule.external_id) |value|
            std.fmt.bufPrint(&id_buf, "{d}", .{value}) catch "?"
        else
            "-";
        std.debug.print("  [{d}] phase={d} id={s} action={s} @ {d}:{d}\n", .{
            index,                          rule.phase,    id,
            @tagName(rule.disruptive.kind), location.line, location.column,
        });
    }
}

/// Compile a config, run a synthetic request through the engine's request
/// phases, and print whether it is blocked or allowed — a quick way to check a
/// rule against a request from the command line or CI.
fn testRequest(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    const path = args.next() orelse {
        std.debug.print("zig-waf test: expected a config file\n", .{});
        std.process.exit(2);
    };
    const method = args.next() orelse "GET";
    const uri = args.next() orelse "/";
    // Optional request body + content type (positional), so request-body-phase
    // rules (URL-encoded / JSON / multipart / XML) can be exercised, plus
    // optional `--status` / `--response-body` / `--response-type` flags that
    // simulate a backend response for response-phase rules (CRS 95x data
    // leakage). An empty body means "no body" — otherwise a GET would carry a
    // zero-length body and content-type headers, which protocol rules flag.
    var body: ?[]const u8 = null;
    var content_type: []const u8 = "application/x-www-form-urlencoded";
    var response_status: u16 = 200;
    var response_body: ?[]const u8 = null;
    var response_type: []const u8 = "text/html";
    var positional: usize = 0;
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.eql(u8, arg, "--status")) {
                response_status = std.fmt.parseInt(u16, args.next() orelse flagError("--status"), 10) catch flagError("--status");
            } else if (std.mem.eql(u8, arg, "--response-body")) {
                const value = args.next() orelse flagError("--response-body");
                response_body = if (value.len == 0) null else value;
            } else if (std.mem.eql(u8, arg, "--response-type")) {
                response_type = args.next() orelse flagError("--response-type");
            } else {
                std.debug.print("zig-waf test: unknown flag {s}\n", .{arg});
                std.process.exit(2);
            }
        } else switch (positional) {
            0 => {
                body = if (arg.len == 0) null else arg;
                positional += 1;
            },
            1 => {
                content_type = arg;
                positional += 1;
            },
            else => {
                std.debug.print("zig-waf test: unexpected argument {s}\n", .{arg});
                std.process.exit(2);
            },
        }
    }

    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_config_bytes)) catch |err| {
        std.debug.print("{s}: cannot read: {t}\n", .{ path, err });
        std.process.exit(1);
    };
    defer gpa.free(bytes);

    var parsed = try waf.seclang.parser.parseBytesOutcome(gpa, path, bytes, .{}, .{});
    defer parsed.deinit();
    const document = switch (parsed.outcome) {
        .diagnostic => |value| {
            const rendered = try waf.seclang.diagnostic.renderHuman(gpa, &parsed.registry, value, .{});
            defer gpa.free(rendered);
            std.debug.print("{s}", .{rendered});
            std.process.exit(1);
        },
        .document => |document| document,
    };
    var documents = [_]waf.seclang.parser.Document{document};
    const root = configRoot(io, gpa, path);
    defer if (root) |value| gpa.free(value);
    var provider_storage: DataFileProvider = undefined;
    var provider: ?waf.plan.DataProvider = null;
    if (root) |value| {
        provider_storage = .{ .io = io, .root = value };
        provider = provider_storage.provider();
    }
    const plan = waf.plan.compileWithProvider(gpa, &parsed.registry, &documents, .{}, provider) catch |failure| {
        std.debug.print("{s}: plan compilation failed: {t}\n", .{ path, failure });
        std.process.exit(1);
    };
    defer plan.deinit();

    var builder = waf.Waf.Builder.init(gpa);
    builder.setRetainedPlan(plan);
    const instance = try builder.build();
    defer instance.deinit() catch {};

    var tx = instance.newTransaction();
    defer tx.deinit();
    try tx.processConnection("127.0.0.1", 40000, "127.0.0.1", 80);
    try tx.processUri(uri, method, "HTTP/1.1");
    // Send the headers a normal client always carries. CRS protocol-enforcement
    // rules (920) legitimately flag requests missing Host / User-Agent / Accept,
    // so without these a benign request looks like a bare scanner probe and is
    // blocked — masking real detection behaviour behind a test artifact.
    try tx.addRequestHeader("Host", "localhost");
    try tx.addRequestHeader("User-Agent", "zig-waf-test/1.0");
    try tx.addRequestHeader("Accept", "*/*");
    if (body) |bytes_body| {
        try tx.addRequestHeader("Content-Type", content_type);
        var length_buffer: [20]u8 = undefined;
        const length = std.fmt.bufPrint(&length_buffer, "{d}", .{bytes_body.len}) catch unreachable;
        try tx.addRequestHeader("Content-Length", length);
    }
    try tx.processRequestHeaders();
    try tx.evaluatePhase(gpa, .request_headers);
    if ((try tx.intervention()) == null) {
        if (body) |bytes_body| try tx.writeRequestBody(bytes_body);
        try tx.processRequestBody();
        try tx.evaluatePhase(gpa, .request_body);
    }

    // Simulate the backend response so response-phase rules (CRS 95x data
    // leakage / web shells) can be exercised. Only run if the request was not
    // already blocked — a blocked request never reaches the origin.
    if ((try tx.intervention()) == null) {
        try tx.addResponseHeader("Content-Type", response_type);
        if (response_body) |resp| {
            var length_buffer: [20]u8 = undefined;
            const length = std.fmt.bufPrint(&length_buffer, "{d}", .{resp.len}) catch unreachable;
            try tx.addResponseHeader("Content-Length", length);
        }
        try tx.processResponseHeaders(response_status, "HTTP/1.1");
        try tx.evaluatePhase(gpa, .response_headers);
        if ((try tx.intervention()) == null) {
            if (response_body) |resp| try tx.writeResponseBody(resp);
            try tx.processResponseBody();
            try tx.evaluatePhase(gpa, .response_body);
        }
    }

    if (try tx.intervention()) |decision| {
        std.debug.print("BLOCKED  action={s} status={d}{s}\n", .{
            @tagName(decision.action),
            decision.status,
            if (decision.enforced) "" else "  (detection-only)",
        });
    } else {
        std.debug.print("ALLOWED\n", .{});
    }
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
            const root = configRoot(io, gpa, path);
            defer if (root) |value| gpa.free(value);
            var provider_storage: DataFileProvider = undefined;
            var provider: ?waf.plan.DataProvider = null;
            if (root) |value| {
                provider_storage = .{ .io = io, .root = value };
                provider = provider_storage.provider();
            }
            const compiled = waf.plan.compileWithProvider(gpa, &parsed.registry, &documents, .{}, provider) catch |failure| {
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
