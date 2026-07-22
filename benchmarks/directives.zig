const std = @import("std");
const waf = @import("waf");

const sample =
    \\SecRuleEngine DetectionOnly
    \\SecRequestBodyAccess On
    \\SecRequestBodyLimit 1048576
    \\SecResponseBodyMimeTypesClear
    \\SecResponseBodyMimeType application/json text/plain
    \\SecAuditEngine RelevantOnly
    \\SecRule ARGS "@contains attack" "id:1001,deny"
;

pub fn main(init: std.process.Init) !void {
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    _ = arguments.next();
    const external_path = arguments.next();
    const input = if (external_path) |path|
        try std.Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(32 * 1024 * 1024))
    else
        try init.gpa.dupe(u8, sample);
    defer init.gpa.free(input);

    var parsed = try waf.seclang.parser.parseBytes(init.gpa, "directive-benchmark.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]waf.seclang.parser.Document{parsed.document};
    const compiled = try waf.plan.compile(init.gpa, &parsed.registry, &documents, .{});
    defer compiled.deinit();
    if (waf.directives.validatePlan(compiled, .full()) != .valid) return error.InvalidBenchmarkConfiguration;

    const target_directives: usize = 1_000_000;
    const iterations = @min(@as(usize, 100_000), @max(@as(usize, 1_000), target_directives / @max(compiled.directives.len, 1)));
    var checksum: u64 = 0;
    const validation_start = std.Io.Clock.now(.awake, init.io);
    for (0..iterations) |_| {
        switch (waf.directives.validatePlan(compiled, .full())) {
            .valid => checksum +%= 1,
            .diagnostic => return error.DirectiveBenchmarkValidationFailed,
        }
    }
    const validation_ns: u64 = @intCast(validation_start.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);

    const configuration_start = std.Io.Clock.now(.awake, init.io);
    for (0..iterations) |_| {
        const configuration = waf.directives.Configuration.init(compiled, .full()).configuration;
        checksum +%= configuration.fingerprint[0];
        std.mem.doNotOptimizeAway(configuration.fingerprint);
    }
    const configuration_ns: u64 = @intCast(configuration_start.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);
    const directive_count = compiled.directives.len * iterations;
    std.debug.print(
        "directives input_bytes={d} directives={d} iterations={d} validation_nanoseconds={d} validations_per_second={d} validated_directives_per_second={d} configuration_nanoseconds={d} configurations_per_second={d} configured_directives_per_second={d} checksum={d}\n",
        .{
            input.len,
            compiled.directives.len,
            iterations,
            validation_ns,
            rate(iterations, validation_ns),
            rate(directive_count, validation_ns),
            configuration_ns,
            rate(iterations, configuration_ns),
            rate(directive_count, configuration_ns),
            checksum,
        },
    );
}

fn rate(count: usize, nanoseconds: u64) u128 {
    return if (nanoseconds == 0) 0 else (@as(u128, count) * std.time.ns_per_s) / nanoseconds;
}
