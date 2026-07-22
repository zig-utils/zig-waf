const std = @import("std");
const waf = @import("waf");

const sample =
    \\SecDefaultAction "phase:2,pass,t:lowercase"
    \\SecRule ARGS|REQUEST_HEADERS:host "@contains attack" "id:1001,msg:'attack',deny,chain"
    \\SecRule TX:score "@pm select union" "capture,setvar:tx.hit=1"
    \\SecRule RESPONSE_HEADERS:content-type "@beginsWith text/" "id:1002,phase:3,pass"
    \\SecMarker END
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

    var parsed = try waf.seclang.parser.parseBytes(init.gpa, "plan-benchmark.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]waf.seclang.parser.Document{parsed.document};
    const baseline = try waf.plan.compile(init.gpa, &parsed.registry, &documents, .{});
    defer baseline.deinit();

    const target_bytes = 32 * 1024 * 1024;
    const iterations = @min(@as(usize, 20_000), @max(@as(usize, 10), target_bytes / @max(input.len, 1)));
    const compile_start = std.Io.Clock.now(.awake, init.io);
    for (0..iterations) |_| {
        const compiled = try waf.plan.compile(init.gpa, &parsed.registry, &documents, .{});
        compiled.deinit();
    }
    const compile_ns: u64 = @intCast(compile_start.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);
    const rules_total = baseline.rules.len * iterations;
    const directives_total = baseline.directives.len * iterations;

    var phase_checksum: u64 = 0;
    const traversal_iterations: usize = @max(10_000, 1_000_000 / @max(baseline.rules.len, 1));
    const traversal_start = std.Io.Clock.now(.awake, init.io);
    for (0..traversal_iterations) |_| {
        for (1..6) |phase| for (baseline.phaseRules(@intCast(phase))) |rule_id| {
            std.mem.doNotOptimizeAway(rule_id);
            phase_checksum +%= @backingInt(rule_id) + 1;
        };
    }
    const traversal_ns: u64 = @intCast(traversal_start.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);
    const traversed_rules = baseline.rules.len * traversal_iterations;

    const reuse_start = std.Io.Clock.now(.awake, init.io);
    const reused = try waf.plan.compileWithPrevious(init.gpa, &parsed.registry, &documents, .{}, baseline);
    const reuse_ns: u64 = @intCast(reuse_start.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);
    defer reused.deinit();
    if (baseline.sharedReferenceCount() != 2) return error.PlanBenchmarkReuseFailed;

    var initial_builder = waf.Waf.Builder.init(init.gpa);
    initial_builder.setRetainedPlan(baseline);
    const runtime = try initial_builder.buildRuntime();
    const publication_iterations: usize = 1000;
    const generations = try init.gpa.alloc(*waf.Waf, publication_iterations);
    defer init.gpa.free(generations);
    const retired_generations = try init.gpa.alloc(waf.RetiredGeneration, publication_iterations);
    defer init.gpa.free(retired_generations);
    for (generations) |*generation| {
        var replacement_builder = waf.Waf.Builder.init(init.gpa);
        replacement_builder.setRetainedPlan(reused);
        generation.* = try replacement_builder.build();
    }
    const publish_start = std.Io.Clock.now(.awake, init.io);
    for (generations, retired_generations) |generation, *retired| retired.* = try runtime.reload(generation);
    const publication_total_ns: u64 = @intCast(publish_start.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);
    for (retired_generations) |*retired| try retired.tryReclaim();
    try runtime.deinit();

    const referenced_string_bytes = referencedStringBytes(baseline);
    const dedup_saved_bytes = referenced_string_bytes -| baseline.string_bytes.len;
    std.debug.print(
        "plan input_bytes={d} iterations={d} directives={d} rules={d} compile_nanoseconds={d} plans_per_second={d} directives_per_second={d} rules_per_second={d} owned_bytes={d} bytes_per_rule={d} unique_strings={d} interned_string_bytes={d} referenced_string_bytes={d} dedup_saved_bytes={d} phase_traversal_nanoseconds={d} phase_traversal_rules_per_second={d} reuse_compile_nanoseconds={d} publication_iterations={d} publication_total_nanoseconds={d} publication_nanoseconds={d} checksum={d}\n",
        .{
            input.len,
            iterations,
            baseline.directives.len,
            baseline.rules.len,
            compile_ns,
            rate(iterations, compile_ns),
            rate(directives_total, compile_ns),
            rate(rules_total, compile_ns),
            baseline.owned_bytes,
            if (baseline.rules.len == 0) 0 else baseline.owned_bytes / baseline.rules.len,
            baseline.strings.len,
            baseline.string_bytes.len,
            referenced_string_bytes,
            dedup_saved_bytes,
            traversal_ns,
            rate(traversed_rules, traversal_ns),
            reuse_ns,
            publication_iterations,
            publication_total_ns,
            publication_total_ns / publication_iterations,
            phase_checksum,
        },
    );
}

fn rate(count: usize, nanoseconds: u64) u128 {
    return if (nanoseconds == 0) 0 else (@as(u128, count) * std.time.ns_per_s) / nanoseconds;
}

fn referencedStringBytes(plan: *const waf.plan.Plan) usize {
    var total: usize = 0;
    for (plan.directives) |directive| total += plan.string(directive.name).?.len;
    for (plan.arguments) |argument| total += plan.string(argument.raw).?.len;
    for (plan.targets) |target| {
        total += plan.string(target.raw).?.len + plan.string(target.collection).?.len;
        if (target.selector) |selector| total += plan.string(selector).?.len;
    }
    for (plan.rules) |rule| {
        total += plan.string(rule.operator.raw).?.len;
        total += plan.string(rule.operator.name).?.len;
        total += plan.string(rule.operator.parameter).?.len;
    }
    for (plan.actions) |action| {
        total += plan.string(action.raw).?.len + plan.string(action.name).?.len;
        if (action.value) |value| total += plan.string(value).?.len;
    }
    for (plan.transformations) |transformation| total += plan.string(transformation.name).?.len;
    for (plan.prefilter_literals) |literal| total += plan.string(literal).?.len;
    return total;
}
