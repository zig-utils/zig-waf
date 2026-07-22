const std = @import("std");
const waf = @import("waf");

const iterations = 5_000;

const Scenario = struct {
    name: []const u8,
    input: []const u8,
    persistent: bool = false,
    captures: []const ?waf.CaptureRange = &.{},
};

const scenarios = [_]Scenario{
    .{
        .name = "metadata",
        .input = "SecRule ARGS @rx \"id:1,msg:'metadata',tag:'benchmark',log\"\n",
    },
    .{
        .name = "tx_scoring",
        .input = "SecRule ARGS @rx \"id:2,msg:'score=%{TX.score}',setvar:'tx.score=1',setvar:'tx.score=+5',setvar:'tx.copy=%{TX.score}',setenv:'SCORE=%{TX.score}',auditlog\"\n",
    },
    .{
        .name = "capture",
        .input = "SecRule ARGS @rx \"id:3,msg:'capture',capture,nolog\"\n",
        .captures = &.{ .{ .start = 0, .end = 16 }, .{ .start = 0, .end = 4 }, null, .{ .start = 8, .end = 16 } },
    },
    .{
        .name = "persistent_staging",
        .input = "SecRule ARGS @rx \"id:4,initcol:'ip=%{REMOTE_ADDR}',setvar:'ip.score=1',setvar:'ip.score=+5',deprecatevar:'ip.score=1/60',expirevar:'ip.score=300'\"\n",
        .persistent = true,
    },
    .{
        .name = "deny_decision",
        .input = "SecRule ARGS @rx \"id:5,msg:'denied',deny,status:403\"\n",
    },
    .{
        .name = "redirect_decision",
        .input = "SecRule ARGS @rx \"id:6,setvar:'tx.path=blocked',redirect:'https://example.test/%{TX.path}',status:307\"\n",
    },
    .{
        .name = "runtime_controls",
        .input = "SecRule ARGS @rx \"id:7,ctl:auditEngine=On,ctl:auditLogParts=ABCFHZ,ctl:ruleRemoveById=100-200,ctl:ruleRemoveByTag=benchmark,ctl:ruleRemoveTargetById=300;ARGS:secret\"\n",
    },
};

const FlowTargetProbe = struct {
    rule_index: usize,
    target: []const u8,
    expected: bool,
};

const FlowScenario = struct {
    name: []const u8,
    input: []const u8,
    commit_first: bool = false,
    target_probe: ?FlowTargetProbe = null,
};

const flow_scenarios = [_]FlowScenario{
    .{
        .name = "cursor_noop",
        .input =
        \\SecRule ARGS @rx "id:100,phase:1"
        \\SecRule ARGS @rx "id:101,phase:1"
        \\SecRule ARGS @rx "id:102,phase:1"
        \\SecRule ARGS @rx "id:103,phase:1"
        \\SecRule ARGS @rx "id:104,phase:1"
        \\SecRule ARGS @rx "id:105,phase:1"
        \\SecRule ARGS @rx "id:106,phase:1"
        \\SecRule ARGS @rx "id:107,phase:1"
        ,
    },
    .{
        .name = "cursor_exclusion_heavy",
        .input =
        \\SecRule ARGS @rx "id:200,phase:1,ctl:ruleRemoveById=201-206,ctl:ruleRemoveByTag=skip-me,ctl:ruleRemoveTargetById=209;ARGS:/^secret\./"
        \\SecRule ARGS @rx "id:201,phase:1"
        \\SecRule ARGS @rx "id:202,phase:1"
        \\SecRule ARGS @rx "id:203,phase:1"
        \\SecRule ARGS @rx "id:204,phase:1"
        \\SecRule ARGS @rx "id:205,phase:1"
        \\SecRule ARGS @rx "id:206,phase:1"
        \\SecRule ARGS @rx "id:207,phase:1,tag:'skip-me'"
        \\SecRule ARGS @rx "id:208,phase:1"
        \\SecRule ARGS @rx "id:209,phase:1"
        ,
        .commit_first = true,
        .target_probe = .{ .rule_index = 9, .target = "ARGS:secret.value", .expected = true },
    },
    .{
        .name = "cursor_dynamic_skip_after",
        .input =
        \\SecRule ARGS @rx "id:300,phase:1,setvar:'tx.marker=END',skipAfter:'%{TX.marker}'"
        \\SecRule ARGS @rx "id:301,phase:1"
        \\SecRule ARGS @rx "id:302,phase:1"
        \\SecRule ARGS @rx "id:303,phase:1"
        \\SecRule ARGS @rx "id:304,phase:1"
        \\SecMarker END
        \\SecRule ARGS @rx "id:305,phase:1"
        ,
        .commit_first = true,
    },
};

pub fn main(init: std.process.Init) !void {
    for (scenarios) |scenario| try runScenario(init, scenario);
    for (flow_scenarios) |scenario| try runFlowScenario(init, scenario);
}

fn runScenario(init: std.process.Init, scenario: Scenario) !void {
    var stats: AllocationStats = .{};
    var profiling = ProfilingAllocator.init(init.gpa, &stats);
    const allocator = profiling.allocator();
    var parsed = try waf.seclang.parser.parseBytes(allocator, "action-benchmark.conf", scenario.input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]waf.seclang.parser.Document{parsed.document};
    const plan = try waf.plan.compile(allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var memory = waf.persistent.InMemoryBackend.init(allocator);
    defer memory.deinit();
    var builder = waf.Waf.Builder.init(allocator);
    builder.setIo(init.io);
    builder.setRetainedPlan(plan);
    if (scenario.persistent) builder.setPersistentBackend(memory.backend());
    const engine = try builder.build();
    defer engine.deinit() catch unreachable;

    const samples = try init.gpa.alloc(u64, iterations);
    defer init.gpa.free(samples);
    const allocations_before = stats.allocations;
    const bytes_before = stats.total_bytes;
    var effects: usize = 0;
    var evidence_bytes: usize = 0;
    const total_start = std.Io.Clock.now(.awake, init.io);
    for (samples) |*sample| {
        var tx = engine.newTransaction();
        try tx.processConnection("192.0.2.1", 54321, "198.51.100.10", 443);
        try tx.processUri("/benchmark", "POST", "HTTP/1.1");
        try tx.processRequestHeaders();
        const started = std.Io.Clock.now(.awake, init.io);
        const outcome = if (scenario.persistent)
            try tx.applyMatchedRule(@fromBackingInt(0), .{
                .name = "ARGS:benchmark",
                .value = "0123456789abcdef",
                .source = .{ .origin = .request_body, .offset = 0, .length = 16 },
                .captures = scenario.captures,
            })
        else
            try tx.applyLocalMatchedRule(@fromBackingInt(0), .{
                .name = "ARGS:benchmark",
                .value = "0123456789abcdef",
                .source = .{ .origin = .request_body, .offset = 0, .length = 16 },
                .captures = scenario.captures,
            });
        sample.* = @intCast(started.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);
        effects += outcome.effects_applied;
        const intent = tx.matchIntent(outcome.intent).?;
        evidence_bytes += intent.matched_name.len + intent.matched_value.len;
        if (intent.message) |value| evidence_bytes += value.len;
        if (intent.log_data) |value| evidence_bytes += value.len;
        for (intent.tags) |value| evidence_bytes += value.len;
        tx.deinit();
    }
    const total_ns: u64 = @intCast(total_start.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);
    std.sort.heap(u64, samples, {}, std.sort.asc(u64));
    const runtime_allocations = stats.allocations - allocations_before;
    const runtime_bytes = stats.total_bytes - bytes_before;
    std.debug.print(
        "actions scenario={s} iterations={d} actions_per_second={d} p50_ns={d} p95_ns={d} p99_ns={d} allocations_per_application={d} allocated_bytes_per_application={d} evidence_bytes_per_application={d} effects_per_application={d}\n",
        .{
            scenario.name,
            iterations,
            (@as(u128, iterations) * std.time.ns_per_s) / @max(@as(u64, 1), total_ns),
            percentile(samples, 50),
            percentile(samples, 95),
            percentile(samples, 99),
            runtime_allocations / iterations,
            runtime_bytes / iterations,
            evidence_bytes / iterations,
            effects / iterations,
        },
    );
}

fn runFlowScenario(init: std.process.Init, scenario: FlowScenario) !void {
    var stats: AllocationStats = .{};
    var profiling = ProfilingAllocator.init(init.gpa, &stats);
    const allocator = profiling.allocator();
    var parsed = try waf.seclang.parser.parseBytes(allocator, "flow-benchmark.conf", scenario.input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]waf.seclang.parser.Document{parsed.document};
    const plan = try waf.plan.compile(allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var builder = waf.Waf.Builder.init(allocator);
    builder.setIo(init.io);
    builder.setRetainedPlan(plan);
    const engine = try builder.build();
    defer engine.deinit() catch unreachable;

    const samples = try init.gpa.alloc(u64, iterations);
    defer init.gpa.free(samples);
    var operation_allocations: usize = 0;
    var operation_bytes: usize = 0;
    var visited: usize = 0;
    const total_start = std.Io.Clock.now(.awake, init.io);
    for (samples) |*sample| {
        var tx = engine.newTransaction();
        try tx.processConnection("192.0.2.1", 54321, "198.51.100.10", 443);
        try tx.processUri("/benchmark", "GET", "HTTP/1.1");
        try tx.processRequestHeaders();
        var cursor = try waf.PhaseCursor.init(&tx, .request_headers);
        if (scenario.commit_first) {
            std.debug.assert((try cursor.next()).? == @as(waf.plan.RuleId, @fromBackingInt(0)));
            _ = try tx.applyLocalMatchedRule(@fromBackingInt(0), .{
                .name = "ARGS:benchmark",
                .value = "secret.value",
                .source = .{ .origin = .request_header, .offset = 0, .length = 12 },
            });
        }

        const allocations_before = stats.allocations;
        const bytes_before = stats.total_bytes;
        const started = std.Io.Clock.now(.awake, init.io);
        while (try cursor.next()) |rule_id| {
            visited +%= @backingInt(rule_id) + 1;
            std.mem.doNotOptimizeAway(rule_id);
        }
        if (scenario.target_probe) |probe| {
            const excluded = try tx.targetExcluded(@fromBackingInt(@as(u32, @intCast(probe.rule_index))), probe.target);
            if (excluded != probe.expected) return error.UnexpectedTargetExclusion;
            std.mem.doNotOptimizeAway(excluded);
        }
        sample.* = @intCast(started.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);
        operation_allocations += stats.allocations - allocations_before;
        operation_bytes += stats.total_bytes - bytes_before;
        tx.deinit();
    }
    const total_ns: u64 = @intCast(total_start.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);
    std.sort.heap(u64, samples, {}, std.sort.asc(u64));
    std.mem.doNotOptimizeAway(visited);
    std.debug.print(
        "flow scenario={s} iterations={d} iterations_per_second={d} p50_ns={d} p95_ns={d} p99_ns={d} operation_allocations_per_iteration={d} operation_bytes_per_iteration={d}\n",
        .{
            scenario.name,
            iterations,
            (@as(u128, iterations) * std.time.ns_per_s) / @max(@as(u64, 1), total_ns),
            percentile(samples, 50),
            percentile(samples, 95),
            percentile(samples, 99),
            operation_allocations / iterations,
            operation_bytes / iterations,
        },
    );
}

fn percentile(sorted: []const u64, percent: usize) u64 {
    const index = @min(sorted.len - 1, (sorted.len * percent + 99) / 100 - 1);
    return sorted[index];
}

const AllocationStats = struct {
    allocations: usize = 0,
    total_bytes: usize = 0,
};

const ProfilingAllocator = struct {
    parent: std.mem.Allocator,
    stats: *AllocationStats,

    fn init(parent: std.mem.Allocator, stats: *AllocationStats) ProfilingAllocator {
        return .{ .parent = parent, .stats = stats };
    }

    fn allocator(self: *ProfilingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(context: *anyopaque, length: usize, alignment: std.mem.Alignment, return_address: usize) ?[*]u8 {
        const self: *ProfilingAllocator = @ptrCast(@alignCast(context));
        const result = self.parent.rawAlloc(length, alignment, return_address);
        if (result != null) {
            self.stats.allocations += 1;
            self.stats.total_bytes += length;
        }
        return result;
    }

    fn resize(context: *anyopaque, buffer: []u8, alignment: std.mem.Alignment, new_length: usize, return_address: usize) bool {
        const self: *ProfilingAllocator = @ptrCast(@alignCast(context));
        if (!self.parent.rawResize(buffer, alignment, new_length, return_address)) return false;
        if (new_length > buffer.len) self.stats.total_bytes += new_length - buffer.len;
        return true;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(context: *anyopaque, buffer: []u8, alignment: std.mem.Alignment, return_address: usize) void {
        const self: *ProfilingAllocator = @ptrCast(@alignCast(context));
        self.parent.rawFree(buffer, alignment, return_address);
    }
};
