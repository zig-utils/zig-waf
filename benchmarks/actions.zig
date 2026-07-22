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

pub fn main(init: std.process.Init) !void {
    for (scenarios) |scenario| try runScenario(init, scenario);
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
