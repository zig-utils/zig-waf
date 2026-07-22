const std = @import("std");
const waf = @import("waf");

const sample =
    \\SecDefaultAction "phase:1,log,pass"
    \\SecRule REQUEST_HEADERS:Content-Type "!@rx ^application/json" "id:1001,phase:1,deny,status:415"
    \\SecRule ARGS|!ARGS:token "@rx (?i)(?:select|union)" \
    \\    "id:1002,phase:2,log,deny,msg:'SQL syntax, benchmark',tag:'parser'"
    \\SecAction "id:1003,phase:2,setvar:tx.score=+1,pass"
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

    const target_bytes = 128 * 1024 * 1024;
    const iterations = @min(@as(usize, 50_000), @max(@as(usize, 10), target_bytes / @max(input.len, 1)));
    var stats: AllocationStats = .{};
    var profiling = ProfilingAllocator.init(std.heap.page_allocator, &stats);
    const allocator = profiling.allocator();
    var directive_count: usize = 0;
    const start = std.Io.Clock.now(.awake, init.io);
    for (0..iterations) |_| {
        var parsed = try waf.seclang.parser.parseBytes(allocator, "benchmark.conf", input, .{}, .{});
        directive_count += parsed.document.directives.items.len;
        parsed.deinit();
    }
    const elapsed: u64 = @intCast(start.durationTo(std.Io.Clock.now(.awake, init.io)).nanoseconds);
    if (stats.current_bytes != 0) return error.ParserBenchmarkLeak;
    const total_bytes = input.len * iterations;
    const bytes_per_second = if (elapsed == 0) 0 else (@as(u128, total_bytes) * std.time.ns_per_s) / elapsed;
    const directives_per_second = if (elapsed == 0) 0 else (@as(u128, directive_count) * std.time.ns_per_s) / elapsed;
    std.debug.print(
        "parser input_bytes={d} iterations={d} directives={d} bytes_per_second={d} directives_per_second={d} allocations_per_parse={d} peak_owned_bytes={d}\n",
        .{
            input.len,
            iterations,
            directive_count,
            bytes_per_second,
            directives_per_second,
            stats.allocations / iterations,
            stats.peak_bytes,
        },
    );
}

const AllocationStats = struct {
    allocations: usize = 0,
    total_bytes: usize = 0,
    current_bytes: usize = 0,
    peak_bytes: usize = 0,
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
            self.stats.current_bytes += length;
            self.stats.peak_bytes = @max(self.stats.peak_bytes, self.stats.current_bytes);
        }
        return result;
    }

    fn resize(context: *anyopaque, buffer: []u8, alignment: std.mem.Alignment, new_length: usize, return_address: usize) bool {
        const self: *ProfilingAllocator = @ptrCast(@alignCast(context));
        if (!self.parent.rawResize(buffer, alignment, new_length, return_address)) return false;
        if (new_length > buffer.len) {
            const added = new_length - buffer.len;
            self.stats.total_bytes += added;
            self.stats.current_bytes += added;
            self.stats.peak_bytes = @max(self.stats.peak_bytes, self.stats.current_bytes);
        } else {
            self.stats.current_bytes -= buffer.len - new_length;
        }
        return true;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(context: *anyopaque, buffer: []u8, alignment: std.mem.Alignment, return_address: usize) void {
        const self: *ProfilingAllocator = @ptrCast(@alignCast(context));
        self.parent.rawFree(buffer, alignment, return_address);
        self.stats.current_bytes -= buffer.len;
    }
};
