const std = @import("std");
const waf = @import("waf");
const transformations = waf.transformations;

const iterations = 200_000;

const Kind = transformations.Kind;
const Executor = transformations.Executor;

/// Wraps a backing allocator and counts allocation calls and requested bytes so
/// the benchmark can prove which steady-state hot paths avoid per-op allocation.
const Counting = struct {
    backing: std.mem.Allocator,
    allocs: u64 = 0,
    bytes: u64 = 0,

    fn allocator(self: *Counting) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn reset(self: *Counting) void {
        self.allocs = 0;
        self.bytes = 0;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.allocs += 1;
        self.bytes += len;
        return self.backing.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        return self.backing.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        return self.backing.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(memory, alignment, ret_addr);
    }
};

fn timeStep(io: std.Io, executor: *Executor, kind: Kind, input: []const u8) u64 {
    const start = std.Io.Clock.now(.awake, io);
    for (0..iterations) |_| {
        const result = executor.apply(kind, input) catch unreachable;
        std.mem.doNotOptimizeAway(result.bytes.ptr);
        std.mem.doNotOptimizeAway(result.bytes.len);
    }
    const elapsed: u64 = @intCast(start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    return elapsed / iterations;
}

fn timePipeline(io: std.Io, executor: *Executor, pipeline: []const Kind, input: []const u8, multi_match: bool) u64 {
    const start = std.Io.Clock.now(.awake, io);
    for (0..iterations) |_| {
        const result = executor.applyPipeline(pipeline, input, multi_match) catch unreachable;
        std.mem.doNotOptimizeAway(result.bytes.ptr);
        std.mem.doNotOptimizeAway(result.checkpoints.len);
    }
    const elapsed: u64 = @intCast(start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    return elapsed / iterations;
}

const Percentiles = struct { p50: u64, p95: u64, p99: u64 };

/// Per-operation latency percentiles. Meaningful only for paths whose cost is
/// large relative to the clock-read overhead (the CRS pipeline and cache miss);
/// request-path percentile gates belong to WAF-39.
fn percentiles(samples: []u64) Percentiles {
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    return .{
        .p50 = samples[samples.len / 2],
        .p95 = samples[samples.len * 95 / 100],
        .p99 = samples[samples.len * 99 / 100],
    };
}

fn samplePipeline(io: std.Io, executor: *Executor, pipeline: []const Kind, input: []const u8, samples: []u64) Percentiles {
    for (samples) |*sample| {
        const start = std.Io.Clock.now(.awake, io);
        const result = executor.applyPipeline(pipeline, input, false) catch unreachable;
        std.mem.doNotOptimizeAway(result.bytes.ptr);
        sample.* = @intCast(start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    }
    return percentiles(samples);
}

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var counting = Counting{ .backing = std.heap.page_allocator };
    const allocator = counting.allocator();
    const limits = transformations.Limits{};

    var executor = try Executor.initWithProfile(allocator, limits, .coraza);
    defer executor.deinit();

    // Borrowed, allocation-free no-op: already-lowercase ASCII stays borrowed.
    const borrowed_input = "already lowercase argument value";
    counting.reset();
    const borrowed_ns = timeStep(io, &executor, .lowercase, borrowed_input);
    const borrowed_allocs = counting.allocs;
    const borrowed_out = (try executor.apply(.lowercase, borrowed_input)).bytes.len;

    // Decoder-heavy percent- and entity-encoded payload.
    const decoder_unit = "%3Cscript%3Ealert%281%29%3C%2Fscript%3E&amp;%26%23x41%3B";
    const decoder_input = decoder_unit ++ decoder_unit ++ decoder_unit ++ decoder_unit;
    const url_decode_ns = timeStep(io, &executor, .url_decode_uni, decoder_input);
    const entity_decode_ns = timeStep(io, &executor, .html_entity_decode, decoder_input);
    const decoder_out = (try executor.apply(.url_decode_uni, decoder_input)).bytes.len;

    // Path normalization over a traversal-heavy path.
    const path_input = "/var/www//../../etc/./passwd/../../a/b/c/../../d";
    const path_ns = timeStep(io, &executor, .normalise_path, path_input);

    // Digest transforms over a representative header value.
    const digest_input = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 zig-waf/1.0";
    const sha1_ns = timeStep(io, &executor, .sha1, digest_input);
    const md5_ns = timeStep(io, &executor, .md5, digest_input);

    // A representative CRS request-argument pipeline.
    const crs_pipeline = [_]Kind{
        .url_decode_uni,
        .html_entity_decode,
        .js_decode,
        .css_decode,
        .remove_nulls,
        .compress_whitespace,
        .lowercase,
    };
    const crs_input = "  %3CIMG%20SRC%3Djavascript:alert(&#x27;xss&#x27;)%3E  ";
    // Warm the retained executor buffers, then measure steady-state allocations.
    _ = try executor.applyPipeline(&crs_pipeline, crs_input, false);
    counting.reset();
    const crs_ns = timePipeline(io, &executor, &crs_pipeline, crs_input, false);
    const crs_allocs = counting.allocs;
    const crs_out = (try executor.applyPipeline(&crs_pipeline, crs_input, false)).bytes.len;
    const crs_multi_ns = timePipeline(io, &executor, &crs_pipeline, crs_input, true);

    // Per-operation latency distribution for the CRS pipeline.
    const samples = try allocator.alloc(u64, iterations);
    defer allocator.free(samples);
    const crs_pct = samplePipeline(io, &executor, &crs_pipeline, crs_input, samples);

    // Cache hit throughput: identical pipeline and input keep hitting the LRU.
    var cached = try Executor.initWithOptions(allocator, limits, .{
        .profile = .coraza,
        .cache_enabled = true,
    });
    defer cached.deinit();
    _ = try cached.applyPipeline(&crs_pipeline, crs_input, false);
    const cache_hit_ns = timePipeline(io, &cached, &crs_pipeline, crs_input, false);
    const hit_stats = cached.cacheStats();

    // Cache miss throughput: a fresh input every iteration forces recompute and eviction.
    var miss = try Executor.initWithOptions(allocator, limits, .{
        .profile = .coraza,
        .cache_enabled = true,
    });
    defer miss.deinit();
    var scratch: [64]u8 = undefined;
    const miss_start = std.Io.Clock.now(.awake, io);
    for (samples, 0..) |*sample, index| {
        const rendered = std.fmt.bufPrint(&scratch, "  arg-{d}-value  ", .{index}) catch unreachable;
        const op_start = std.Io.Clock.now(.awake, io);
        const result = miss.applyPipeline(&crs_pipeline, rendered, false) catch unreachable;
        std.mem.doNotOptimizeAway(result.bytes.ptr);
        sample.* = @intCast(op_start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    }
    const miss_elapsed: u64 = @intCast(miss_start.durationTo(std.Io.Clock.now(.awake, io)).nanoseconds);
    const cache_miss_ns = miss_elapsed / iterations;
    const miss_pct = percentiles(samples);
    const miss_stats = miss.cacheStats();

    std.debug.print(
        "transformations iterations={d}" ++
            " borrowed_noop_ns={d} borrowed_allocs={d} borrowed_out_bytes={d}" ++
            " url_decode_uni_ns={d} html_entity_decode_ns={d} decoder_out_bytes={d}" ++
            " normalise_path_ns={d}" ++
            " sha1_ns={d} md5_ns={d}" ++
            " crs_pipeline_ns={d} crs_steady_allocs={d} crs_out_bytes={d} crs_multimatch_ns={d}" ++
            " crs_p50_ns={d} crs_p95_ns={d} crs_p99_ns={d}" ++
            " cache_hit_ns={d} cache_hits={d}" ++
            " cache_miss_ns={d} cache_miss_p50_ns={d} cache_miss_p95_ns={d} cache_miss_p99_ns={d}" ++
            " cache_misses={d} cache_evictions={d}\n",
        .{
            iterations,
            borrowed_ns,
            borrowed_allocs,
            borrowed_out,
            url_decode_ns,
            entity_decode_ns,
            decoder_out,
            path_ns,
            sha1_ns,
            md5_ns,
            crs_ns,
            crs_allocs,
            crs_out,
            crs_multi_ns,
            crs_pct.p50,
            crs_pct.p95,
            crs_pct.p99,
            cache_hit_ns,
            hit_stats.hits,
            cache_miss_ns,
            miss_pct.p50,
            miss_pct.p95,
            miss_pct.p99,
            miss_stats.misses,
            miss_stats.evictions,
        },
    );
}
