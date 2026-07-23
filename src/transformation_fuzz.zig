//! Reusable deterministic and coverage-guided transformation oracle.

const std = @import("std");
const transformations = @import("transformations.zig");

pub fn fuzzOne(allocator: std.mem.Allocator, input: []const u8) !void {
    if (input.len > 64 * 1024) return error.TransformationFuzzInputTooLarge;
    const expansion = std.math.mul(usize, @max(input.len, 1), 8) catch return error.TransformationFuzzInputTooLarge;
    const max_output = @max(expansion, 64);
    const max_cumulative = std.math.mul(usize, max_output, 32) catch return error.TransformationFuzzInputTooLarge;
    const limits = transformations.Limits{
        .max_input_bytes = @max(input.len, 1),
        .max_output_bytes = max_output,
        .max_pipeline_steps = 32,
        .max_cumulative_output_bytes = max_cumulative,
        .max_cache_entries = 8,
        .max_cache_bytes = @max(max_cumulative, 1024),
    };

    inline for (std.meta.tags(transformations.Profile)) |profile| {
        var first = try transformations.Executor.initWithProfile(allocator, limits, profile);
        defer first.deinit();
        var second = try transformations.Executor.initWithProfile(allocator, limits, profile);
        defer second.deinit();
        for (transformations.specs) |spec| try compareStep(&first, &second, spec.kind, input);

        var pipeline_storage: [32]transformations.Kind = undefined;
        const pipeline = derivePipeline(&pipeline_storage, input, profile);
        try comparePipeline(&first, &second, pipeline, input, false);
        try comparePipeline(&first, &second, pipeline, input, true);

        var cached = try transformations.Executor.initWithOptions(allocator, limits, .{
            .profile = profile,
            .cache_enabled = true,
        });
        defer cached.deinit();
        const cache_pipeline = [_]transformations.Kind{ .url_decode, .lowercase, .trim };
        const initial = try cached.applyPipeline(&cache_pipeline, input, true);
        const hit = try cached.applyPipeline(&cache_pipeline, input, true);
        try equalPipeline(initial, hit);
        if (cached.cacheStats().status == .enabled) {
            try std.testing.expectEqual(@as(u64, 1), cached.cacheStats().hits);
            try std.testing.expectEqual(transformations.Storage.cache, hit.storage);
        }
    }

    const tight_output = if (input.len == 0) 1 else 1 + @as(usize, input[0]) % @min(input.len, 255);
    const tight_cumulative = std.math.add(usize, @max(input.len, 1), tight_output) catch return;
    var tight = try transformations.Executor.initWithProfile(allocator, .{
        .max_input_bytes = @max(input.len, 1),
        .max_output_bytes = tight_output,
        .max_pipeline_steps = 32,
        .max_cumulative_output_bytes = tight_cumulative,
        .max_cache_entries = 1,
        .max_cache_bytes = 1,
    }, .modsecurity);
    defer tight.deinit();
    var pipeline_storage: [32]transformations.Kind = undefined;
    const pipeline = derivePipeline(&pipeline_storage, input, .modsecurity);
    _ = tight.applyPipeline(pipeline, input, true) catch |err| switch (err) {
        error.OutputTooLarge, error.CumulativeOutputTooLarge, error.InvalidInput => return,
        else => return err,
    };
}

fn compareStep(
    first: *transformations.Executor,
    second: *transformations.Executor,
    kind: transformations.Kind,
    input: []const u8,
) !void {
    const left = first.apply(kind, input) catch |left_error| {
        _ = second.apply(kind, input) catch |right_error| {
            if (left_error != right_error) return error.NondeterministicTransformationError;
            return allowed(left_error);
        };
        return error.NondeterministicTransformationSuccess;
    };
    const right = second.apply(kind, input) catch return error.NondeterministicTransformationSuccess;
    try std.testing.expectEqual(left.changed, right.changed);
    try std.testing.expectEqual(left.storage, right.storage);
    try std.testing.expectEqualSlices(u8, left.bytes, right.bytes);
}

fn comparePipeline(
    first: *transformations.Executor,
    second: *transformations.Executor,
    pipeline: []const transformations.Kind,
    input: []const u8,
    multi_match: bool,
) !void {
    const left = first.applyPipeline(pipeline, input, multi_match) catch |left_error| {
        _ = second.applyPipeline(pipeline, input, multi_match) catch |right_error| {
            if (left_error != right_error) return error.NondeterministicPipelineError;
            return allowed(left_error);
        };
        return error.NondeterministicPipelineSuccess;
    };
    const right = second.applyPipeline(pipeline, input, multi_match) catch return error.NondeterministicPipelineSuccess;
    try equalPipeline(left, right);
}

fn equalPipeline(left: transformations.PipelineResult, right: transformations.PipelineResult) !void {
    try std.testing.expectEqual(left.changed, right.changed);
    try std.testing.expectEqual(left.steps_executed, right.steps_executed);
    try std.testing.expectEqual(left.cumulative_bytes, right.cumulative_bytes);
    try std.testing.expectEqualSlices(u8, left.bytes, right.bytes);
    try std.testing.expectEqual(left.checkpoints.len, right.checkpoints.len);
    for (left.checkpoints, right.checkpoints) |left_checkpoint, right_checkpoint| {
        try std.testing.expectEqual(left_checkpoint.after_step, right_checkpoint.after_step);
        try std.testing.expectEqualSlices(u8, left_checkpoint.bytes, right_checkpoint.bytes);
    }
}

fn derivePipeline(storage: *[32]transformations.Kind, input: []const u8, profile: transformations.Profile) []const transformations.Kind {
    var hasher = std.hash.Wyhash.init(@as(u64, 0x5741462d3136) + @as(u64, @backingInt(profile)));
    hasher.update(input);
    var state = hasher.final();
    const length: usize = @intCast(state % (storage.len + 1));
    for (storage[0..length], 0..) |*kind, index| {
        const mixed = if (input.len == 0) state else state ^ input[index % input.len];
        kind.* = @fromBackingInt(@intCast(mixed % transformations.specs.len));
        state = state *% 0x9e3779b97f4a7c15 +% index +% 1;
    }
    return storage[0..length];
}

fn allowed(err: transformations.ApplyError) !void {
    return switch (err) {
        error.InvalidInput, error.OutputTooLarge, error.CumulativeOutputTooLarge => {},
        else => err,
    };
}

test "transformation fuzz oracle covers binary decoders and ordered pipelines" {
    const cases = [_][]const u8{
        "",
        "ordinary ASCII",
        "%uFF01%41+&NotEqualTilde;\\x41/*comment*/0x4142",
        "\x00\xff\xc0\xaf\xed\xa0\x80\xe2(\xa1",
        "../a//b/../../c\\d",
    };
    for (cases) |case| try fuzzOne(std.testing.allocator, case);
}
