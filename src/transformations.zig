//! Stable SecLang transformation inventory and canonical name resolution.

const std = @import("std");
const html_entities = @import("html_entities.zig");

pub const Kind = enum(u8) {
    base64_decode,
    base64_decode_ext,
    base64_encode,
    cmd_line,
    compress_whitespace,
    css_decode,
    escape_seq_decode,
    hex_decode,
    hex_encode,
    html_entity_decode,
    js_decode,
    length,
    lowercase,
    md5,
    normalise_path,
    normalise_path_win,
    parity_even_7bit,
    parity_odd_7bit,
    parity_zero_7bit,
    remove_comments,
    remove_comments_char,
    remove_nulls,
    remove_whitespace,
    replace_comments,
    replace_nulls,
    sha1,
    sql_hex_decode,
    trim,
    trim_left,
    trim_right,
    uppercase,
    url_decode,
    url_decode_uni,
    url_encode,
    utf8_to_unicode,

    pub fn canonicalName(self: Kind) []const u8 {
        return specs[@backingInt(self)].name;
    }
};

pub const Resolution = union(enum) {
    reset,
    builtin: Kind,

    pub fn canonicalName(self: Resolution) []const u8 {
        return switch (self) {
            .reset => "none",
            .builtin => |kind| kind.canonicalName(),
        };
    }
};

pub const Spec = struct {
    kind: Kind,
    name: []const u8,
};

pub const Alias = struct {
    name: []const u8,
    kind: Kind,
};

pub const specs = [_]Spec{
    .{ .kind = .base64_decode, .name = "base64Decode" },
    .{ .kind = .base64_decode_ext, .name = "base64DecodeExt" },
    .{ .kind = .base64_encode, .name = "base64Encode" },
    .{ .kind = .cmd_line, .name = "cmdLine" },
    .{ .kind = .compress_whitespace, .name = "compressWhitespace" },
    .{ .kind = .css_decode, .name = "cssDecode" },
    .{ .kind = .escape_seq_decode, .name = "escapeSeqDecode" },
    .{ .kind = .hex_decode, .name = "hexDecode" },
    .{ .kind = .hex_encode, .name = "hexEncode" },
    .{ .kind = .html_entity_decode, .name = "htmlEntityDecode" },
    .{ .kind = .js_decode, .name = "jsDecode" },
    .{ .kind = .length, .name = "length" },
    .{ .kind = .lowercase, .name = "lowercase" },
    .{ .kind = .md5, .name = "md5" },
    .{ .kind = .normalise_path, .name = "normalisePath" },
    .{ .kind = .normalise_path_win, .name = "normalisePathWin" },
    .{ .kind = .parity_even_7bit, .name = "parityEven7bit" },
    .{ .kind = .parity_odd_7bit, .name = "parityOdd7bit" },
    .{ .kind = .parity_zero_7bit, .name = "parityZero7bit" },
    .{ .kind = .remove_comments, .name = "removeComments" },
    .{ .kind = .remove_comments_char, .name = "removeCommentsChar" },
    .{ .kind = .remove_nulls, .name = "removeNulls" },
    .{ .kind = .remove_whitespace, .name = "removeWhitespace" },
    .{ .kind = .replace_comments, .name = "replaceComments" },
    .{ .kind = .replace_nulls, .name = "replaceNulls" },
    .{ .kind = .sha1, .name = "sha1" },
    .{ .kind = .sql_hex_decode, .name = "sqlHexDecode" },
    .{ .kind = .trim, .name = "trim" },
    .{ .kind = .trim_left, .name = "trimLeft" },
    .{ .kind = .trim_right, .name = "trimRight" },
    .{ .kind = .uppercase, .name = "uppercase" },
    .{ .kind = .url_decode, .name = "urlDecode" },
    .{ .kind = .url_decode_uni, .name = "urlDecodeUni" },
    .{ .kind = .url_encode, .name = "urlEncode" },
    .{ .kind = .utf8_to_unicode, .name = "utf8toUnicode" },
};

pub const aliases = [_]Alias{
    .{ .name = "normalizePath", .kind = .normalise_path },
    .{ .name = "normalizePathWin", .kind = .normalise_path_win },
};

comptime {
    for (specs, 0..) |spec, index| {
        if (@backingInt(spec.kind) != index) @compileError("transformation specs must follow enum order");
    }
    for (aliases, 0..) |alias, alias_index| {
        for (specs) |spec| {
            if (std.ascii.eqlIgnoreCase(alias.name, spec.name))
                @compileError("transformation alias duplicates a canonical name");
        }
        for (aliases[0..alias_index]) |previous| {
            if (std.ascii.eqlIgnoreCase(alias.name, previous.name))
                @compileError("duplicate transformation alias");
        }
    }
}

pub fn resolve(name: []const u8) ?Resolution {
    if (std.ascii.eqlIgnoreCase(name, "none")) return .reset;
    for (specs) |spec| {
        if (std.ascii.eqlIgnoreCase(name, spec.name)) return .{ .builtin = spec.kind };
    }
    for (aliases) |alias| {
        if (std.ascii.eqlIgnoreCase(name, alias.name)) return .{ .builtin = alias.kind };
    }
    return null;
}

pub const Limits = struct {
    max_input_bytes: usize = 1024 * 1024,
    max_output_bytes: usize = 4 * 1024 * 1024,
    max_pipeline_steps: usize = 64,
    max_cumulative_output_bytes: usize = 16 * 1024 * 1024,
    max_cache_entries: usize = 256,
    max_cache_bytes: usize = 4 * 1024 * 1024,

    pub fn validate(self: Limits) error{InvalidLimits}!void {
        if (self.max_input_bytes == 0 or
            self.max_output_bytes == 0 or
            self.max_pipeline_steps == 0 or
            self.max_cumulative_output_bytes < self.max_output_bytes or
            self.max_cache_entries == 0 or
            self.max_cache_entries > std.math.maxInt(u32) or
            self.max_cache_bytes == 0)
        {
            return error.InvalidLimits;
        }
    }
};

pub const Storage = enum {
    borrowed,
    executor_a,
    executor_b,
    cache,
};

pub const Profile = enum {
    modsecurity,
    coraza,
};

/// Immutable ModSecurity Unicode-map values indexed by a 16-bit code point.
/// Negative and out-of-range entries are unmapped. The backing table must
/// outlive the executor and may be shared by request workers.
pub const UnicodeMap = struct {
    table: []const i32,

    pub fn lookup(self: UnicodeMap, code_point: u16) ?u8 {
        if (code_point >= self.table.len) return null;
        const mapped = self.table[code_point];
        if (mapped < 0) return null;
        return @truncate(@as(u32, @intCast(mapped)));
    }
};

pub const Options = struct {
    profile: Profile = .modsecurity,
    unicode_map: ?UnicodeMap = null,
    cache_enabled: bool = false,
};

pub const CacheStatus = enum {
    disabled,
    enabled,
    limit_exhausted,
    allocation_failed,
};

pub const CacheStats = struct {
    status: CacheStatus,
    entries: usize,
    bytes: usize,
    hits: u64,
    misses: u64,
    evictions: u64,
};

pub const Result = struct {
    bytes: []const u8,
    /// Upstream transformation semantics, which can differ from byte equality.
    /// For example, `length` and non-empty parity transforms always report a
    /// change, while a single compressed tab becomes a space but reports false.
    changed: bool,
    storage: Storage,
};

pub const Checkpoint = struct {
    bytes: []const u8,
    /// Null identifies the original value; otherwise this is the zero-based
    /// pipeline step whose upstream `changed` result created the checkpoint.
    after_step: ?u32,
};

pub const PipelineResult = struct {
    bytes: []const u8,
    changed: bool,
    storage: Storage,
    checkpoints: []const Checkpoint,
    steps_executed: u32,
    cumulative_bytes: usize,
};

const CheckpointRecord = struct {
    offset: usize,
    length: usize,
    after_step: ?u32,
};

const CacheEntry = struct {
    hash: u64,
    pipeline: []Kind,
    input: []u8,
    multi_match: bool,
    output: []u8,
    changed: bool,
    checkpoints: []Checkpoint,
    checkpoint_bytes: []u8,
    steps_executed: u32,
    cumulative_bytes: usize,
    owned_bytes: usize,
    last_used: u64,

    fn deinit(self: *CacheEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.pipeline);
        allocator.free(self.input);
        allocator.free(self.output);
        allocator.free(self.checkpoints);
        allocator.free(self.checkpoint_bytes);
        self.* = undefined;
    }
};

pub const ApplyError = std.mem.Allocator.Error || error{
    InvalidLimits,
    InputTooLarge,
    OutputTooLarge,
    TooManyPipelineSteps,
    CumulativeOutputTooLarge,
    InvalidInput,
    /// A frozen WAF-22 plugin callback failed. Built-ins never emit this tag.
    PluginFailure,
};

pub const FailureKind = enum {
    configuration,
    allocation,
    invalid_input,
    input_limit,
    output_limit,
    work_limit,
    plugin,
};

pub fn failureKind(err: ApplyError) FailureKind {
    return switch (err) {
        error.InvalidLimits => .configuration,
        error.OutOfMemory => .allocation,
        error.InvalidInput => .invalid_input,
        error.InputTooLarge => .input_limit,
        error.OutputTooLarge => .output_limit,
        error.TooManyPipelineSteps, error.CumulativeOutputTooLarge => .work_limit,
        error.PluginFailure => .plugin,
    };
}

/// Reusable bounded scratch for one request worker/transaction. Executor-backed
/// result bytes remain valid until that same scratch slot is reused (at least
/// one subsequent executor-backed result); borrowed results retain input life.
pub const Executor = struct {
    const Scratch = struct {
        buffer: *std.ArrayList(u8),
        storage: Storage,
    };

    allocator: std.mem.Allocator,
    limits: Limits,
    profile: Profile,
    unicode_map: ?UnicodeMap,
    buffers: [2]std.ArrayList(u8) = .{ .empty, .empty },
    checkpoint_bytes: std.ArrayList(u8) = .empty,
    checkpoints: std.ArrayList(Checkpoint) = .empty,
    cache_entries: std.ArrayList(CacheEntry) = .empty,
    cache_status: CacheStatus,
    cache_bytes: usize = 0,
    cache_clock: u64 = 0,
    cache_hits: u64 = 0,
    cache_misses: u64 = 0,
    cache_evictions: u64 = 0,
    next_buffer: usize = 0,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) error{InvalidLimits}!Executor {
        return initWithOptions(allocator, limits, .{});
    }

    pub fn initWithProfile(allocator: std.mem.Allocator, limits: Limits, profile: Profile) error{InvalidLimits}!Executor {
        return initWithOptions(allocator, limits, .{ .profile = profile });
    }

    pub fn initWithOptions(allocator: std.mem.Allocator, limits: Limits, options: Options) error{InvalidLimits}!Executor {
        try limits.validate();
        return .{
            .allocator = allocator,
            .limits = limits,
            .profile = options.profile,
            .unicode_map = options.unicode_map,
            .cache_status = if (options.cache_enabled) .enabled else .disabled,
        };
    }

    pub fn deinit(self: *Executor) void {
        for (&self.buffers) |*buffer| buffer.deinit(self.allocator);
        self.checkpoint_bytes.deinit(self.allocator);
        self.checkpoints.deinit(self.allocator);
        self.clearCacheEntries();
        self.cache_entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn cacheStats(self: *const Executor) CacheStats {
        return .{
            .status = self.cache_status,
            .entries = self.cache_entries.items.len,
            .bytes = self.cache_bytes,
            .hits = self.cache_hits,
            .misses = self.cache_misses,
            .evictions = self.cache_evictions,
        };
    }

    pub fn apply(self: *Executor, kind: Kind, input: []const u8) ApplyError!Result {
        if (input.len > self.limits.max_input_bytes) return error.InputTooLarge;
        return self.applyStep(kind, input);
    }

    fn applyStep(self: *Executor, kind: Kind, input: []const u8) ApplyError!Result {
        return switch (kind) {
            .base64_decode => self.base64Decode(input, false),
            .base64_decode_ext => self.base64Decode(input, true),
            .base64_encode => self.base64Encode(input),
            .cmd_line => self.cmdLine(input),
            .css_decode => self.cssDecode(input),
            .escape_seq_decode => self.escapeSeqDecode(input),
            .html_entity_decode => self.htmlEntityDecode(input),
            .js_decode => self.jsDecode(input),
            .lowercase => self.mapAsciiCase(input, false),
            .md5 => self.digest(input, std.crypto.hash.Md5),
            .normalise_path => self.normalisePath(input, false),
            .normalise_path_win => self.normalisePath(input, true),
            .uppercase => self.mapAsciiCase(input, true),
            .remove_comments => self.removeComments(input),
            .remove_comments_char => self.removeCommentsChar(input),
            .replace_comments => self.replaceComments(input),
            .trim => trimResult(input, true, true),
            .trim_left => trimResult(input, true, false),
            .trim_right => trimResult(input, false, true),
            .compress_whitespace => self.compressWhitespace(input),
            .remove_whitespace => self.removeBytes(input, isRemovalWhitespace),
            .remove_nulls => self.removeBytes(input, isNull),
            .replace_nulls => self.replaceNulls(input),
            .sha1 => self.digest(input, std.crypto.hash.Sha1),
            .hex_decode => self.hexDecode(input),
            .hex_encode => self.hexEncode(input),
            .sql_hex_decode => self.sqlHexDecode(input),
            .url_decode => self.urlDecode(input),
            .url_decode_uni => self.urlDecodeUni(input),
            .url_encode => self.urlEncode(input),
            .utf8_to_unicode => self.utf8ToUnicode(input),
            .parity_even_7bit => self.parity(input, true),
            .parity_odd_7bit => self.parity(input, false),
            .parity_zero_7bit => self.parityZero(input),
            .length => self.length(input),
        };
    }

    pub fn applyPipeline(self: *Executor, pipeline: anytype, input: []const u8, multi_match: bool) ApplyError!PipelineResult {
        if (input.len > self.limits.max_input_bytes) return error.InputTooLarge;
        if (pipeline.len > self.limits.max_pipeline_steps) return error.TooManyPipelineSteps;
        var cache_hash: u64 = 0;
        if (self.cache_status == .enabled) {
            cache_hash = pipelineHash(pipeline, input, multi_match);
            if (self.findCacheEntry(pipeline, input, multi_match, cache_hash)) |entry| {
                self.cache_hits +|= 1;
                self.cache_clock +|= 1;
                entry.last_used = self.cache_clock;
                return .{
                    .bytes = entry.output,
                    .changed = entry.changed,
                    .storage = .cache,
                    .checkpoints = entry.checkpoints,
                    .steps_executed = entry.steps_executed,
                    .cumulative_bytes = entry.cumulative_bytes,
                };
            }
            self.cache_misses +|= 1;
        }
        self.checkpoint_bytes.clearRetainingCapacity();
        self.checkpoints.clearRetainingCapacity();
        errdefer {
            self.checkpoint_bytes.clearRetainingCapacity();
            self.checkpoints.clearRetainingCapacity();
        }

        var cumulative_bytes = input.len;
        if (cumulative_bytes > self.limits.max_cumulative_output_bytes) return error.CumulativeOutputTooLarge;
        var checkpoint_records: std.ArrayList(CheckpointRecord) = .empty;
        defer checkpoint_records.deinit(self.allocator);
        if (multi_match) try self.stageCheckpoint(&checkpoint_records, input, null);

        var current = Result{ .bytes = input, .changed = false, .storage = .borrowed };
        var pipeline_changed = false;
        for (pipeline, 0..) |configured, step| {
            const kind = pipelineKind(configured);
            const previous_storage = current.storage;
            var next = try self.applyStep(kind, current.bytes);
            if (next.storage == .borrowed) next.storage = previous_storage;
            current = next;
            cumulative_bytes = std.math.add(usize, cumulative_bytes, current.bytes.len) catch
                return error.CumulativeOutputTooLarge;
            if (cumulative_bytes > self.limits.max_cumulative_output_bytes)
                return error.CumulativeOutputTooLarge;
            pipeline_changed = pipeline_changed or current.changed;
            if (multi_match and current.changed) {
                try self.stageCheckpoint(&checkpoint_records, current.bytes, @intCast(step));
            }
        }

        try self.checkpoints.ensureTotalCapacity(self.allocator, checkpoint_records.items.len);
        for (checkpoint_records.items) |record| {
            self.checkpoints.appendAssumeCapacity(.{
                .bytes = self.checkpoint_bytes.items[record.offset..][0..record.length],
                .after_step = record.after_step,
            });
        }
        const result = PipelineResult{
            .bytes = current.bytes,
            .changed = pipeline_changed,
            .storage = current.storage,
            .checkpoints = self.checkpoints.items,
            .steps_executed = @intCast(pipeline.len),
            .cumulative_bytes = cumulative_bytes,
        };
        if (self.cache_status == .enabled) self.storeCacheEntry(pipeline, input, multi_match, cache_hash, result);
        return result;
    }

    fn stageCheckpoint(
        self: *Executor,
        records: *std.ArrayList(CheckpointRecord),
        bytes: []const u8,
        after_step: ?u32,
    ) ApplyError!void {
        if (bytes.len > self.limits.max_cumulative_output_bytes -| self.checkpoint_bytes.items.len)
            return error.CumulativeOutputTooLarge;
        const offset = self.checkpoint_bytes.items.len;
        try self.checkpoint_bytes.appendSlice(self.allocator, bytes);
        try records.append(self.allocator, .{ .offset = offset, .length = bytes.len, .after_step = after_step });
    }

    fn findCacheEntry(self: *Executor, pipeline: anytype, input: []const u8, multi_match: bool, hash: u64) ?*CacheEntry {
        for (self.cache_entries.items) |*entry| {
            if (entry.hash != hash or entry.multi_match != multi_match or
                !std.mem.eql(u8, entry.input, input) or entry.pipeline.len != pipeline.len)
            {
                continue;
            }
            var equal = true;
            for (pipeline, entry.pipeline) |configured, kind| {
                if (kind != pipelineKind(configured)) {
                    equal = false;
                    break;
                }
            }
            if (equal) return entry;
        }
        return null;
    }

    fn storeCacheEntry(
        self: *Executor,
        pipeline: anytype,
        input: []const u8,
        multi_match: bool,
        hash: u64,
        result: PipelineResult,
    ) void {
        var entry = self.createCacheEntry(pipeline, input, multi_match, hash, result) catch {
            self.disableCache(.allocation_failed);
            return;
        };
        if (entry.owned_bytes > self.limits.max_cache_bytes) {
            entry.deinit(self.allocator);
            self.disableCache(.limit_exhausted);
            return;
        }
        while (self.cache_entries.items.len >= self.limits.max_cache_entries or
            entry.owned_bytes > self.limits.max_cache_bytes - self.cache_bytes)
        {
            if (self.cache_entries.items.len == 0) {
                entry.deinit(self.allocator);
                self.disableCache(.limit_exhausted);
                return;
            }
            var oldest: usize = 0;
            for (self.cache_entries.items[1..], 1..) |candidate, index| {
                if (candidate.last_used < self.cache_entries.items[oldest].last_used) oldest = index;
            }
            var evicted = self.cache_entries.orderedRemove(oldest);
            self.cache_bytes -= evicted.owned_bytes;
            evicted.deinit(self.allocator);
            self.cache_evictions +|= 1;
        }
        self.cache_clock +|= 1;
        entry.last_used = self.cache_clock;
        self.cache_entries.append(self.allocator, entry) catch {
            entry.deinit(self.allocator);
            self.disableCache(.allocation_failed);
            return;
        };
        self.cache_bytes += entry.owned_bytes;
    }

    fn createCacheEntry(
        self: *Executor,
        pipeline: anytype,
        input: []const u8,
        multi_match: bool,
        hash: u64,
        result: PipelineResult,
    ) std.mem.Allocator.Error!CacheEntry {
        const owned_pipeline = try self.allocator.alloc(Kind, pipeline.len);
        errdefer self.allocator.free(owned_pipeline);
        for (pipeline, owned_pipeline) |configured, *destination| destination.* = pipelineKind(configured);
        const owned_input = try self.allocator.dupe(u8, input);
        errdefer self.allocator.free(owned_input);
        const owned_output = try self.allocator.dupe(u8, result.bytes);
        errdefer self.allocator.free(owned_output);
        const owned_checkpoint_bytes = try self.allocator.dupe(u8, self.checkpoint_bytes.items);
        errdefer self.allocator.free(owned_checkpoint_bytes);
        const owned_checkpoints = try self.allocator.alloc(Checkpoint, result.checkpoints.len);
        errdefer self.allocator.free(owned_checkpoints);
        var offset: usize = 0;
        for (result.checkpoints, owned_checkpoints) |source, *destination| {
            destination.* = .{
                .bytes = owned_checkpoint_bytes[offset..][0..source.bytes.len],
                .after_step = source.after_step,
            };
            offset += source.bytes.len;
        }
        const pipeline_bytes = std.math.mul(usize, owned_pipeline.len, @sizeOf(Kind)) catch return error.OutOfMemory;
        const checkpoint_table_bytes = std.math.mul(usize, owned_checkpoints.len, @sizeOf(Checkpoint)) catch return error.OutOfMemory;
        var owned_bytes: usize = @sizeOf(CacheEntry);
        inline for (.{ pipeline_bytes, owned_input.len, owned_output.len, owned_checkpoint_bytes.len, checkpoint_table_bytes }) |amount| {
            owned_bytes = std.math.add(usize, owned_bytes, amount) catch return error.OutOfMemory;
        }
        return .{
            .hash = hash,
            .pipeline = owned_pipeline,
            .input = owned_input,
            .multi_match = multi_match,
            .output = owned_output,
            .changed = result.changed,
            .checkpoints = owned_checkpoints,
            .checkpoint_bytes = owned_checkpoint_bytes,
            .steps_executed = result.steps_executed,
            .cumulative_bytes = result.cumulative_bytes,
            .owned_bytes = owned_bytes,
            .last_used = 0,
        };
    }

    fn disableCache(self: *Executor, status: CacheStatus) void {
        self.clearCacheEntries();
        self.cache_status = status;
    }

    fn clearCacheEntries(self: *Executor) void {
        for (self.cache_entries.items) |*entry| entry.deinit(self.allocator);
        self.cache_entries.clearRetainingCapacity();
        self.cache_bytes = 0;
    }

    fn writable(self: *Executor, capacity: usize) ApplyError!Scratch {
        if (capacity > self.limits.max_output_bytes) return error.OutputTooLarge;
        const slot = self.next_buffer;
        const buffer = &self.buffers[slot];
        buffer.clearRetainingCapacity();
        try buffer.ensureTotalCapacity(self.allocator, capacity);
        self.next_buffer = (slot + 1) % self.buffers.len;
        return .{
            .buffer = buffer,
            .storage = if (slot == 0) .executor_a else .executor_b,
        };
    }

    fn finish(generated: Scratch, input: []const u8, changed: bool) Result {
        if (std.mem.eql(u8, generated.buffer.items, input)) {
            generated.buffer.clearRetainingCapacity();
            return .{ .bytes = input, .changed = changed, .storage = .borrowed };
        }
        return .{ .bytes = generated.buffer.items, .changed = changed, .storage = generated.storage };
    }

    fn mapAsciiCase(self: *Executor, input: []const u8, uppercase: bool) ApplyError!Result {
        var changed = false;
        for (input) |byte| {
            const mapped = if (uppercase) std.ascii.toUpper(byte) else std.ascii.toLower(byte);
            if (mapped != byte) {
                changed = true;
                break;
            }
        }
        if (!changed) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        for (input) |byte| generated.buffer.appendAssumeCapacity(if (uppercase) std.ascii.toUpper(byte) else std.ascii.toLower(byte));
        return finish(generated, input, true);
    }

    fn cmdLine(self: *Executor, input: []const u8) ApplyError!Result {
        var needs_transform = false;
        for (input) |byte| {
            if ((byte >= 'A' and byte <= 'Z') or isCmdLineSpecial(byte)) {
                needs_transform = true;
                break;
            }
        }
        if (!needs_transform) return .{ .bytes = input, .changed = false, .storage = .borrowed };

        const generated = try self.writable(input.len);
        var space = false;
        for (input) |byte| {
            switch (byte) {
                '"', '\'', '\\', '^' => {},
                ' ', ',', ';', '\t', '\r', '\n' => if (!space) {
                    generated.buffer.appendAssumeCapacity(' ');
                    space = true;
                },
                '/', '(' => {
                    if (space) _ = generated.buffer.pop();
                    generated.buffer.appendAssumeCapacity(byte);
                    space = false;
                },
                else => {
                    generated.buffer.appendAssumeCapacity(std.ascii.toLower(byte));
                    space = false;
                },
            }
        }
        const changed = if (self.profile == .coraza) true else generated.buffer.items.len != input.len;
        return finish(generated, input, changed);
    }

    fn normalisePath(self: *Executor, input: []const u8, windows: bool) ApplyError!Result {
        if (input.len == 0) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const rooted = pathByte(input[0], windows) == '/';
        const trailing = pathByte(input[input.len - 1], windows) == '/';
        const reserve = std.math.add(usize, input.len, @intFromBool(self.profile == .coraza and rooted and trailing)) catch return error.OutputTooLarge;
        const generated = try self.writable(reserve);
        if (rooted) generated.buffer.appendAssumeCapacity('/');

        var index: usize = @intFromBool(rooted);
        while (index <= input.len) {
            while (index < input.len and pathByte(input[index], windows) == '/') : (index += 1) {}
            if (index == input.len) break;
            const start = index;
            while (index < input.len and pathByte(input[index], windows) != '/') : (index += 1) {}
            const segment = input[start..index];
            if (std.mem.eql(u8, segment, ".")) continue;
            if (std.mem.eql(u8, segment, "..")) {
                if (!popNormalPathSegment(generated.buffer, rooted)) {
                    if (!rooted) appendPathSegment(generated.buffer, segment);
                }
                continue;
            }
            appendPathSegment(generated.buffer, segment);
        }

        if (generated.buffer.items.len != 0 and trailing) {
            if (self.profile == .coraza or generated.buffer.items[generated.buffer.items.len - 1] != '/') {
                generated.buffer.appendAssumeCapacity('/');
            }
        }

        const changed = switch (self.profile) {
            .modsecurity => !std.mem.eql(u8, generated.buffer.items, input),
            .coraza => generated.buffer.items.len == 0 or trailing or !equalsMappedPath(generated.buffer.items, input, windows),
        };
        return finish(generated, input, changed);
    }

    fn digest(self: *Executor, input: []const u8, comptime Hash: type) ApplyError!Result {
        const generated = try self.writable(Hash.digest_length);
        var output: [Hash.digest_length]u8 = undefined;
        Hash.hash(input, &output, .{});
        generated.buffer.appendSliceAssumeCapacity(&output);
        return finish(generated, input, true);
    }

    fn cssDecode(self: *Executor, input: []const u8) ApplyError!Result {
        const first = std.mem.indexOfScalar(u8, input, '\\') orelse
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        generated.buffer.appendSliceAssumeCapacity(input[0..first]);
        var changed = self.profile == .coraza;
        var index = first;
        while (index < input.len) {
            if (input[index] != '\\') {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
                continue;
            }
            if (index + 1 == input.len) {
                changed = true;
                index += 1;
                continue;
            }

            index += 1;
            var digits: usize = 0;
            while (digits < 6 and index + digits < input.len and isHex(input[index + digits])) : (digits += 1) {}
            if (digits != 0) {
                var decoded = if (digits == 1)
                    hexNibble(input[index]).?
                else
                    hexNibble(input[index + digits - 2]).? * 16 + hexNibble(input[index + digits - 1]).?;
                const full_width_check = digits == 4 or
                    (digits == 5 and input[index] == '0') or
                    (digits == 6 and input[index] == '0' and input[index + 1] == '0');
                if (full_width_check and decoded > 0 and decoded < 0x5f and
                    (input[index + digits - 4] == 'f' or input[index + digits - 4] == 'F') and
                    (input[index + digits - 3] == 'f' or input[index + digits - 3] == 'F'))
                {
                    decoded += 0x20;
                }
                generated.buffer.appendAssumeCapacity(decoded);
                index += digits;
                if (index < input.len and isAsciiWhitespace(input[index])) index += 1;
                changed = true;
            } else if (input[index] == '\n') {
                index += 1;
                changed = true;
            } else {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
            }
        }
        return finish(generated, input, changed);
    }

    fn escapeSeqDecode(self: *Executor, input: []const u8) ApplyError!Result {
        const first = std.mem.indexOfScalar(u8, input, '\\') orelse
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        generated.buffer.appendSliceAssumeCapacity(input[0..first]);
        var changed = false;
        var index = first;
        while (index < input.len) {
            if (input[index] != '\\' or index + 1 == input.len) {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
                continue;
            }

            const escaped = input[index + 1];
            if (cEscapeByte(escaped)) |decoded| {
                generated.buffer.appendAssumeCapacity(decoded);
                index += 2;
            } else if ((escaped == 'x' or escaped == 'X') and index + 3 < input.len and
                isHex(input[index + 2]) and isHex(input[index + 3]))
            {
                generated.buffer.appendAssumeCapacity(hexNibble(input[index + 2]).? * 16 + hexNibble(input[index + 3]).?);
                index += 4;
            } else if (isOctal(escaped)) {
                var digits: usize = 1;
                var decoded: u16 = escaped - '0';
                while (digits < 3 and index + 1 + digits < input.len and isOctal(input[index + 1 + digits])) : (digits += 1) {
                    decoded = decoded * 8 + input[index + 1 + digits] - '0';
                }
                generated.buffer.appendAssumeCapacity(@truncate(decoded));
                index += 1 + digits;
            } else {
                generated.buffer.appendAssumeCapacity(escaped);
                index += 2;
            }
            changed = true;
        }
        return finish(generated, input, changed);
    }

    fn jsDecode(self: *Executor, input: []const u8) ApplyError!Result {
        const first = std.mem.indexOfScalar(u8, input, '\\') orelse
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        generated.buffer.appendSliceAssumeCapacity(input[0..first]);
        var changed = false;
        var index = first;
        while (index < input.len) {
            if (input[index] != '\\') {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
            } else if (index + 5 < input.len and input[index + 1] == 'u' and
                isHex(input[index + 2]) and isHex(input[index + 3]) and
                isHex(input[index + 4]) and isHex(input[index + 5]))
            {
                const code_point = decodeHexU16(input[index + 2 .. index + 6]);
                var decoded: u8 = @truncate(code_point);
                if (decoded > 0 and decoded < 0x5f and (code_point & 0xff00) == 0xff00) decoded += 0x20;
                generated.buffer.appendAssumeCapacity(decoded);
                index += 6;
                changed = true;
            } else if (index + 3 < input.len and input[index + 1] == 'x' and
                isHex(input[index + 2]) and isHex(input[index + 3]))
            {
                generated.buffer.appendAssumeCapacity(hexNibble(input[index + 2]).? * 16 + hexNibble(input[index + 3]).?);
                index += 4;
                changed = true;
            } else if (index + 1 < input.len and isOctal(input[index + 1])) {
                var digits: usize = 1;
                while (digits < 3 and index + 1 + digits < input.len and isOctal(input[index + 1 + digits])) : (digits += 1) {}
                if (digits == 3 and input[index + 1] > '3') digits = 2;
                var decoded: u8 = 0;
                for (input[index + 1 .. index + 1 + digits]) |digit| decoded = decoded * 8 + digit - '0';
                generated.buffer.appendAssumeCapacity(decoded);
                index += 1 + digits;
                changed = true;
            } else if (index + 1 < input.len) {
                generated.buffer.appendAssumeCapacity(cEscapeByte(input[index + 1]) orelse input[index + 1]);
                index += 2;
                changed = true;
            } else {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
            }
        }
        return finish(generated, input, changed);
    }

    fn htmlEntityDecode(self: *Executor, input: []const u8) ApplyError!Result {
        return switch (self.profile) {
            .modsecurity => self.htmlEntityDecodeModSecurity(input),
            .coraza => self.htmlEntityDecodeCoraza(input),
        };
    }

    fn htmlEntityDecodeModSecurity(self: *Executor, input: []const u8) ApplyError!Result {
        const first = std.mem.indexOfScalar(u8, input, '&') orelse
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        generated.buffer.appendSliceAssumeCapacity(input[0..first]);
        var index = first;
        while (index < input.len) {
            if (input[index] != '&' or index + 1 == input.len) {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
                continue;
            }

            var cursor = index + 1;
            if (input[cursor] == '#') {
                cursor += 1;
                if (cursor == input.len) {
                    generated.buffer.appendSliceAssumeCapacity(input[index..cursor]);
                    index = cursor;
                    continue;
                }
                var base: u8 = 10;
                if (input[cursor] == 'x' or input[cursor] == 'X') {
                    base = 16;
                    cursor += 1;
                }
                const digits_start = cursor;
                while (cursor < input.len and if (base == 16) isHex(input[cursor]) else std.ascii.isDigit(input[cursor])) : (cursor += 1) {}
                if (cursor != digits_start) {
                    generated.buffer.appendAssumeCapacity(parseSaturatingByte(input[digits_start..cursor], base));
                    if (cursor < input.len and input[cursor] == ';') cursor += 1;
                    index = cursor;
                    continue;
                }
            } else {
                const name_start = cursor;
                while (cursor < input.len and std.ascii.isAlphanumeric(input[cursor])) : (cursor += 1) {}
                if (cursor != name_start) {
                    const name = input[name_start..cursor];
                    const decoded: ?u8 = if (startsWithIgnoreCase(name, "quot"))
                        '"'
                    else if (startsWithIgnoreCase(name, "amp"))
                        '&'
                    else if (startsWithIgnoreCase(name, "lt"))
                        '<'
                    else if (startsWithIgnoreCase(name, "gt"))
                        '>'
                    else if (startsWithIgnoreCase(name, "nbsp"))
                        0xa0
                    else
                        null;
                    if (decoded) |byte| {
                        generated.buffer.appendAssumeCapacity(byte);
                        if (cursor < input.len and input[cursor] == ';') cursor += 1;
                        index = cursor;
                        continue;
                    }
                }
            }

            generated.buffer.appendAssumeCapacity(input[index]);
            index += 1;
        }
        return finish(generated, input, generated.buffer.items.len != input.len);
    }

    fn htmlEntityDecodeCoraza(self: *Executor, input: []const u8) ApplyError!Result {
        const first = std.mem.indexOfScalar(u8, input, '&') orelse
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        var output_len = first;
        var index = first;
        while (index < input.len) {
            if (input[index] != '&') {
                output_len = std.math.add(usize, output_len, 1) catch return error.OutputTooLarge;
                index += 1;
                continue;
            }
            const decoded = decodeCorazaHtmlEntity(input[index..]);
            if (decoded) |entity| {
                output_len = std.math.add(usize, output_len, utf8Length(entity.value.first)) catch return error.OutputTooLarge;
                if (entity.value.second) |second|
                    output_len = std.math.add(usize, output_len, utf8Length(second)) catch return error.OutputTooLarge;
                index += entity.consumed;
            } else {
                output_len = std.math.add(usize, output_len, 1) catch return error.OutputTooLarge;
                index += 1;
            }
        }

        const generated = try self.writable(output_len);
        generated.buffer.appendSliceAssumeCapacity(input[0..first]);
        index = first;
        while (index < input.len) {
            if (input[index] != '&') {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
                continue;
            }
            const decoded = decodeCorazaHtmlEntity(input[index..]);
            if (decoded) |entity| {
                try appendCodePoint(generated.buffer, entity.value.first);
                if (entity.value.second) |second| try appendCodePoint(generated.buffer, second);
                index += entity.consumed;
            } else {
                generated.buffer.appendAssumeCapacity('&');
                index += 1;
            }
        }
        return finish(generated, input, generated.buffer.items.len != input.len);
    }

    fn removeComments(self: *Executor, input: []const u8) ApplyError!Result {
        if (findCommentStart(input, true) == null)
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        var index: usize = 0;
        var in_comment = false;
        while (index < input.len) {
            if (!in_comment) {
                if (startsAt(input, index, "/*")) {
                    in_comment = true;
                    index += 2;
                } else if (startsAt(input, index, "<!--")) {
                    in_comment = true;
                    index += 4;
                } else if (startsAt(input, index, "--") or input[index] == '#') {
                    break;
                } else {
                    generated.buffer.appendAssumeCapacity(input[index]);
                    index += 1;
                }
            } else if (startsAt(input, index, "*/")) {
                in_comment = false;
                index += 2;
                generated.buffer.appendAssumeCapacity(if (index < input.len) input[index] else 0);
                index += 1;
            } else if (startsAt(input, index, "-->")) {
                in_comment = false;
                index += 3;
                generated.buffer.appendAssumeCapacity(if (index < input.len) input[index] else 0);
                index += 1;
            } else {
                index += 1;
            }
        }
        if (in_comment) generated.buffer.appendAssumeCapacity(' ');
        return finish(generated, input, true);
    }

    fn removeCommentsChar(self: *Executor, input: []const u8) ApplyError!Result {
        const first = findCommentMarker(input) orelse
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len - 1);
        generated.buffer.appendSliceAssumeCapacity(input[0..first]);
        var index = first;
        while (index < input.len) {
            if (startsAt(input, index, "/*") or startsAt(input, index, "*/")) {
                index += 2;
            } else if (startsAt(input, index, "<!--")) {
                index += 4;
            } else if (startsAt(input, index, "-->")) {
                index += 3;
            } else if (startsAt(input, index, "--")) {
                index += 2;
            } else if (input[index] == '#') {
                index += 1;
            } else {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
            }
        }
        return finish(generated, input, true);
    }

    fn replaceComments(self: *Executor, input: []const u8) ApplyError!Result {
        const first = std.mem.indexOf(u8, input, "/*") orelse
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len - 1);
        generated.buffer.appendSliceAssumeCapacity(input[0..first]);
        var index = first;
        var in_comment = false;
        while (index < input.len) {
            if (!in_comment and startsAt(input, index, "/*")) {
                in_comment = true;
                index += 2;
            } else if (in_comment and startsAt(input, index, "*/")) {
                in_comment = false;
                index += 2;
                generated.buffer.appendAssumeCapacity(' ');
            } else if (in_comment) {
                index += 1;
            } else {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
            }
        }
        if (in_comment) generated.buffer.appendAssumeCapacity(' ');
        return finish(generated, input, true);
    }

    fn compressWhitespace(self: *Executor, input: []const u8) ApplyError!Result {
        var first: ?usize = null;
        for (input, 0..) |byte, index| {
            if (isAsciiWhitespace(byte)) {
                first = index;
                break;
            }
        }
        if (first == null) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        generated.buffer.appendSliceAssumeCapacity(input[0..first.?]);
        var in_whitespace = false;
        for (input[first.?..]) |byte| {
            if (isAsciiWhitespace(byte)) {
                if (in_whitespace) continue;
                in_whitespace = true;
                generated.buffer.appendAssumeCapacity(' ');
            } else {
                in_whitespace = false;
                generated.buffer.appendAssumeCapacity(byte);
            }
        }
        return finish(generated, input, generated.buffer.items.len != input.len);
    }

    fn removeBytes(self: *Executor, input: []const u8, comptime predicate: fn (u8) bool) ApplyError!Result {
        var first: ?usize = null;
        for (input, 0..) |byte, index| {
            if (predicate(byte)) {
                first = index;
                break;
            }
        }
        if (first == null) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len - 1);
        generated.buffer.appendSliceAssumeCapacity(input[0..first.?]);
        for (input[first.? + 1 ..]) |byte| if (!predicate(byte)) generated.buffer.appendAssumeCapacity(byte);
        return finish(generated, input, true);
    }

    fn replaceNulls(self: *Executor, input: []const u8) ApplyError!Result {
        if (std.mem.indexOfScalar(u8, input, 0) == null)
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        for (input) |byte| generated.buffer.appendAssumeCapacity(if (byte == 0) ' ' else byte);
        return finish(generated, input, true);
    }

    fn hexDecode(self: *Executor, input: []const u8) ApplyError!Result {
        if (self.profile == .coraza) {
            if (input.len % 2 != 0) return error.InvalidInput;
            for (input) |byte| if (!isHex(byte)) return error.InvalidInput;
        } else if (input.len == 0) {
            return .{ .bytes = input, .changed = false, .storage = .borrowed };
        }
        const generated = try self.writable(input.len / 2);
        var index: usize = 0;
        while (index + 1 < input.len) : (index += 2) {
            const high = if (self.profile == .coraza) hexNibble(input[index]).? else modSecurityHexNibble(input[index]);
            const low = if (self.profile == .coraza) hexNibble(input[index + 1]).? else modSecurityHexNibble(input[index + 1]);
            generated.buffer.appendAssumeCapacity(high *% 16 +% low);
        }
        return finish(generated, input, true);
    }

    fn base64Encode(self: *Executor, input: []const u8) ApplyError!Result {
        if (input.len == 0)
            return .{ .bytes = input, .changed = self.profile == .coraza, .storage = .borrowed };
        const groups = std.math.add(usize, input.len, 2) catch return error.OutputTooLarge;
        const capacity = std.math.mul(usize, groups / 3, 4) catch return error.OutputTooLarge;
        const generated = try self.writable(capacity);
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var index: usize = 0;
        while (index + 3 <= input.len) : (index += 3) {
            const bits = (@as(u24, input[index]) << 16) | (@as(u24, input[index + 1]) << 8) | input[index + 2];
            generated.buffer.appendAssumeCapacity(alphabet[@intCast((bits >> 18) & 0x3f)]);
            generated.buffer.appendAssumeCapacity(alphabet[@intCast((bits >> 12) & 0x3f)]);
            generated.buffer.appendAssumeCapacity(alphabet[@intCast((bits >> 6) & 0x3f)]);
            generated.buffer.appendAssumeCapacity(alphabet[@intCast(bits & 0x3f)]);
        }
        const remaining = input.len - index;
        if (remaining != 0) {
            const first: u24 = @as(u24, input[index]) << 16;
            const second: u24 = if (remaining == 2) @as(u24, input[index + 1]) << 8 else 0;
            const bits = first | second;
            generated.buffer.appendAssumeCapacity(alphabet[@intCast((bits >> 18) & 0x3f)]);
            generated.buffer.appendAssumeCapacity(alphabet[@intCast((bits >> 12) & 0x3f)]);
            generated.buffer.appendAssumeCapacity(if (remaining == 2) alphabet[@intCast((bits >> 6) & 0x3f)] else '=');
            generated.buffer.appendAssumeCapacity('=');
        }
        return finish(generated, input, true);
    }

    fn base64Decode(self: *Executor, input: []const u8, extended: bool) ApplyError!Result {
        if (input.len == 0) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        var accumulator: u32 = 0;
        var sextets: u3 = 0;
        var padding: u3 = 0;
        var saw_padding = false;
        var invalid = false;

        const strict_modsecurity = self.profile == .modsecurity and !extended;
        for (input) |byte| {
            if (strict_modsecurity and byte == 0) break;
            if (byte == '=') {
                if (self.profile == .modsecurity and extended) continue;
                saw_padding = true;
                padding +|= 1;
                continue;
            }
            if (base64Value(byte)) |value| {
                if (saw_padding) {
                    invalid = true;
                    break;
                }
                accumulator = (accumulator << 6) | value;
                sextets += 1;
                if (sextets == 4) {
                    generated.buffer.appendAssumeCapacity(@intCast((accumulator >> 16) & 0xff));
                    generated.buffer.appendAssumeCapacity(@intCast((accumulator >> 8) & 0xff));
                    generated.buffer.appendAssumeCapacity(@intCast(accumulator & 0xff));
                    accumulator = 0;
                    sextets = 0;
                }
                continue;
            }

            const ignored = if (extended)
                if (self.profile == .modsecurity) true else byte == '.' or isCorazaBase64Whitespace(byte)
            else
                byte == '\r' or byte == '\n';
            if (ignored) continue;
            if (self.profile == .coraza) break;
            invalid = true;
            break;
        }

        if (strict_modsecurity) {
            const valid_padding = switch (sextets) {
                0 => padding == 0,
                2 => padding == 0 or padding == 2,
                3 => padding == 0 or padding == 1,
                else => false,
            };
            if (invalid or !valid_padding) {
                generated.buffer.clearRetainingCapacity();
                return .{ .bytes = input, .changed = false, .storage = .borrowed };
            }
        }
        switch (sextets) {
            2 => {
                accumulator <<= 12;
                generated.buffer.appendAssumeCapacity(@intCast((accumulator >> 16) & 0xff));
            },
            3 => {
                accumulator <<= 6;
                generated.buffer.appendAssumeCapacity(@intCast((accumulator >> 16) & 0xff));
                generated.buffer.appendAssumeCapacity(@intCast((accumulator >> 8) & 0xff));
            },
            else => {},
        }
        return finish(generated, input, true);
    }

    fn hexEncode(self: *Executor, input: []const u8) ApplyError!Result {
        if (input.len == 0)
            return .{ .bytes = input, .changed = self.profile == .coraza, .storage = .borrowed };
        const capacity = std.math.mul(usize, input.len, 2) catch return error.OutputTooLarge;
        const generated = try self.writable(capacity);
        const digits = "0123456789abcdef";
        for (input) |byte| {
            generated.buffer.appendAssumeCapacity(digits[byte >> 4]);
            generated.buffer.appendAssumeCapacity(digits[byte & 0x0f]);
        }
        return finish(generated, input, true);
    }

    fn sqlHexDecode(self: *Executor, input: []const u8) ApplyError!Result {
        var first: ?usize = null;
        var index: usize = 0;
        while (index + 3 < input.len) : (index += 1) {
            if (input[index] == '0' and
                (input[index + 1] == 'x' or input[index + 1] == 'X') and
                isHex(input[index + 2]) and
                isHex(input[index + 3]))
            {
                first = index;
                break;
            }
        }
        if (first == null) return .{ .bytes = input, .changed = false, .storage = .borrowed };

        const generated = try self.writable(input.len - 2);
        generated.buffer.appendSliceAssumeCapacity(input[0..first.?]);
        index = first.?;
        while (index < input.len) {
            if (index + 3 < input.len and
                input[index] == '0' and
                (input[index + 1] == 'x' or input[index + 1] == 'X') and
                isHex(input[index + 2]) and
                isHex(input[index + 3]))
            {
                index += 2;
                while (index + 1 < input.len and isHex(input[index]) and isHex(input[index + 1])) {
                    generated.buffer.appendAssumeCapacity(hexNibble(input[index]).? * 16 + hexNibble(input[index + 1]).?);
                    index += 2;
                }
            } else {
                generated.buffer.appendAssumeCapacity(input[index]);
                index += 1;
            }
        }
        return finish(generated, input, true);
    }

    fn urlDecode(self: *Executor, input: []const u8) ApplyError!Result {
        return self.urlDecodeInternal(input, false);
    }

    fn urlDecodeUni(self: *Executor, input: []const u8) ApplyError!Result {
        return self.urlDecodeInternal(input, true);
    }

    fn urlDecodeInternal(self: *Executor, input: []const u8, unicode: bool) ApplyError!Result {
        var changed = false;
        var index: usize = 0;
        while (index < input.len) : (index += 1) {
            if (input[index] == '+') {
                changed = true;
                break;
            }
            if (input[index] == '%') {
                if (self.profile == .coraza or
                    (unicode and isValidUrlUnicodeEscape(input, index)) or
                    (index + 2 < input.len and isHex(input[index + 1]) and isHex(input[index + 2])))
                {
                    changed = true;
                    break;
                }
            }
        }
        if (!changed) return .{ .bytes = input, .changed = false, .storage = .borrowed };

        const generated = try self.writable(input.len);
        index = 0;
        while (index < input.len) {
            if (unicode and isValidUrlUnicodeEscape(input, index)) {
                const code_point = decodeHexU16(input[index + 2 .. index + 6]);
                var decoded = if (self.unicode_map) |unicode_map|
                    unicode_map.lookup(code_point)
                else
                    null;
                if (decoded == null) {
                    decoded = @truncate(code_point);
                    if (decoded.? > 0 and decoded.? < 0x5f and (code_point & 0xff00) == 0xff00) {
                        decoded.? += 0x20;
                    }
                }
                generated.buffer.appendAssumeCapacity(decoded.?);
                index += 6;
            } else if (unicode and input[index] == '%' and index + 1 < input.len and
                (input[index + 1] == 'u' or input[index + 1] == 'U'))
            {
                generated.buffer.appendSliceAssumeCapacity(input[index .. index + 2]);
                index += 2;
            } else if (input[index] == '%' and index + 2 < input.len and isHex(input[index + 1]) and isHex(input[index + 2])) {
                generated.buffer.appendAssumeCapacity(hexNibble(input[index + 1]).? * 16 + hexNibble(input[index + 2]).?);
                index += 3;
            } else {
                generated.buffer.appendAssumeCapacity(if (input[index] == '+') ' ' else input[index]);
                index += 1;
            }
        }
        return finish(generated, input, true);
    }

    fn urlEncode(self: *Executor, input: []const u8) ApplyError!Result {
        var changed = false;
        for (input) |byte| {
            if (!isUrlUnescaped(byte)) {
                changed = true;
                break;
            }
        }
        if (!changed) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        var output_len: usize = 0;
        for (input) |byte| {
            const encoded_len: usize = if (byte == ' ' or isUrlUnescaped(byte)) 1 else 3;
            output_len = std.math.add(usize, output_len, encoded_len) catch return error.OutputTooLarge;
        }
        const generated = try self.writable(output_len);
        const digits = "0123456789abcdef";
        for (input) |byte| {
            if (byte == ' ') {
                generated.buffer.appendAssumeCapacity('+');
            } else if (isUrlUnescaped(byte)) {
                generated.buffer.appendAssumeCapacity(byte);
            } else {
                generated.buffer.appendAssumeCapacity('%');
                generated.buffer.appendAssumeCapacity(digits[byte >> 4]);
                generated.buffer.appendAssumeCapacity(digits[byte & 0x0f]);
            }
        }
        return finish(generated, input, true);
    }

    fn utf8ToUnicode(self: *Executor, input: []const u8) ApplyError!Result {
        return switch (self.profile) {
            .modsecurity => self.utf8ToUnicodeModSecurity(input),
            .coraza => self.utf8ToUnicodeCoraza(input),
        };
    }

    fn utf8ToUnicodeCoraza(self: *Executor, input: []const u8) ApplyError!Result {
        var output_len: usize = 0;
        var changed = false;
        var index: usize = 0;
        while (index < input.len) {
            const step = strictUtf8Step(input[index..]);
            output_len = std.math.add(usize, output_len, if (step.ascii) 1 else unicodeEscapeLen(step.code_point)) catch return error.OutputTooLarge;
            changed = changed or !step.ascii;
            index += step.consumed;
        }
        if (!changed) return .{ .bytes = input, .changed = false, .storage = .borrowed };

        const generated = try self.writable(output_len);
        index = 0;
        while (index < input.len) {
            const step = strictUtf8Step(input[index..]);
            if (step.ascii) {
                generated.buffer.appendAssumeCapacity(input[index]);
            } else {
                appendUnicodeEscape(generated.buffer, step.code_point);
            }
            index += step.consumed;
        }
        return finish(generated, input, true);
    }

    fn utf8ToUnicodeModSecurity(self: *Executor, input: []const u8) ApplyError!Result {
        var output_len: usize = 0;
        var changed = false;
        var requires_output = false;
        var index: usize = 0;
        while (index < input.len) {
            const step = modSecurityUtf8Step(input, index);
            output_len = std.math.add(usize, output_len, step.outputLen()) catch return error.OutputTooLarge;
            changed = changed or step.changed;
            requires_output = requires_output or !step.isIdentity(input[index]);
            index += step.consumed;
        }
        if (!requires_output) return .{ .bytes = input, .changed = changed, .storage = .borrowed };

        const generated = try self.writable(output_len);
        index = 0;
        while (index < input.len) {
            const step = modSecurityUtf8Step(input, index);
            if (step.prefix_copy) generated.buffer.appendAssumeCapacity(input[index]);
            if (step.code_point) |code_point| appendUnicodeEscape(generated.buffer, code_point);
            for (0..step.suffix_copies) |_| generated.buffer.appendAssumeCapacity(input[index]);
            index += step.consumed;
        }
        return finish(generated, input, changed);
    }

    fn parity(self: *Executor, input: []const u8, even: bool) ApplyError!Result {
        if (input.len == 0) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        for (input) |byte| {
            const seven = byte & 0x7f;
            const odd_ones = @popCount(seven) % 2 == 1;
            const high: u8 = if (if (even) odd_ones else !odd_ones) 0x80 else 0;
            generated.buffer.appendAssumeCapacity(seven | high);
        }
        return finish(generated, input, true);
    }

    fn parityZero(self: *Executor, input: []const u8) ApplyError!Result {
        if (input.len == 0) return .{ .bytes = input, .changed = false, .storage = .borrowed };
        const generated = try self.writable(input.len);
        for (input) |byte| generated.buffer.appendAssumeCapacity(byte & 0x7f);
        return finish(generated, input, true);
    }

    fn length(self: *Executor, input: []const u8) ApplyError!Result {
        var storage: [32]u8 = undefined;
        const rendered = std.fmt.bufPrint(&storage, "{d}", .{input.len}) catch unreachable;
        const generated = try self.writable(rendered.len);
        generated.buffer.appendSliceAssumeCapacity(rendered);
        return finish(generated, input, true);
    }
};

fn pipelineKind(configured: anytype) Kind {
    const T = @TypeOf(configured);
    if (T == Kind) return configured;
    if (@hasField(T, "kind") and @TypeOf(configured.kind) == Kind) return configured.kind;
    @compileError("pipeline entries must be transformation Kind values or structs with a Kind field");
}

fn pipelineHash(pipeline: anytype, input: []const u8, multi_match: bool) u64 {
    var hasher = std.hash.Wyhash.init(0x7a69672d776166);
    hasher.update(&.{@intFromBool(multi_match)});
    for (pipeline) |configured| hasher.update(&.{@backingInt(pipelineKind(configured))});
    hasher.update(input);
    return hasher.final();
}

fn trimResult(input: []const u8, left: bool, right: bool) Result {
    var start: usize = 0;
    var end = input.len;
    if (left) {
        while (start < end and isAsciiWhitespace(input[start])) : (start += 1) {}
    }
    if (right) {
        while (end > start and isAsciiWhitespace(input[end - 1])) : (end -= 1) {}
    }
    return .{ .bytes = input[start..end], .changed = start != 0 or end != input.len, .storage = .borrowed };
}

fn isAsciiWhitespace(byte: u8) bool {
    return switch (byte) {
        ' ', '\t', '\n', '\r', 0x0b, 0x0c => true,
        else => false,
    };
}

fn isRemovalWhitespace(byte: u8) bool {
    return isAsciiWhitespace(byte) or byte == 0xa0 or byte == 0xc2;
}

fn isNull(byte: u8) bool {
    return byte == 0;
}

fn isCmdLineSpecial(byte: u8) bool {
    return switch (byte) {
        '"', '\'', '\\', '^', ' ', ',', ';', '\t', '\r', '\n', '/', '(' => true,
        else => false,
    };
}

fn pathByte(byte: u8, windows: bool) u8 {
    return if (windows and byte == '\\') '/' else byte;
}

fn appendPathSegment(buffer: *std.ArrayList(u8), segment: []const u8) void {
    if (buffer.items.len != 0 and buffer.items[buffer.items.len - 1] != '/') buffer.appendAssumeCapacity('/');
    buffer.appendSliceAssumeCapacity(segment);
}

fn popNormalPathSegment(buffer: *std.ArrayList(u8), rooted: bool) bool {
    const minimum: usize = @intFromBool(rooted);
    if (buffer.items.len <= minimum) return false;
    const last_separator = std.mem.lastIndexOfScalar(u8, buffer.items, '/');
    const segment_start = if (last_separator) |separator| separator + 1 else 0;
    if (std.mem.eql(u8, buffer.items[segment_start..], "..")) return false;
    buffer.shrinkRetainingCapacity(if (last_separator) |separator| @max(separator, minimum) else minimum);
    return true;
}

fn equalsMappedPath(output: []const u8, input: []const u8, windows: bool) bool {
    if (output.len != input.len) return false;
    for (output, input) |actual, original| if (actual != pathByte(original, windows)) return false;
    return true;
}

fn startsWithIgnoreCase(input: []const u8, prefix: []const u8) bool {
    return input.len >= prefix.len and std.ascii.eqlIgnoreCase(input[0..prefix.len], prefix);
}

fn startsAt(input: []const u8, index: usize, needle: []const u8) bool {
    return index + needle.len <= input.len and std.mem.eql(u8, input[index .. index + needle.len], needle);
}

fn findCommentStart(input: []const u8, line_comments: bool) ?usize {
    var index: usize = 0;
    while (index < input.len) : (index += 1) {
        if (startsAt(input, index, "/*") or startsAt(input, index, "<!--") or
            (line_comments and (startsAt(input, index, "--") or input[index] == '#')))
        {
            return index;
        }
    }
    return null;
}

fn findCommentMarker(input: []const u8) ?usize {
    var index: usize = 0;
    while (index < input.len) : (index += 1) {
        if (startsAt(input, index, "/*") or startsAt(input, index, "*/") or
            startsAt(input, index, "<!--") or startsAt(input, index, "-->") or
            startsAt(input, index, "--") or input[index] == '#')
        {
            return index;
        }
    }
    return null;
}

fn parseSaturatingByte(digits: []const u8, base: u8) u8 {
    const maximum: u64 = std.math.maxInt(i64);
    var value: u64 = 0;
    for (digits) |digit| {
        const decoded: u64 = if (base == 16) hexNibble(digit).? else digit - '0';
        if (value > (maximum - decoded) / base) {
            value = maximum;
            break;
        }
        value = value * base + decoded;
    }
    return @truncate(value);
}

const DecodedHtmlEntity = struct {
    value: html_entities.Value,
    consumed: usize,
};

fn decodeCorazaHtmlEntity(input: []const u8) ?DecodedHtmlEntity {
    if (input.len <= 1 or input[0] != '&') return null;
    if (input[1] == '#') return decodeCorazaNumericEntity(input);

    var end: usize = 1;
    while (end < input.len and std.ascii.isAlphanumeric(input[end])) : (end += 1) {}
    if (end < input.len and input[end] == ';') end += 1;
    const name = input[1..end];
    if (name.len == 0) return null;
    if (html_entities.lookup(name)) |value| return .{ .value = value, .consumed = end };

    var prefix_len = @min(name.len - 1, 6);
    while (prefix_len > 1) : (prefix_len -= 1) {
        if (html_entities.lookup(name[0..prefix_len])) |value| {
            return .{ .value = value, .consumed = prefix_len + 1 };
        }
    }
    return null;
}

fn decodeCorazaNumericEntity(input: []const u8) ?DecodedHtmlEntity {
    if (input.len <= 3) return null;
    var cursor: usize = 2;
    var base: u8 = 10;
    if (input[cursor] == 'x' or input[cursor] == 'X') {
        base = 16;
        cursor += 1;
    }
    const digits_start = cursor;
    var value: u32 = 0;
    while (cursor < input.len) : (cursor += 1) {
        const digit: u32 = if (base == 16)
            hexNibble(input[cursor]) orelse break
        else if (std.ascii.isDigit(input[cursor]))
            input[cursor] - '0'
        else
            break;
        value = if (value > (0x110000 - digit) / base) 0x110000 else value * base + digit;
    }
    if (cursor == digits_start) return null;
    if (cursor < input.len and input[cursor] == ';') cursor += 1;

    const code_point: u21 = if (value >= 0x80 and value <= 0x9f)
        html_numeric_replacements[value - 0x80]
    else if (value == 0 or (value >= 0xd800 and value <= 0xdfff) or value > 0x10ffff)
        0xfffd
    else
        @intCast(value);
    return .{ .value = .{ .first = code_point }, .consumed = cursor };
}

fn appendCodePoint(buffer: *std.ArrayList(u8), code_point: u21) ApplyError!void {
    var encoded: [4]u8 = undefined;
    const length = std.unicode.utf8Encode(code_point, &encoded) catch unreachable;
    buffer.appendSliceAssumeCapacity(encoded[0..length]);
}

fn utf8Length(code_point: u21) usize {
    return std.unicode.utf8CodepointSequenceLength(code_point) catch unreachable;
}

const html_numeric_replacements = [_]u21{
    0x20ac, 0x0081, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,
    0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008d, 0x017d, 0x008f,
    0x0090, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
    0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x009d, 0x017e, 0x0178,
};

const StrictUtf8Step = struct {
    code_point: u21,
    consumed: usize,
    ascii: bool,
};

fn strictUtf8Step(input: []const u8) StrictUtf8Step {
    if (input[0] < 0x80) return .{ .code_point = input[0], .consumed = 1, .ascii = true };
    const sequence_len = std.unicode.utf8ByteSequenceLength(input[0]) catch
        return .{ .code_point = 0xfffd, .consumed = 1, .ascii = false };
    if (sequence_len > input.len)
        return .{ .code_point = 0xfffd, .consumed = 1, .ascii = false };
    const code_point = std.unicode.utf8Decode(input[0..sequence_len]) catch
        return .{ .code_point = 0xfffd, .consumed = 1, .ascii = false };
    return .{ .code_point = code_point, .consumed = sequence_len, .ascii = false };
}

const ModSecurityUtf8Step = struct {
    code_point: ?u32 = null,
    consumed: usize = 1,
    prefix_copy: bool = false,
    suffix_copies: u2 = 0,
    changed: bool = false,

    fn outputLen(self: ModSecurityUtf8Step) usize {
        return @intFromBool(self.prefix_copy) + self.suffix_copies +
            if (self.code_point) |code_point| unicodeEscapeLen(code_point) else 0;
    }

    fn isIdentity(self: ModSecurityUtf8Step, input_byte: u8) bool {
        return self.consumed == 1 and self.code_point == null and
            @as(usize, @intFromBool(self.prefix_copy)) + self.suffix_copies == 1 and input_byte != 0;
    }
};

fn modSecurityUtf8Step(input: []const u8, index: usize) ModSecurityUtf8Step {
    const byte = input[index];
    if (byte < 0x80) {
        if (byte == 0 and index + 1 < input.len) return .{};
        return .{ .suffix_copies = 1 };
    }

    var sequence_len: usize = 0;
    var code_point: u32 = 0;
    if ((byte & 0xe0) == 0xc0) {
        sequence_len = 2;
        if (!hasContinuationBytes(input[index..], sequence_len)) return .{};
        code_point = (@as(u32, byte & 0x1f) << 6) | (input[index + 1] & 0x3f);
    } else if ((byte & 0xf0) == 0xe0) {
        sequence_len = 3;
        if (!hasContinuationBytes(input[index..], sequence_len)) return .{};
        code_point = (@as(u32, byte & 0x0f) << 12) |
            (@as(u32, input[index + 1] & 0x3f) << 6) |
            (input[index + 2] & 0x3f);
    } else if ((byte & 0xf8) == 0xf0) {
        sequence_len = 4;
        const prefix_copy = byte >= 0xf5;
        if (!hasContinuationBytes(input[index..], sequence_len)) return .{ .prefix_copy = prefix_copy };
        code_point = (@as(u32, byte & 0x07) << 18) |
            (@as(u32, input[index + 1] & 0x3f) << 12) |
            (@as(u32, input[index + 2] & 0x3f) << 6) |
            (input[index + 3] & 0x3f);
        return .{
            .code_point = code_point,
            .consumed = sequence_len,
            .prefix_copy = prefix_copy,
            .suffix_copies = @intFromBool(code_point >= 0xd800 and code_point <= 0xdfff) +
                @intFromBool(code_point < 0x10000),
            .changed = true,
        };
    } else {
        return .{ .suffix_copies = 1 };
    }

    return .{
        .code_point = code_point,
        .consumed = sequence_len,
        .suffix_copies = @intFromBool((code_point >= 0xd800 and code_point <= 0xdfff) or
            (sequence_len == 3 and code_point < 0x800) or
            (sequence_len == 2 and code_point < 0x80)),
        .changed = true,
    };
}

fn hasContinuationBytes(input: []const u8, sequence_len: usize) bool {
    if (input.len < sequence_len) return false;
    for (input[1..sequence_len]) |byte| if ((byte & 0xc0) != 0x80) return false;
    return true;
}

fn unicodeEscapeLen(code_point: u32) usize {
    return 2 + @max(4, hexDigits(code_point));
}

fn hexDigits(value: u32) usize {
    if (value <= 0xf) return 1;
    if (value <= 0xff) return 2;
    if (value <= 0xfff) return 3;
    if (value <= 0xffff) return 4;
    if (value <= 0xfffff) return 5;
    return 6;
}

fn appendUnicodeEscape(buffer: *std.ArrayList(u8), code_point: u32) void {
    buffer.appendSliceAssumeCapacity("%u");
    const digits = hexDigits(code_point);
    for (0..4 -| digits) |_| buffer.appendAssumeCapacity('0');
    const alphabet = "0123456789abcdef";
    var shift: usize = digits * 4;
    while (shift != 0) {
        shift -= 4;
        buffer.appendAssumeCapacity(alphabet[(code_point >> @intCast(shift)) & 0x0f]);
    }
}

fn cEscapeByte(byte: u8) ?u8 {
    return switch (byte) {
        'a' => 0x07,
        'b' => 0x08,
        'f' => 0x0c,
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'v' => 0x0b,
        '\\', '?', '\'', '"' => byte,
        else => null,
    };
}

fn isOctal(byte: u8) bool {
    return byte >= '0' and byte <= '7';
}

fn isHex(byte: u8) bool {
    return hexNibble(byte) != null;
}

fn hexNibble(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn modSecurityHexNibble(byte: u8) u8 {
    return if (byte >= 'A') ((byte & 0xdf) -% 'A') +% 10 else byte -% '0';
}

fn isUrlUnescaped(byte: u8) bool {
    return byte == '*' or std.ascii.isAlphanumeric(byte);
}

fn isValidUrlUnicodeEscape(input: []const u8, index: usize) bool {
    return index + 5 < input.len and
        input[index] == '%' and
        (input[index + 1] == 'u' or input[index + 1] == 'U') and
        isHex(input[index + 2]) and
        isHex(input[index + 3]) and
        isHex(input[index + 4]) and
        isHex(input[index + 5]);
}

fn decodeHexU16(input: []const u8) u16 {
    return (@as(u16, hexNibble(input[0]).?) << 12) |
        (@as(u16, hexNibble(input[1]).?) << 8) |
        (@as(u16, hexNibble(input[2]).?) << 4) |
        hexNibble(input[3]).?;
}

fn base64Value(byte: u8) ?u6 {
    return switch (byte) {
        'A'...'Z' => @intCast(byte - 'A'),
        'a'...'z' => @intCast(byte - 'a' + 26),
        '0'...'9' => @intCast(byte - '0' + 52),
        '+' => 62,
        '/' => 63,
        else => null,
    };
}

fn isCorazaBase64Whitespace(byte: u8) bool {
    return isAsciiWhitespace(byte) or byte == 0x85 or byte == 0xa0;
}

test "stable transformation union and aliases resolve canonically" {
    try std.testing.expectEqual(@as(usize, 35), specs.len);
    for (specs) |spec| {
        try std.testing.expectEqual(spec.kind, (resolve(spec.name) orelse return error.MissingTransformation).builtin);
        const uppercase = try std.ascii.allocUpperString(std.testing.allocator, spec.name);
        defer std.testing.allocator.free(uppercase);
        try std.testing.expectEqual(spec.kind, (resolve(uppercase) orelse return error.MissingTransformation).builtin);
        try std.testing.expectEqualStrings(spec.name, spec.kind.canonicalName());
    }
    try std.testing.expectEqual(Resolution.reset, resolve("NoNe").?);
    try std.testing.expectEqual(Kind.normalise_path, resolve("normalizePath").?.builtin);
    try std.testing.expectEqual(Kind.normalise_path_win, resolve("NORMALIZEPATHWIN").?.builtin);
    try std.testing.expect(resolve("notAStableTransformation") == null);
}

test "bounded executor preserves borrowed and upstream changed semantics" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    const unchanged = try executor.apply(.lowercase, "already lower");
    try std.testing.expectEqual(Storage.borrowed, unchanged.storage);
    try std.testing.expect(!unchanged.changed);
    try std.testing.expectEqualStrings("already lower", unchanged.bytes);

    const lower = try executor.apply(.lowercase, "A\xffZ");
    try std.testing.expectEqualStrings("a\xffz", lower.bytes);
    try std.testing.expect(lower.changed);
    const upper = try executor.apply(.uppercase, "a\xffz");
    try std.testing.expectEqualStrings("A\xffZ", upper.bytes);

    const trimmed = try executor.apply(.trim, " \tvalue\r\n");
    try std.testing.expectEqual(Storage.borrowed, trimmed.storage);
    try std.testing.expectEqualStrings("value", trimmed.bytes);
    try std.testing.expect(trimmed.changed);

    const compressed_same_length = try executor.apply(.compress_whitespace, "\t");
    try std.testing.expectEqualStrings(" ", compressed_same_length.bytes);
    try std.testing.expect(!compressed_same_length.changed);
    const compressed = try executor.apply(.compress_whitespace, "\t a \n\nb");
    try std.testing.expectEqualStrings(" a b", compressed.bytes);
    try std.testing.expect(compressed.changed);
}

test "filter parity and length transformations are binary exact" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualStrings("ab", (try executor.apply(.remove_nulls, "a\x00b\x00")).bytes);
    try std.testing.expectEqualStrings("a b ", (try executor.apply(.replace_nulls, "a\x00b\x00")).bytes);
    try std.testing.expectEqualStrings("ab", (try executor.apply(.remove_whitespace, " \ta\xc2\xa0b\r")).bytes);

    const zero = try executor.apply(.parity_zero_7bit, &.{ 0xff, 0x80, 0x41 });
    try std.testing.expectEqualSlices(u8, &.{ 0x7f, 0x00, 0x41 }, zero.bytes);
    try std.testing.expect(zero.changed);
    try std.testing.expectEqualSlices(u8, &.{ 0x41, 0xc3 }, (try executor.apply(.parity_even_7bit, "AC")).bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0xc1, 0x43 }, (try executor.apply(.parity_odd_7bit, "AC")).bytes);

    const length = try executor.apply(.length, "abc\x00");
    try std.testing.expectEqualStrings("4", length.bytes);
    try std.testing.expect(length.changed);
}

test "hex profiles preserve pinned malformed and empty-input behavior" {
    var modsecurity = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer modsecurity.deinit();
    var coraza = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer coraza.deinit();

    try std.testing.expectEqualStrings("Test\x00Case", (try modsecurity.apply(.hex_decode, "546573740043617365")).bytes);
    try std.testing.expectEqualStrings("546573740043617365", (try modsecurity.apply(.hex_encode, "Test\x00Case")).bytes);
    try std.testing.expectEqualStrings("A", (try modsecurity.apply(.hex_decode, "414")).bytes);
    try std.testing.expect(!(try modsecurity.apply(.hex_decode, "")).changed);
    try std.testing.expect((try coraza.apply(.hex_decode, "")).changed);
    try std.testing.expect((try coraza.apply(.hex_encode, "")).changed);
    try std.testing.expectError(error.InvalidInput, coraza.apply(.hex_decode, "414"));
    try std.testing.expectError(error.InvalidInput, coraza.apply(.hex_decode, "0z"));
}

test "SQL hex decoding preserves malformed prefixes and decodes complete runs" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualStrings("ABC", (try executor.apply(.sql_hex_decode, "0x414243")).bytes);
    try std.testing.expectEqualStrings("aABCz  !", (try executor.apply(.sql_hex_decode, "a0x414243z 0X20!")).bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0xff, 'z' }, (try executor.apply(.sql_hex_decode, "0x00ffz")).bytes);

    for ([_][]const u8{ "", "0x", "0x4", "0xGG", "prefix 0x4" }) |malformed| {
        const result = try executor.apply(.sql_hex_decode, malformed);
        try std.testing.expectEqual(Storage.borrowed, result.storage);
        try std.testing.expect(!result.changed);
        try std.testing.expectEqualStrings(malformed, result.bytes);
    }
}

test "Base64 profiles separate strict partial and forgiving decoding" {
    var modsecurity = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer modsecurity.deinit();
    var coraza = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer coraza.deinit();

    try std.testing.expectEqualStrings("VGVzdENhc2U=", (try modsecurity.apply(.base64_encode, "TestCase")).bytes);
    try std.testing.expectEqualStrings("TestCase", (try modsecurity.apply(.base64_decode, "VGVzdENhc2U=")).bytes);
    try std.testing.expectEqualStrings("TestCase1", (try modsecurity.apply(.base64_decode, "VGVzdENhc2Ux")).bytes);
    try std.testing.expectEqualStrings("Test\x00Case", (try modsecurity.apply(.base64_decode, "VGVzdABDYXNl")).bytes);

    const strict_invalid = try modsecurity.apply(.base64_decode, "VGVz!dA==");
    try std.testing.expectEqual(Storage.borrowed, strict_invalid.storage);
    try std.testing.expect(!strict_invalid.changed);
    try std.testing.expectEqualStrings("VGVz!dA==", strict_invalid.bytes);
    try std.testing.expectEqualStrings("Test", (try coraza.apply(.base64_decode, "VGVzdA!ignored")).bytes);
    try std.testing.expectEqualStrings("Test", (try modsecurity.apply(.base64_decode_ext, "V.G V\n z-dA==")).bytes);
    try std.testing.expectEqualStrings("Test", (try coraza.apply(.base64_decode_ext, "V.G V\n zdA==")).bytes);

    try std.testing.expect(!(try modsecurity.apply(.base64_encode, "")).changed);
    try std.testing.expect((try coraza.apply(.base64_encode, "")).changed);
    try std.testing.expect(!(try coraza.apply(.base64_decode, "")).changed);
}

test "URL encoding is byte-oriented and malformed decoding is non-strict" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualStrings("Test Case", (try executor.apply(.url_decode, "Test+Case")).bytes);
    try std.testing.expectEqualStrings("% ", (try executor.apply(.url_decode, "%%20")).bytes);
    try std.testing.expectEqualStrings("%0g ", (try executor.apply(.url_decode, "%0g%20")).bytes);
    const malformed = try executor.apply(.url_decode, "%0%gg");
    try std.testing.expectEqual(Storage.borrowed, malformed.storage);
    try std.testing.expect(!malformed.changed);
    try std.testing.expectEqualStrings("%0%gg", malformed.bytes);

    try std.testing.expectEqualStrings("Test+Case", (try executor.apply(.url_encode, "Test Case")).bytes);
    try std.testing.expectEqualStrings("*AZaz09%2f%00", (try executor.apply(.url_encode, "*AZaz09/\x00")).bytes);
}

test "URL Unicode decoding matches profile flags and IIS full-width folding" {
    var modsecurity = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer modsecurity.deinit();
    var coraza = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer coraza.deinit();

    try std.testing.expectEqualStrings("Test Case", (try modsecurity.apply(.url_decode_uni, "Test%u0020Case")).bytes);
    try std.testing.expectEqualStrings("ABC", (try modsecurity.apply(.url_decode_uni, "%u0041%U0042%43")).bytes);
    try std.testing.expectEqualStrings("!~", (try modsecurity.apply(.url_decode_uni, "%uff01%uFF5e")).bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0xff }, (try modsecurity.apply(.url_decode_uni, "%u1100%u00ff")).bytes);
    try std.testing.expectEqualStrings("%u000g ", (try modsecurity.apply(.url_decode_uni, "%u000g%u0020")).bytes);
    try std.testing.expectEqualStrings("%u", (try modsecurity.apply(.url_decode_uni, "%u")).bytes);

    const modsecurity_malformed = try modsecurity.apply(.url_decode_uni, "%gg");
    try std.testing.expect(!modsecurity_malformed.changed);
    const coraza_malformed = try coraza.apply(.url_decode_uni, "%gg");
    try std.testing.expect(coraza_malformed.changed);
    try std.testing.expectEqual(Storage.borrowed, coraza_malformed.storage);
    try std.testing.expectEqualStrings("%gg", coraza_malformed.bytes);
    try std.testing.expect((try coraza.apply(.url_decode, "%gg")).changed);

    var table: [0x42]i32 = undefined;
    @memset(&table, -1);
    table[0x41] = 'z';
    var mapped = try Executor.initWithOptions(std.testing.allocator, .{}, .{
        .profile = .modsecurity,
        .unicode_map = .{ .table = &table },
    });
    defer mapped.deinit();
    try std.testing.expectEqualStrings("zB", (try mapped.apply(.url_decode_uni, "%u0041%u0042")).bytes);
}

test "CSS decoding preserves six-digit boundaries and profile changed flags" {
    var modsecurity = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer modsecurity.deinit();
    var coraza = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer coraza.deinit();

    try std.testing.expectEqualStrings("\x1a\x01AV7V7\x01x\x01x", (try modsecurity.apply(.css_decode, "\\1A\\1 A\\1234567\\123456 7\\1x\\1 x")).bytes);
    try std.testing.expectEqualStrings("\n\x0b\x0fnrtv?'\"\x00\x12#4EV!~\x00  string", (try modsecurity.apply(.css_decode, "\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\\x00\\12\\123\\1234\\12345\\123456\\ff01\\ff5e\\\n\\\x00  string")).bytes);
    try std.testing.expectEqualStrings("test", (try modsecurity.apply(.css_decode, "test\\")).bytes);

    const escaped_literal = try modsecurity.apply(.css_decode, "\\q");
    try std.testing.expectEqualStrings("q", escaped_literal.bytes);
    try std.testing.expect(!escaped_literal.changed);
    try std.testing.expect((try coraza.apply(.css_decode, "\\q")).changed);
    try std.testing.expectEqualSlices(u8, &.{ 0, 'x' }, (try modsecurity.apply(.css_decode, "\\0x")).bytes);
}

test "C escape decoding handles simple hex octal and malformed sequences" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x07, 0x08, 0x0c, '\n', '\r', '\t', 0x0b, '?', '\'', '"', 0, 10, 'S', 0, 0xff },
        (try executor.apply(.escape_seq_decode, "\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\0\\12\\123\\x00\\xff")).bytes,
    );
    try std.testing.expectEqualSlices(u8, &.{ '8', '9', 0xb6, 'x', 'a', 'g', 'x', 'g', 'a', 10, '3' }, (try executor.apply(.escape_seq_decode, "\\8\\9\\666\\xag\\xga\\0123")).bytes);

    const trailing = try executor.apply(.escape_seq_decode, "value\\");
    try std.testing.expectEqualStrings("value\\", trailing.bytes);
    try std.testing.expect(!trailing.changed);
    try std.testing.expectEqualStrings("q", (try executor.apply(.escape_seq_decode, "\\q")).bytes);
}

test "JavaScript decoding handles Unicode hex octal and escaped literals" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualSlices(
        u8,
        &.{ '\\', 'a', '\\', 'b', '\\', 'f', '\\', 'n', '\\', 'r', '\\', 't', '\\', 'v', '?', '\'', '"', 0, 10, 'S', 0, 0xff },
        (try executor.apply(.js_decode, "\\\\a\\\\b\\\\f\\\\n\\\\r\\\\t\\\\v\\?\\'\\\"\\0\\12\\123\\x00\\xff")).bytes,
    );
    try std.testing.expectEqualStrings("A!~", (try executor.apply(.js_decode, "\\u0041\\uff01\\uFF5e")).bytes);
    try std.testing.expectEqualStrings("?7", (try executor.apply(.js_decode, "\\777")).bytes);
    try std.testing.expectEqualStrings("uUxxg", (try executor.apply(.js_decode, "\\u\\U\\x\\xg")).bytes);

    const trailing = try executor.apply(.js_decode, "\\");
    try std.testing.expectEqualStrings("\\", trailing.bytes);
    try std.testing.expect(!trailing.changed);
}

test "HTML entity decoding preserves ModSecurity byte semantics" {
    var executor = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer executor.deinit();

    try std.testing.expectEqualSlices(u8, &.{ '"', '&', '<', '>', 0xa0 }, (try executor.apply(.html_entity_decode, "&quot;&AMP;&lt;&gt;&nbsp;")).bytes);
    try std.testing.expectEqualSlices(u8, &.{ 'A', 'A', 0xff, 1 }, (try executor.apply(.html_entity_decode, "&#65;&#x41;&#x1ff;&#1")).bytes);
    try std.testing.expectEqualStrings("&", (try executor.apply(.html_entity_decode, "&ampfoo;")).bytes);
    const unknown = try executor.apply(.html_entity_decode, "&unknown;");
    try std.testing.expectEqual(Storage.borrowed, unknown.storage);
    try std.testing.expect(!unknown.changed);
}

test "HTML entity decoding preserves Coraza HTML5 and Unicode semantics" {
    var executor = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer executor.deinit();

    try std.testing.expectEqualStrings("á€", (try executor.apply(.html_entity_decode, "&aacute;&#128;")).bytes);
    try std.testing.expectEqualStrings("≂̸", (try executor.apply(.html_entity_decode, "&NotEqualTilde;")).bytes);
    try std.testing.expectEqualStrings("&foo", (try executor.apply(.html_entity_decode, "&ampfoo")).bytes);
    try std.testing.expectEqualStrings("���", (try executor.apply(.html_entity_decode, "&#0;&#xD800;&#999999999999999999999;")).bytes);

    const short_numeric = try executor.apply(.html_entity_decode, "&#1");
    try std.testing.expectEqualStrings("&#1", short_numeric.bytes);
    try std.testing.expect(!short_numeric.changed);
    const unknown = try executor.apply(.html_entity_decode, "&zzzzzz;");
    try std.testing.expectEqual(Storage.borrowed, unknown.storage);

    var bounded = try Executor.initWithProfile(std.testing.allocator, .{
        .max_output_bytes = 2,
        .max_cumulative_output_bytes = 2,
    }, .coraza);
    defer bounded.deinit();
    try std.testing.expectEqualStrings("á", (try bounded.apply(.html_entity_decode, "&aacute;")).bytes);
    try std.testing.expectError(error.OutputTooLarge, bounded.apply(.html_entity_decode, "&euro;"));
}

test "UTF-8 to Unicode profiles preserve valid and hostile byte semantics" {
    var modsecurity = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer modsecurity.deinit();
    var coraza = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer coraza.deinit();

    try std.testing.expectEqualStrings("A%u00e9%u20ac%u1f600", (try modsecurity.apply(.utf8_to_unicode, "Aé€😀")).bytes);
    try std.testing.expectEqualStrings("A%u00e9%u20ac%u1f600", (try coraza.apply(.utf8_to_unicode, "Aé€😀")).bytes);
    try std.testing.expectEqualStrings("%u002f\xc0", (try modsecurity.apply(.utf8_to_unicode, "\xc0\xaf")).bytes);
    try std.testing.expectEqualStrings("%ufffd%ufffd", (try coraza.apply(.utf8_to_unicode, "\xc0\xaf")).bytes);
    try std.testing.expectEqualStrings("%ud800\xed", (try modsecurity.apply(.utf8_to_unicode, "\xed\xa0\x80")).bytes);
    try std.testing.expectEqualSlices(u8, &.{ '(', 0xa1 }, (try modsecurity.apply(.utf8_to_unicode, "\xe2(\xa1")).bytes);

    const invalid_identity = try modsecurity.apply(.utf8_to_unicode, "\xff");
    try std.testing.expectEqual(Storage.borrowed, invalid_identity.storage);
    try std.testing.expect(!invalid_identity.changed);
    const invalid_coraza = try coraza.apply(.utf8_to_unicode, "\xff");
    try std.testing.expectEqualStrings("%ufffd", invalid_coraza.bytes);
    try std.testing.expect(invalid_coraza.changed);
    const interior_null = try modsecurity.apply(.utf8_to_unicode, "a\x00b");
    try std.testing.expectEqualStrings("ab", interior_null.bytes);
    try std.testing.expect(!interior_null.changed);
}

test "UTF-8 to Unicode uses exact bounded expansion sizing" {
    var exact = try Executor.initWithProfile(std.testing.allocator, .{
        .max_output_bytes = 6,
        .max_cumulative_output_bytes = 6,
    }, .coraza);
    defer exact.deinit();
    try std.testing.expectEqualStrings("%u00e9", (try exact.apply(.utf8_to_unicode, "é")).bytes);
    try std.testing.expectEqualStrings("%ufffd", (try exact.apply(.utf8_to_unicode, "\xff")).bytes);
    try std.testing.expectError(error.OutputTooLarge, exact.apply(.utf8_to_unicode, "éé"));
}

test "comment transformations preserve pinned marker state machines" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualStrings("BeforeAfter", (try executor.apply(.remove_comments, "Before/* Test */After")).bytes);
    try std.testing.expectEqualSlices(u8, &.{0}, (try executor.apply(.remove_comments, "/* Test */")).bytes);
    try std.testing.expectEqualStrings("Before  ", (try executor.apply(.remove_comments, "Before /* unterminated")).bytes);
    try std.testing.expectEqualStrings("BeforeAfter", (try executor.apply(.remove_comments, "Before<!-- Test -->After")).bytes);
    try std.testing.expectEqualStrings("Before", (try executor.apply(.remove_comments, "Before-- line")).bytes);
    try std.testing.expectEqualStrings("Before", (try executor.apply(.remove_comments, "Before# line")).bytes);

    try std.testing.expectEqualStrings("Before Test After", (try executor.apply(.remove_comments_char, "Before/* Test */After")).bytes);
    try std.testing.expectEqualStrings("abcdef", (try executor.apply(.remove_comments_char, "a<!--b-->c--d#e/*f*/")).bytes);
    try std.testing.expectEqualStrings("Before After", (try executor.apply(.replace_comments, "Before/* Test */After")).bytes);
    try std.testing.expectEqualStrings("Before ", (try executor.apply(.replace_comments, "Before/* unterminated")).bytes);

    const closer_only = try executor.apply(.replace_comments, "Before*/After");
    try std.testing.expectEqual(Storage.borrowed, closer_only.storage);
    try std.testing.expect(!closer_only.changed);
}

test "command-line canonicalization preserves profile changed flags" {
    var modsecurity = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer modsecurity.deinit();
    var coraza = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer coraza.deinit();

    try std.testing.expectEqualStrings("command/c dir", (try modsecurity.apply(.cmd_line, "C^OMMAND /C DIR")).bytes);
    try std.testing.expectEqualStrings("cmd/c dir", (try modsecurity.apply(.cmd_line, "\"cmd\",;/c DiR")).bytes);
    try std.testing.expectEqualStrings("(test)/path", (try modsecurity.apply(.cmd_line, " (TEST) /PATH")).bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0xff, 'a' }, (try modsecurity.apply(.cmd_line, &.{ 0xff, 'A' })).bytes);

    const lowercase_only = try modsecurity.apply(.cmd_line, "UPPER");
    try std.testing.expectEqualStrings("upper", lowercase_only.bytes);
    try std.testing.expect(!lowercase_only.changed);
    try std.testing.expect((try coraza.apply(.cmd_line, "UPPER")).changed);
    const ordinary = try coraza.apply(.cmd_line, "ordinary");
    try std.testing.expectEqual(Storage.borrowed, ordinary.storage);
    try std.testing.expect(!ordinary.changed);
}

test "path normalization preserves relative root and trailing profile semantics" {
    var modsecurity = try Executor.initWithProfile(std.testing.allocator, .{}, .modsecurity);
    defer modsecurity.deinit();
    var coraza = try Executor.initWithProfile(std.testing.allocator, .{}, .coraza);
    defer coraza.deinit();

    const vectors = [_]struct { input: []const u8, output: []const u8 }{
        .{ .input = "/dir/foo//bar", .output = "/dir/foo/bar" },
        .{ .input = "dir/foo//bar/", .output = "dir/foo/bar/" },
        .{ .input = "dir/../../foo", .output = "../foo" },
        .{ .input = "dir/./.././../../foo/bar", .output = "../../foo/bar" },
        .{ .input = "/../../etc/./passwd", .output = "/etc/passwd" },
        .{ .input = "./", .output = "" },
    };
    for (vectors) |vector| {
        try std.testing.expectEqualStrings(vector.output, (try modsecurity.apply(.normalise_path, vector.input)).bytes);
        try std.testing.expectEqualStrings(vector.output, (try coraza.apply(.normalise_path, vector.input)).bytes);
    }

    const mod_relative = try modsecurity.apply(.normalise_path, "../");
    try std.testing.expectEqualStrings("../", mod_relative.bytes);
    try std.testing.expect(!mod_relative.changed);
    try std.testing.expect((try coraza.apply(.normalise_path, "../")).changed);
    try std.testing.expectEqualStrings("/", (try modsecurity.apply(.normalise_path, "/")).bytes);
    try std.testing.expectEqualStrings("//", (try coraza.apply(.normalise_path, "/")).bytes);

    const mod_windows = try modsecurity.apply(.normalise_path_win, "foo\\bar\\..\\baz");
    try std.testing.expectEqualStrings("foo/baz", mod_windows.bytes);
    try std.testing.expect(mod_windows.changed);
    const coraza_windows = try coraza.apply(.normalise_path_win, "foo\\bar");
    try std.testing.expectEqualStrings("foo/bar", coraza_windows.bytes);
    try std.testing.expect(!coraza_windows.changed);
}

test "compatibility digests return raw binary bytes" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e },
        (try executor.apply(.md5, "")).bytes,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xc9, 0xab, 0xa2, 0xc3, 0xe6, 0x01, 0x26, 0x16, 0x9e, 0x80, 0xe9, 0xa2, 0x6b, 0xa2, 0x73, 0xc1 },
        (try executor.apply(.md5, "TestCase")).bytes,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09 },
        (try executor.apply(.sha1, "")).bytes,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x63, 0xbf, 0x60, 0xc7, 0x10, 0x5a, 0x07, 0xa2, 0xb1, 0x25, 0xbb, 0xf8, 0x9e, 0x61, 0xab, 0xda, 0xbc, 0x69, 0x78, 0xc2 },
        (try executor.apply(.sha1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08")).bytes,
    );
    try std.testing.expect((try executor.apply(.md5, "")).changed);
    try std.testing.expect((try executor.apply(.sha1, "")).changed);
}

test "ordered pipelines retain storage and stage multi-match checkpoints" {
    var executor = try Executor.init(std.testing.allocator, .{});
    defer executor.deinit();

    const pipeline = [_]Kind{ .url_decode, .lowercase, .trim };
    const result = try executor.applyPipeline(&pipeline, " %41+ ", true);
    try std.testing.expectEqualStrings("a", result.bytes);
    try std.testing.expect(result.changed);
    try std.testing.expect(result.storage != .borrowed);
    try std.testing.expectEqual(@as(u32, 3), result.steps_executed);
    try std.testing.expectEqual(@as(usize, 4), result.checkpoints.len);
    try std.testing.expectEqualStrings(" %41+ ", result.checkpoints[0].bytes);
    try std.testing.expectEqual(@as(?u32, null), result.checkpoints[0].after_step);
    try std.testing.expectEqualStrings(" A  ", result.checkpoints[1].bytes);
    try std.testing.expectEqual(@as(?u32, 0), result.checkpoints[1].after_step);
    try std.testing.expectEqualStrings(" a  ", result.checkpoints[2].bytes);
    try std.testing.expectEqual(@as(?u32, 1), result.checkpoints[2].after_step);
    try std.testing.expectEqualStrings("a", result.checkpoints[3].bytes);
    try std.testing.expectEqual(@as(?u32, 2), result.checkpoints[3].after_step);

    const unchanged = try executor.applyPipeline(&[_]Kind{.lowercase}, "ordinary", true);
    try std.testing.expect(!unchanged.changed);
    try std.testing.expectEqual(@as(usize, 1), unchanged.checkpoints.len);
    const upstream_changed = try executor.applyPipeline(&[_]Kind{.length}, "1", true);
    try std.testing.expect(upstream_changed.changed);
    try std.testing.expectEqual(@as(usize, 2), upstream_changed.checkpoints.len);
    try std.testing.expectEqualStrings("1", upstream_changed.checkpoints[0].bytes);
    try std.testing.expectEqualStrings("1", upstream_changed.checkpoints[1].bytes);
    const without_multi_match = try executor.applyPipeline(&pipeline, " %41+ ", false);
    try std.testing.expectEqual(@as(usize, 0), without_multi_match.checkpoints.len);
}

test "pipeline failures publish no partial checkpoint storage" {
    var steps = try Executor.init(std.testing.allocator, .{
        .max_pipeline_steps = 1,
    });
    defer steps.deinit();
    try std.testing.expectError(error.TooManyPipelineSteps, steps.applyPipeline(&[_]Kind{ .lowercase, .uppercase }, "x", true));

    var cumulative = try Executor.init(std.testing.allocator, .{
        .max_output_bytes = 8,
        .max_cumulative_output_bytes = 8,
    });
    defer cumulative.deinit();
    try std.testing.expectError(error.CumulativeOutputTooLarge, cumulative.applyPipeline(&[_]Kind{ .lowercase, .uppercase }, "ABCD", true));
    const recovered = try cumulative.applyPipeline(&[_]Kind{}, "x", true);
    try std.testing.expectEqual(@as(usize, 1), recovered.checkpoints.len);
    try std.testing.expectEqualStrings("x", recovered.checkpoints[0].bytes);
}

test "transaction-local pipeline cache uses exact keys and preserves checkpoints" {
    var executor = try Executor.initWithOptions(std.testing.allocator, .{}, .{ .cache_enabled = true });
    defer executor.deinit();
    const pipeline = [_]Kind{ .url_decode, .lowercase };

    const miss = try executor.applyPipeline(&pipeline, "%41", true);
    try std.testing.expectEqualStrings("a", miss.bytes);
    try std.testing.expect(miss.storage != .cache);
    var stats = executor.cacheStats();
    try std.testing.expectEqual(CacheStatus.enabled, stats.status);
    try std.testing.expectEqual(@as(u64, 0), stats.hits);
    try std.testing.expectEqual(@as(u64, 1), stats.misses);
    try std.testing.expectEqual(@as(usize, 1), stats.entries);

    const hit = try executor.applyPipeline(&pipeline, "%41", true);
    try std.testing.expectEqual(Storage.cache, hit.storage);
    try std.testing.expectEqualStrings("a", hit.bytes);
    try std.testing.expectEqual(@as(usize, 3), hit.checkpoints.len);
    try std.testing.expectEqualStrings("%41", hit.checkpoints[0].bytes);
    try std.testing.expectEqualStrings("A", hit.checkpoints[1].bytes);
    try std.testing.expectEqualStrings("a", hit.checkpoints[2].bytes);
    stats = executor.cacheStats();
    try std.testing.expectEqual(@as(u64, 1), stats.hits);

    _ = try executor.applyPipeline(&pipeline, "%41", false);
    _ = try executor.applyPipeline(&[_]Kind{.url_decode}, "%41", true);
    _ = try executor.applyPipeline(&pipeline, "%42", true);
    stats = executor.cacheStats();
    try std.testing.expectEqual(@as(u64, 4), stats.misses);
    try std.testing.expectEqual(@as(usize, 4), stats.entries);
}

test "cache evicts least-recent entries and disables on an oversized entry" {
    var lru = try Executor.initWithOptions(std.testing.allocator, .{
        .max_cache_entries = 1,
    }, .{ .cache_enabled = true });
    defer lru.deinit();
    _ = try lru.applyPipeline(&[_]Kind{.lowercase}, "A", false);
    _ = try lru.applyPipeline(&[_]Kind{.lowercase}, "B", false);
    const lru_stats = lru.cacheStats();
    try std.testing.expectEqual(@as(usize, 1), lru_stats.entries);
    try std.testing.expectEqual(@as(u64, 1), lru_stats.evictions);

    var bounded = try Executor.initWithOptions(std.testing.allocator, .{
        .max_cache_bytes = 1,
    }, .{ .cache_enabled = true });
    defer bounded.deinit();
    const result = try bounded.applyPipeline(&[_]Kind{.lowercase}, "ABC", true);
    try std.testing.expectEqualStrings("abc", result.bytes);
    const bounded_stats = bounded.cacheStats();
    try std.testing.expectEqual(CacheStatus.limit_exhausted, bounded_stats.status);
    try std.testing.expectEqual(@as(usize, 0), bounded_stats.entries);
    _ = try bounded.applyPipeline(&[_]Kind{.lowercase}, "ABC", true);
    try std.testing.expectEqual(@as(u64, 1), bounded.cacheStats().misses);
}

test "executor validates deterministic input and output limits" {
    try std.testing.expectError(error.InvalidLimits, Executor.init(std.testing.allocator, .{ .max_input_bytes = 0 }));
    var executor = try Executor.init(std.testing.allocator, .{
        .max_input_bytes = 3,
        .max_output_bytes = 3,
        .max_cumulative_output_bytes = 3,
    });
    defer executor.deinit();
    try std.testing.expectError(error.InputTooLarge, executor.apply(.lowercase, "four"));
    try std.testing.expectEqualStrings("AB", (try executor.apply(.uppercase, "ab")).bytes);
    try std.testing.expectEqualStrings("a+b", (try executor.apply(.url_encode, "a b")).bytes);
    try std.testing.expectEqualStrings("a", (try executor.apply(.base64_decode, "YQ")).bytes);
    try std.testing.expectError(error.OutputTooLarge, executor.apply(.url_encode, "!!"));
    try std.testing.expectError(error.OutputTooLarge, executor.apply(.base64_encode, "abc"));
}

test "transformation failures retain stable policy classes" {
    try std.testing.expectEqual(FailureKind.configuration, failureKind(error.InvalidLimits));
    try std.testing.expectEqual(FailureKind.allocation, failureKind(error.OutOfMemory));
    try std.testing.expectEqual(FailureKind.invalid_input, failureKind(error.InvalidInput));
    try std.testing.expectEqual(FailureKind.input_limit, failureKind(error.InputTooLarge));
    try std.testing.expectEqual(FailureKind.output_limit, failureKind(error.OutputTooLarge));
    try std.testing.expectEqual(FailureKind.work_limit, failureKind(error.TooManyPipelineSteps));
    try std.testing.expectEqual(FailureKind.work_limit, failureKind(error.CumulativeOutputTooLarge));
    try std.testing.expectEqual(FailureKind.plugin, failureKind(error.PluginFailure));
}

test "executor scratch ownership is exhaustive-allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var executor = try Executor.init(allocator, .{});
            defer executor.deinit();
            try std.testing.expectEqualStrings(" mixed whitespace ", (try executor.apply(.compress_whitespace, "\t mixed\n\nwhitespace \r")).bytes);
            try std.testing.expectEqualStrings("MIXED", (try executor.apply(.uppercase, "mixed")).bytes);
            try std.testing.expectEqualSlices(u8, &.{ 0x41, 0xc3 }, (try executor.apply(.parity_even_7bit, "AC")).bytes);
            const pipeline = try executor.applyPipeline(&[_]Kind{ .url_decode, .lowercase, .trim }, " %41+ ", true);
            try std.testing.expectEqualStrings("a", pipeline.bytes);
            try std.testing.expectEqual(@as(usize, 4), pipeline.checkpoints.len);
        }
    }.run, .{});
}
