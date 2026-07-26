//! The debug log: what the engine did, at a level the operator chose (#32).
//!
//! `SecDebugLog` and `SecDebugLogLevel` were parsed and validated and then ignored,
//! which is the worst state for a diagnostic to be in — an operator raises the level,
//! sees nothing, and concludes the engine has nothing to say rather than that nobody
//! is listening. This module is the sink those directives name.
//!
//! Two properties shape it:
//!
//! **It does no I/O.** Records go into a bounded in-memory buffer that the host
//! drains, because writing a log line is a blocking file write and the request path
//! must not contain one. A WAF that stalls a request to describe what it is doing has
//! made the diagnostic more expensive than the check.
//!
//! **It is bounded and says when it truncated.** At level 9 a single request can
//! produce a record per rule per target, which is unbounded in the input's size. The
//! buffer therefore has a record ceiling and a byte ceiling, and drops are counted
//! rather than silent: a debug log that quietly stops being complete is one an
//! operator reasons from and is misled by. `dropped` is the number of records that
//! did not fit, and it appears in the rendered output.

const std = @import("std");

/// Verbosity, matching `SecDebugLogLevel`'s 0-9 range so a ModSecurity configuration
/// means here what it means there.
///
/// The names carry the intent; the numbers are what the directive sets. A record is
/// emitted when its level is at or below the configured one, so raising the level
/// only ever adds output.
pub const Level = enum(u4) {
    /// Nothing is recorded. The default, so a build that never configures a level
    /// does no work per request rather than a little.
    none = 0,
    /// The engine could not do what the configuration asked.
    err = 1,
    /// Something was refused or degraded but the transaction continued.
    warning = 2,
    /// A decision worth knowing about: an intervention, a phase's outcome.
    notice = 3,
    /// How the transaction was handled — phases, body processing.
    info = 4,
    /// Per-rule detail: which rules ran, which matched.
    detail = 5,
    /// Per-target detail within a rule.
    trace = 6,
    /// Reserved for still finer detail; accepted so a configuration using them is
    /// honoured rather than rejected.
    trace7 = 7,
    trace8 = 8,
    /// Everything, including per-transformation steps.
    everything = 9,

    pub fn parse(text: []const u8) ?Level {
        const value = std.fmt.parseInt(u4, text, 10) catch return null;
        if (value > 9) return null;
        return @fromBackingInt(@intCast(value));
    }

    /// Whether a record at `candidate` should be emitted when the configured level is
    /// `self`. Level `none` permits nothing, including errors: a configuration that
    /// asked for silence gets it.
    pub fn permits(self: Level, candidate: Level) bool {
        if (self == .none) return false;
        return @backingInt(candidate) <= @backingInt(self);
    }
};

/// What `SecDebugLog` and `SecDebugLogLevel` asked for.
pub const Settings = struct {
    /// Where the host should write the drained records, or null when unset. This
    /// module never opens it — it does no I/O — but the path is the operator's
    /// instruction and has to reach whoever can act on it.
    path: ?[]const u8 = null,
    level: Level = .none,

    /// Whether anything is actually configured. A path with level 0, or a level with
    /// no path, produces no log; saying so lets a host report the half-configuration
    /// rather than write to a file nobody asked for or compute records nobody reads.
    pub fn active(self: Settings) bool {
        return self.path != null and self.level != .none;
    }
};

/// Read the debug-log settings out of a compiled plan.
///
/// An unparseable level is reported as `error.InvalidLevel` rather than defaulting: a
/// configuration that says `SecDebugLogLevel 12` is wrong, and quietly reading it as
/// 9 or 0 would either flood the log or silence it, both without telling anyone.
pub fn settingsFromPlan(compiled: anytype) error{InvalidLevel}!Settings {
    var settings: Settings = .{};
    if (compiled.settingText("SecDebugLog")) |path| {
        if (path.len != 0) settings.path = path;
    }
    if (compiled.settingText("SecDebugLogLevel")) |text| {
        settings.level = Level.parse(text) orelse return error.InvalidLevel;
    }
    return settings;
}

/// One thing that happened.
pub const Record = struct {
    level: Level,
    /// The phase it happened in, or null outside rule evaluation.
    phase: ?u3,
    /// The rule it concerns, or null when it is not about one rule.
    rule_id: ?u32,
    /// The message, owned by the recorder.
    message: []const u8,
};

pub const Limits = struct {
    /// Records kept before dropping. A request at level 9 can emit one per rule per
    /// target, so this is what keeps a diagnostic from becoming a memory leak.
    max_records: usize = 4096,
    /// Bytes of message text kept, across all records.
    max_bytes: usize = 256 * 1024,
    /// The longest single message. Longer ones are truncated with a marker rather
    /// than dropped, since the beginning of a long message is usually the useful
    /// part.
    max_message_bytes: usize = 2048,
};

/// What was truncated, so the reader knows the log is not the whole story.
pub const Stats = struct {
    recorded: usize = 0,
    /// Records that did not fit under a limit.
    dropped: usize = 0,
    /// Messages kept but shortened.
    truncated: usize = 0,
};

/// A bounded, non-blocking sink. Not thread-safe: one per transaction, or one guarded
/// by the host. Sharing an unguarded recorder between threads would corrupt it, which
/// is why this says so rather than taking a lock nobody needs.
pub const Recorder = struct {
    allocator: std.mem.Allocator,
    level: Level = .none,
    limits: Limits = .{},
    records: std.ArrayList(Record) = .empty,
    bytes_held: usize = 0,
    stats: Stats = .{},

    pub fn init(allocator: std.mem.Allocator, level: Level, limits: Limits) Recorder {
        return .{ .allocator = allocator, .level = level, .limits = limits };
    }

    pub fn deinit(self: *Recorder) void {
        for (self.records.items) |item| self.allocator.free(item.message);
        self.records.deinit(self.allocator);
        self.* = undefined;
    }

    /// Whether anything at `level` would be kept. Callers check this before
    /// formatting, so a disabled log costs a comparison rather than a message nobody
    /// reads.
    pub fn permits(self: *const Recorder, level: Level) bool {
        return self.level.permits(level);
    }

    /// Record a message. Silently does nothing when the level is not permitted —
    /// that is the point of a level — and counts a drop when a limit is reached.
    ///
    /// Allocation failure is counted as a drop rather than returned: a diagnostic
    /// that fails the request it is describing has inverted its purpose.
    pub fn record(self: *Recorder, level: Level, phase: ?u3, rule_id: ?u32, message: []const u8) void {
        if (!self.permits(level)) return;
        if (self.records.items.len >= self.limits.max_records) {
            self.stats.dropped += 1;
            return;
        }

        var kept = message;
        var truncated = false;
        if (kept.len > self.limits.max_message_bytes) {
            kept = kept[0..self.limits.max_message_bytes];
            truncated = true;
        }
        if (self.bytes_held + kept.len > self.limits.max_bytes) {
            self.stats.dropped += 1;
            return;
        }

        const owned = self.allocator.dupe(u8, kept) catch {
            self.stats.dropped += 1;
            return;
        };
        self.records.append(self.allocator, .{
            .level = level,
            .phase = phase,
            .rule_id = rule_id,
            .message = owned,
        }) catch {
            self.allocator.free(owned);
            self.stats.dropped += 1;
            return;
        };
        self.bytes_held += owned.len;
        self.stats.recorded += 1;
        if (truncated) self.stats.truncated += 1;
    }

    /// Record a formatted message. Formatting happens into a stack buffer, so a
    /// message longer than it is truncated exactly as `record` would truncate it.
    pub fn print(
        self: *Recorder,
        level: Level,
        phase: ?u3,
        rule_id: ?u32,
        comptime format: []const u8,
        arguments: anytype,
    ) void {
        if (!self.permits(level)) return;
        var buffer: [4096]u8 = undefined;
        const message = std.fmt.bufPrint(&buffer, format, arguments) catch blk: {
            // A message that overflows the buffer is kept up to its length rather
            // than lost: a truncated diagnostic beats none.
            self.stats.truncated += 1;
            break :blk buffer[0..];
        };
        self.record(level, phase, rule_id, message);
    }

    pub fn items(self: *const Recorder) []const Record {
        return self.records.items;
    }

    /// Drop everything, keeping the counters. The host calls this after draining, and
    /// the counters survive because "how much was dropped" is a property of the
    /// transaction, not of the current buffer contents.
    pub fn clear(self: *Recorder) void {
        for (self.records.items) |item| self.allocator.free(item.message);
        self.records.clearRetainingCapacity();
        self.bytes_held = 0;
    }

    /// Render as text, one record per line, ending with a summary line when anything
    /// was dropped or truncated. The summary is not optional decoration: without it a
    /// reader cannot tell a complete log from a clipped one.
    pub fn render(self: *const Recorder, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        for (self.records.items) |item| {
            try writer.print("[{d}]", .{@backingInt(item.level)});
            if (item.phase) |phase| try writer.print(" [phase {d}]", .{phase});
            if (item.rule_id) |id| try writer.print(" [id {d}]", .{id});
            try writer.print(" {s}\n", .{item.message});
        }
        if (self.stats.dropped != 0 or self.stats.truncated != 0) {
            try writer.print(
                "[0] debug log incomplete: {d} record(s) dropped, {d} message(s) truncated\n",
                .{ self.stats.dropped, self.stats.truncated },
            );
        }
    }
};

// ---- tests --------------------------------------------------------------

const testing = std.testing;

test "a level permits itself and everything less verbose, and none permits nothing" {
    try testing.expectEqual(Level.none, Level.parse("0").?);
    try testing.expectEqual(Level.detail, Level.parse("5").?);
    try testing.expectEqual(Level.everything, Level.parse("9").?);
    // Out of range and non-numeric are rejected rather than clamped: a configuration
    // asking for level 12 is a mistake, and clamping it hides the mistake.
    try testing.expect(Level.parse("10") == null);
    try testing.expect(Level.parse("-1") == null);
    try testing.expect(Level.parse("") == null);
    try testing.expect(Level.parse("debug") == null);

    // Raising the level only adds output.
    try testing.expect(Level.detail.permits(.err));
    try testing.expect(Level.detail.permits(.detail));
    try testing.expect(!Level.detail.permits(.trace));
    try testing.expect(Level.everything.permits(.everything));

    // Silence means silence, including errors.
    try testing.expect(!Level.none.permits(.err));
    try testing.expect(!Level.none.permits(.none));
}

test "records below the configured level cost nothing and are not kept" {
    var recorder = Recorder.init(testing.allocator, .notice, .{});
    defer recorder.deinit();

    recorder.record(.err, null, null, "cannot open data file");
    recorder.record(.detail, 2, 942100, "rule evaluated"); // too verbose for .notice
    try testing.expectEqual(@as(usize, 1), recorder.items().len);
    try testing.expectEqual(@as(usize, 1), recorder.stats.recorded);
    try testing.expectEqualStrings("cannot open data file", recorder.items()[0].message);

    // A disabled recorder keeps nothing at all, so an engine can call into it
    // unconditionally.
    var silent = Recorder.init(testing.allocator, .none, .{});
    defer silent.deinit();
    silent.record(.err, null, null, "not kept");
    silent.print(.err, null, null, "not kept either: {d}", .{1});
    try testing.expectEqual(@as(usize, 0), silent.items().len);
    try testing.expect(!silent.permits(.err));
}

test "a record cap drops rather than grows, and says how much it dropped" {
    var recorder = Recorder.init(testing.allocator, .everything, .{ .max_records = 2 });
    defer recorder.deinit();

    recorder.record(.info, 1, null, "one");
    recorder.record(.info, 1, null, "two");
    recorder.record(.info, 1, null, "three");
    recorder.record(.info, 1, null, "four");

    try testing.expectEqual(@as(usize, 2), recorder.items().len);
    try testing.expectEqual(@as(usize, 2), recorder.stats.dropped);
    // The kept records are the first ones: at level 9 the early records describe how
    // the transaction started, which is what a reader needs to follow it.
    try testing.expectEqualStrings("one", recorder.items()[0].message);
    try testing.expectEqualStrings("two", recorder.items()[1].message);

    // The rendering says the log is not complete, because a reader who cannot tell a
    // clipped log from a whole one will reason from a gap as though it were absence.
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try recorder.render(&writer);
    const text = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, text, "[4] [phase 1] one") != null);
    try testing.expect(std.mem.indexOf(u8, text, "2 record(s) dropped") != null);
}

test "a byte cap drops, and an oversized message is truncated rather than lost" {
    var recorder = Recorder.init(testing.allocator, .everything, .{
        .max_bytes = 16,
        .max_message_bytes = 8,
    });
    defer recorder.deinit();

    recorder.record(.info, null, null, "0123456789abcdef"); // truncated to 8
    try testing.expectEqual(@as(usize, 1), recorder.items().len);
    try testing.expectEqualStrings("01234567", recorder.items()[0].message);
    try testing.expectEqual(@as(usize, 1), recorder.stats.truncated);

    recorder.record(.info, null, null, "abcdefgh"); // fills the byte budget exactly
    try testing.expectEqual(@as(usize, 2), recorder.items().len);
    recorder.record(.info, null, null, "x"); // no room left
    try testing.expectEqual(@as(usize, 2), recorder.items().len);
    try testing.expectEqual(@as(usize, 1), recorder.stats.dropped);
}

test "rendering names the phase and rule, and clearing keeps the counters" {
    var recorder = Recorder.init(testing.allocator, .detail, .{ .max_records = 1 });
    defer recorder.deinit();

    recorder.print(.detail, 2, 942100, "matched at {s}", .{"ARGS:id"});
    recorder.record(.detail, 2, 942100, "dropped by the cap");

    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try recorder.render(&writer);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "[5] [phase 2] [id 942100] matched at ARGS:id") != null);

    // Clearing frees the records but not the record of what was lost: "how much was
    // dropped" is a fact about the transaction, not about the current buffer.
    recorder.clear();
    try testing.expectEqual(@as(usize, 0), recorder.items().len);
    try testing.expectEqual(@as(usize, 0), recorder.bytes_held);
    try testing.expectEqual(@as(usize, 1), recorder.stats.dropped);
    try testing.expectEqual(@as(usize, 1), recorder.stats.recorded);

    // And it is usable again afterwards.
    recorder.record(.detail, null, null, "after clear");
    try testing.expectEqual(@as(usize, 1), recorder.items().len);
}

test "the debug-log directives are readable from a compiled configuration" {
    // The point of this test is that SecDebugLog and SecDebugLogLevel stop being
    // decorative. Before this, both parsed and validated and nothing could read
    // them, so an operator raising the level saw no change and had no way to tell
    // that nothing was listening.
    const seclang = @import("seclang/root.zig");
    const plan = @import("plan.zig");

    var parsed = try seclang.parser.parseBytes(testing.allocator, "debug.conf",
        \\SecRuleEngine On
        \\SecDebugLog /var/log/waf-debug.log
        \\SecDebugLogLevel 4
        \\SecRule ARGS "@rx attack" "id:1,phase:2,deny"
    , .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try plan.compile(testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    const settings = try settingsFromPlan(compiled);
    try testing.expectEqualStrings("/var/log/waf-debug.log", settings.path.?);
    try testing.expectEqual(Level.info, settings.level);
    try testing.expect(settings.active());
}

test "a later setting replaces an earlier one, and a half-configuration is not active" {
    const seclang = @import("seclang/root.zig");
    const plan = @import("plan.zig");

    // Singular-replace semantics: the last declaration wins, which is what the
    // parser resolves and therefore what a reader has to agree with. Taking the
    // first would make an include's setting beat the one after it.
    var parsed = try seclang.parser.parseBytes(testing.allocator, "debug.conf",
        \\SecDebugLog /tmp/first.log
        \\SecDebugLogLevel 9
        \\SecDebugLog /tmp/second.log
        \\SecDebugLogLevel 3
    , .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try plan.compile(testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    const settings = try settingsFromPlan(compiled);
    try testing.expectEqualStrings("/tmp/second.log", settings.path.?);
    try testing.expectEqual(Level.notice, settings.level);

    // A configuration that names no path at all is inactive rather than logging
    // somewhere the operator did not choose.
    var levelled = try seclang.parser.parseBytes(testing.allocator, "level-only.conf", "SecDebugLogLevel 5", .{}, .{});
    defer levelled.deinit();
    var level_documents = [_]seclang.parser.Document{levelled.document};
    const level_only = try plan.compile(testing.allocator, &levelled.registry, &level_documents, .{});
    defer level_only.deinit();
    const level_settings = try settingsFromPlan(level_only);
    try testing.expectEqual(Level.detail, level_settings.level);
    try testing.expect(level_settings.path == null);
    try testing.expect(!level_settings.active());

    // A path with level 0 is the other half, and equally inactive: the operator
    // named a file and asked for nothing to go in it.
    var pathed = try seclang.parser.parseBytes(testing.allocator, "path-only.conf",
        \\SecDebugLog /tmp/quiet.log
        \\SecDebugLogLevel 0
    , .{}, .{});
    defer pathed.deinit();
    var path_documents = [_]seclang.parser.Document{pathed.document};
    const path_only = try plan.compile(testing.allocator, &pathed.registry, &path_documents, .{});
    defer path_only.deinit();
    const path_settings = try settingsFromPlan(path_only);
    try testing.expect(path_settings.path != null);
    try testing.expectEqual(Level.none, path_settings.level);
    try testing.expect(!path_settings.active());

    // And a configuration with neither is simply unconfigured.
    var bare = try seclang.parser.parseBytes(testing.allocator, "bare.conf", "SecRuleEngine On", .{}, .{});
    defer bare.deinit();
    var bare_documents = [_]seclang.parser.Document{bare.document};
    const bare_plan = try plan.compile(testing.allocator, &bare.registry, &bare_documents, .{});
    defer bare_plan.deinit();
    const bare_settings = try settingsFromPlan(bare_plan);
    try testing.expect(bare_settings.path == null);
    try testing.expectEqual(Level.none, bare_settings.level);
}
