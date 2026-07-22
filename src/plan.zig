//! Immutable, compact structural execution plans compiled from SecLang syntax.

const std = @import("std");
const seclang = @import("seclang/root.zig");

pub const StringId = enum(u32) { _ };
pub const DirectiveId = enum(u32) { _ };
pub const RuleId = enum(u32) { _ };
pub const DefaultId = enum(u32) { _ };

pub const Limits = struct {
    max_documents: usize = 4096,
    max_directives: usize = 1_000_000,
    max_rules: usize = 500_000,
    max_targets: usize = 2_000_000,
    max_actions: usize = 4_000_000,
    max_transformations: usize = 4_000_000,
    max_defaults: usize = 100_000,
    max_arguments: usize = 4_000_000,
    max_strings: usize = 2_000_000,
    max_string_bytes: usize = 1024 * 1024,
    max_interned_bytes: usize = 256 * 1024 * 1024,
    max_owned_bytes: usize = 512 * 1024 * 1024,

    pub fn validate(self: Limits) error{InvalidPlanLimit}!void {
        if (self.max_documents == 0 or
            self.max_directives == 0 or
            self.max_rules == 0 or
            self.max_targets == 0 or
            self.max_actions == 0 or
            self.max_transformations == 0 or
            self.max_defaults == 0 or
            self.max_arguments == 0 or
            self.max_strings == 0 or
            self.max_string_bytes == 0 or
            self.max_interned_bytes < self.max_string_bytes or
            self.max_owned_bytes < self.max_interned_bytes)
        {
            return error.InvalidPlanLimit;
        }
        if (self.max_directives > std.math.maxInt(u32) or
            self.max_rules > std.math.maxInt(u32) or
            self.max_targets > std.math.maxInt(u32) or
            self.max_actions > std.math.maxInt(u32) or
            self.max_transformations > std.math.maxInt(u32) or
            self.max_defaults > std.math.maxInt(u32) or
            self.max_arguments > std.math.maxInt(u32) or
            self.max_strings > std.math.maxInt(u32))
        {
            return error.InvalidPlanLimit;
        }
    }
};

pub const CompileError = std.mem.Allocator.Error || error{
    InvalidPlanLimit,
    TooManyDocuments,
    TooManyDirectives,
    TooManyRules,
    TooManyTargets,
    TooManyActions,
    TooManyTransformations,
    TooManyDefaults,
    TooManyArguments,
    TooManyStrings,
    StringTooLarge,
    InternedStringLimitExceeded,
    PlanStorageLimitExceeded,
    InvalidSourceId,
    InvalidSourceSpan,
    TypedIdOverflow,
    InvalidRuleId,
    DuplicateRuleId,
    InvalidPhase,
    DanglingChain,
    ChainPhaseMismatch,
    InvalidTransformation,
};

pub const StringRange = struct { start: u32, length: u32 };

pub const SourceRecord = struct {
    path: StringId,
    bytes_start: u32,
    bytes_length: u32,
    lines_start: u32,
    lines_count: u32,
    included_from: ?seclang.source.IncludeOrigin,
};

pub const Argument = struct {
    raw: StringId,
    quote: seclang.lexer.Quote,
    source: seclang.source.Span,
};

pub const Directive = struct {
    name: StringId,
    kind: seclang.parser.Kind,
    source: seclang.source.Span,
    arguments_start: u32,
    arguments_count: u32,
    actions_start: u32,
    actions_count: u32,
    rule: ?RuleId,
};

pub const Target = struct {
    raw: StringId,
    modifier: seclang.syntax.Modifier,
    collection: StringId,
    selector: ?StringId,
};

pub const Operator = struct {
    raw: StringId,
    name: StringId,
    parameter: StringId,
    negated: bool,
    implicit_regex: bool,
};

pub const Action = struct {
    raw: StringId,
    name: StringId,
    value: ?StringId,
};

pub const Transformation = struct {
    name: StringId,
};

pub const DefaultSnapshot = struct {
    source: seclang.source.Span,
    phase: u8,
    actions_start: u32,
    actions_count: u32,
};

pub const Rule = struct {
    directive: DirectiveId,
    source: seclang.source.Span,
    external_id: ?u64,
    phase: u8,
    default: ?DefaultId,
    chain_head: RuleId,
    chain_next: ?RuleId,
    chain_position: u32,
    targets_start: u32,
    targets_count: u32,
    operator: Operator,
    actions_start: u32,
    actions_count: u32,
    transformations_start: u32,
    transformations_count: u32,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    strings: []const StringRange,
    string_bytes: []const u8,
    sources: []const SourceRecord,
    source_bytes: []const u8,
    source_lines: []const u32,
    directives: []const Directive,
    arguments: []const Argument,
    rules: []const Rule,
    targets: []const Target,
    actions: []const Action,
    transformations: []const Transformation,
    defaults: []const DefaultSnapshot,
    phase_rules: [5][]const RuleId,
    owned_bytes: usize,

    pub fn deinit(self: *Plan) void {
        const allocator = self.allocator;
        self.arena.deinit();
        allocator.destroy(self);
    }

    pub fn string(self: *const Plan, id: StringId) ?[]const u8 {
        const index: usize = @backingInt(id);
        if (index >= self.strings.len) return null;
        const range = self.strings[index];
        return self.string_bytes[range.start..][0..range.length];
    }

    pub fn sourceSlice(self: *const Plan, span: seclang.source.Span) CompileError![]const u8 {
        const index: usize = @backingInt(span.source);
        if (index >= self.sources.len) return error.InvalidSourceId;
        const record = self.sources[index];
        if (span.start > span.end or span.end > record.bytes_length) return error.InvalidSourceSpan;
        const bytes = self.source_bytes[record.bytes_start..][0..record.bytes_length];
        return bytes[span.start..span.end];
    }

    pub fn sourceLocation(self: *const Plan, source_id: seclang.source.SourceId, offset: u32) CompileError!seclang.source.Location {
        const index: usize = @backingInt(source_id);
        if (index >= self.sources.len) return error.InvalidSourceId;
        const record = self.sources[index];
        if (offset > record.bytes_length) return error.InvalidSourceSpan;
        const lines = self.source_lines[record.lines_start..][0..record.lines_count];
        var low: usize = 0;
        var high = lines.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (lines[middle] <= offset) low = middle + 1 else high = middle;
        }
        const line_index = low - 1;
        return .{ .line = @intCast(line_index + 1), .column = offset - lines[line_index] + 1, .offset = offset };
    }

    pub fn phaseRules(self: *const Plan, phase: u8) []const RuleId {
        if (phase < 1 or phase > 5) return &.{};
        return self.phase_rules[phase - 1];
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    registry: *const seclang.source.Registry,
    documents: []const seclang.parser.Document,
    limits: Limits,
) CompileError!*Plan {
    try limits.validate();
    if (documents.len > limits.max_documents) return error.TooManyDocuments;
    var compiler = Compiler.init(allocator, limits);
    defer compiler.deinit();
    for (documents) |*document| {
        try validateDocument(registry, document);
        try compiler.addDocument(document);
    }
    return compiler.finish(registry);
}

const Compiler = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    interner: Interner,
    directives: std.ArrayList(Directive) = .empty,
    arguments: std.ArrayList(Argument) = .empty,
    rules: std.ArrayList(Rule) = .empty,
    targets: std.ArrayList(Target) = .empty,
    actions: std.ArrayList(Action) = .empty,
    transformations: std.ArrayList(Transformation) = .empty,
    defaults: std.ArrayList(DefaultSnapshot) = .empty,
    phase_rules: [5]std.ArrayList(RuleId) = .{ .empty, .empty, .empty, .empty, .empty },
    rule_ids: std.AutoHashMapUnmanaged(u64, seclang.source.Span) = .empty,
    active_default: ?DefaultId = null,
    pending_chain: ?RuleId = null,

    fn init(allocator: std.mem.Allocator, limits: Limits) Compiler {
        return .{ .allocator = allocator, .limits = limits, .interner = Interner.init(allocator, limits) };
    }

    fn deinit(self: *Compiler) void {
        self.interner.deinit();
        self.directives.deinit(self.allocator);
        self.arguments.deinit(self.allocator);
        self.rules.deinit(self.allocator);
        self.targets.deinit(self.allocator);
        self.actions.deinit(self.allocator);
        self.transformations.deinit(self.allocator);
        self.defaults.deinit(self.allocator);
        self.rule_ids.deinit(self.allocator);
        for (&self.phase_rules) |*items| items.deinit(self.allocator);
    }

    fn addDocument(self: *Compiler, document: *const seclang.parser.Document) CompileError!void {
        for (document.directives.items) |directive| try self.addDirective(directive);
        if (self.pending_chain != null) return error.DanglingChain;
    }

    fn addDirective(self: *Compiler, directive: seclang.parser.Directive) CompileError!void {
        if (self.directives.items.len == self.limits.max_directives) return error.TooManyDirectives;
        if (self.pending_chain != null and directive.kind != .sec_rule) return error.DanglingChain;
        if (directive.arguments.len > self.limits.max_arguments -| self.arguments.items.len) return error.TooManyArguments;
        const argument_start = try typedIndex(self.arguments.items.len);
        for (directive.arguments) |argument| {
            try self.arguments.append(self.allocator, .{
                .raw = try self.interner.intern(argument.raw),
                .quote = argument.quote,
                .source = argument.physical,
            });
        }
        const directive_id: DirectiveId = @fromBackingInt(try typedIndex(self.directives.items.len));
        var action_range: ActionRange = .{ .start = try typedIndex(self.actions.items.len), .count = 0 };
        var rule_id: ?RuleId = null;
        switch (directive.kind) {
            .sec_rule => {
                rule_id = try self.addRule(directive_id, directive);
                const rule = self.rules.items[@backingInt(rule_id.?)];
                action_range = .{ .start = rule.actions_start, .count = rule.actions_count };
            },
            .sec_action => action_range = try self.addActions(directive.parsed_actions),
            .sec_default_action => {
                action_range = try self.addActions(directive.parsed_actions);
                if (self.defaults.items.len == self.limits.max_defaults) return error.TooManyDefaults;
                const phase = try explicitPhase(directive.parsed_actions) orelse return error.InvalidPhase;
                const default_id: DefaultId = @fromBackingInt(try typedIndex(self.defaults.items.len));
                try self.defaults.append(self.allocator, .{
                    .source = directive.physical,
                    .phase = phase,
                    .actions_start = action_range.start,
                    .actions_count = action_range.count,
                });
                self.active_default = default_id;
            },
            else => {},
        }
        try self.directives.append(self.allocator, .{
            .name = try self.interner.intern(directive.name),
            .kind = directive.kind,
            .source = directive.physical,
            .arguments_start = argument_start,
            .arguments_count = try typedIndex(directive.arguments.len),
            .actions_start = action_range.start,
            .actions_count = action_range.count,
            .rule = rule_id,
        });
    }

    fn addRule(self: *Compiler, directive_id: DirectiveId, directive: seclang.parser.Directive) CompileError!RuleId {
        if (self.rules.items.len == self.limits.max_rules) return error.TooManyRules;
        if (directive.parsed_targets.len > self.limits.max_targets -| self.targets.items.len) return error.TooManyTargets;
        const targets_start = try typedIndex(self.targets.items.len);
        for (directive.parsed_targets) |target| {
            try self.targets.append(self.allocator, .{
                .raw = try self.interner.intern(target.raw),
                .modifier = target.modifier,
                .collection = try self.interner.intern(target.collection),
                .selector = if (target.selector) |selector| try self.interner.intern(selector) else null,
            });
        }
        const action_range = try self.addActions(directive.parsed_actions);
        const parsed_operator = directive.parsed_operator.?;
        const id: RuleId = @fromBackingInt(try typedIndex(self.rules.items.len));
        const pending = self.pending_chain;
        const parsed_phase = try explicitPhase(directive.parsed_actions);
        const phase = parsed_phase orelse if (pending) |head_member|
            self.rules.items[@backingInt(head_member)].phase
        else if (self.active_default) |default_id|
            self.defaults.items[@backingInt(default_id)].phase
        else
            2;
        if (pending) |head_member| {
            if (phase != self.rules.items[@backingInt(head_member)].phase) return error.ChainPhaseMismatch;
        }
        const external_id = try explicitRuleId(directive.parsed_actions);
        if (external_id) |value| {
            if (self.rule_ids.contains(value)) return error.DuplicateRuleId;
            try self.rule_ids.put(self.allocator, value, directive.physical);
        }
        const transformation_range = try self.addTransformations(self.active_default, action_range);
        try self.rules.append(self.allocator, .{
            .directive = directive_id,
            .source = directive.physical,
            .external_id = external_id,
            .phase = phase,
            .default = self.active_default,
            .chain_head = id,
            .chain_next = null,
            .chain_position = 0,
            .targets_start = targets_start,
            .targets_count = try typedIndex(directive.parsed_targets.len),
            .operator = .{
                .raw = try self.interner.intern(parsed_operator.raw),
                .name = try self.interner.intern(parsed_operator.name),
                .parameter = try self.interner.intern(parsed_operator.parameter),
                .negated = parsed_operator.negated,
                .implicit_regex = parsed_operator.implicit_regex,
            },
            .actions_start = action_range.start,
            .actions_count = action_range.count,
            .transformations_start = transformation_range.start,
            .transformations_count = transformation_range.count,
        });
        if (pending) |previous_id| {
            const previous = &self.rules.items[@backingInt(previous_id)];
            previous.chain_next = id;
            const current = &self.rules.items[@backingInt(id)];
            current.chain_head = previous.chain_head;
            current.chain_position = previous.chain_position + 1;
        } else {
            try self.phase_rules[phase - 1].append(self.allocator, id);
        }
        self.pending_chain = if (hasAction(directive.parsed_actions, "chain")) id else null;
        return id;
    }

    const ActionRange = struct { start: u32, count: u32 };

    fn addActions(self: *Compiler, parsed_actions: []const seclang.syntax.Action) CompileError!ActionRange {
        if (parsed_actions.len > self.limits.max_actions -| self.actions.items.len) return error.TooManyActions;
        const start = try typedIndex(self.actions.items.len);
        for (parsed_actions) |action| {
            try self.actions.append(self.allocator, .{
                .raw = try self.interner.intern(action.raw),
                .name = try self.interner.intern(action.name),
                .value = if (action.value) |value| try self.interner.intern(value) else null,
            });
        }
        return .{ .start = start, .count = try typedIndex(parsed_actions.len) };
    }

    fn addTransformations(self: *Compiler, default_id: ?DefaultId, explicit: ActionRange) CompileError!ActionRange {
        var pipeline: std.ArrayList(StringId) = .empty;
        defer pipeline.deinit(self.allocator);
        if (default_id) |id| {
            const snapshot = self.defaults.items[@backingInt(id)];
            try self.applyTransformations(&pipeline, .{ .start = snapshot.actions_start, .count = snapshot.actions_count });
        }
        try self.applyTransformations(&pipeline, explicit);
        if (pipeline.items.len > self.limits.max_transformations -| self.transformations.items.len)
            return error.TooManyTransformations;
        const start = try typedIndex(self.transformations.items.len);
        for (pipeline.items) |name| try self.transformations.append(self.allocator, .{ .name = name });
        return .{ .start = start, .count = try typedIndex(pipeline.items.len) };
    }

    fn applyTransformations(self: *Compiler, pipeline: *std.ArrayList(StringId), range: ActionRange) CompileError!void {
        const actions = self.actions.items[range.start..][0..range.count];
        for (actions) |action| {
            const name = self.interner.values.items[@backingInt(action.name)];
            if (!std.ascii.eqlIgnoreCase(name, "t")) continue;
            const raw_value = if (action.value) |value| self.interner.values.items[@backingInt(value)] else return error.InvalidTransformation;
            const value = unquote(raw_value);
            if (std.ascii.eqlIgnoreCase(value, "none")) {
                pipeline.clearRetainingCapacity();
            } else {
                try pipeline.append(self.allocator, try self.interner.intern(value));
            }
        }
    }

    fn finish(self: *Compiler, registry: *const seclang.source.Registry) CompileError!*Plan {
        const plan = try self.allocator.create(Plan);
        errdefer self.allocator.destroy(plan);
        plan.* = undefined;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const arena_allocator = arena.allocator();
        var owned_bytes: usize = 0;
        for (registry.sources.items) |item| _ = try self.interner.intern(item.path);
        const strings = try self.interner.finish(arena_allocator, &owned_bytes);
        const source_data = try finishSources(arena_allocator, registry, &self.interner, &owned_bytes, self.limits);
        const directives = try duplicateCounted(Directive, arena_allocator, self.directives.items, &owned_bytes, self.limits);
        const arguments = try duplicateCounted(Argument, arena_allocator, self.arguments.items, &owned_bytes, self.limits);
        const rules = try duplicateCounted(Rule, arena_allocator, self.rules.items, &owned_bytes, self.limits);
        const targets = try duplicateCounted(Target, arena_allocator, self.targets.items, &owned_bytes, self.limits);
        const actions = try duplicateCounted(Action, arena_allocator, self.actions.items, &owned_bytes, self.limits);
        const transformations = try duplicateCounted(Transformation, arena_allocator, self.transformations.items, &owned_bytes, self.limits);
        const defaults = try duplicateCounted(DefaultSnapshot, arena_allocator, self.defaults.items, &owned_bytes, self.limits);
        var phase_rules: [5][]const RuleId = undefined;
        for (&phase_rules, &self.phase_rules) |*destination, *items| {
            destination.* = try duplicateCounted(RuleId, arena_allocator, items.items, &owned_bytes, self.limits);
        }
        plan.* = .{
            .allocator = self.allocator,
            .arena = arena,
            .strings = strings.ranges,
            .string_bytes = strings.bytes,
            .sources = source_data.records,
            .source_bytes = source_data.bytes,
            .source_lines = source_data.lines,
            .directives = directives,
            .arguments = arguments,
            .rules = rules,
            .targets = targets,
            .actions = actions,
            .transformations = transformations,
            .defaults = defaults,
            .phase_rules = phase_rules,
            .owned_bytes = owned_bytes,
        };
        return plan;
    }
};

fn explicitRuleId(actions: []const seclang.syntax.Action) CompileError!?u64 {
    for (actions) |action| {
        if (!std.ascii.eqlIgnoreCase(action.name, "id")) continue;
        const value = action.value orelse return error.InvalidRuleId;
        return parseUnsigned(unquote(value)) catch return error.InvalidRuleId;
    }
    return null;
}

fn explicitPhase(actions: []const seclang.syntax.Action) CompileError!?u8 {
    for (actions) |action| {
        if (!std.ascii.eqlIgnoreCase(action.name, "phase")) continue;
        const value = action.value orelse return error.InvalidPhase;
        const normalized = unquote(value);
        if (std.ascii.eqlIgnoreCase(normalized, "request")) return 2;
        if (std.ascii.eqlIgnoreCase(normalized, "response")) return 4;
        if (std.ascii.eqlIgnoreCase(normalized, "logging")) return 5;
        const parsed = parseUnsigned(normalized) catch return error.InvalidPhase;
        if (parsed < 1 or parsed > 5) return error.InvalidPhase;
        return @intCast(parsed);
    }
    return null;
}

fn hasAction(actions: []const seclang.syntax.Action, name: []const u8) bool {
    for (actions) |action| if (std.ascii.eqlIgnoreCase(action.name, name)) return true;
    return false;
}

fn parseUnsigned(input: []const u8) error{InvalidUnsigned}!u64 {
    if (input.len == 0) return error.InvalidUnsigned;
    var result: u64 = 0;
    for (input) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidUnsigned;
        result = std.math.mul(u64, result, 10) catch return error.InvalidUnsigned;
        result = std.math.add(u64, result, byte - '0') catch return error.InvalidUnsigned;
    }
    return result;
}

fn unquote(input: []const u8) []const u8 {
    if (input.len < 2) return input;
    if ((input[0] == '\'' and input[input.len - 1] == '\'') or
        (input[0] == '"' and input[input.len - 1] == '"'))
    {
        return input[1 .. input.len - 1];
    }
    return input;
}

fn validateDocument(registry: *const seclang.source.Registry, document: *const seclang.parser.Document) CompileError!void {
    _ = registry.get(document.source_id) orelse return error.InvalidSourceId;
    for (document.directives.items) |directive| {
        registry.validateSpan(directive.name_span) catch return error.InvalidSourceSpan;
        registry.validateSpan(directive.physical) catch return error.InvalidSourceSpan;
        for (directive.arguments) |argument| registry.validateSpan(argument.physical) catch return error.InvalidSourceSpan;
    }
}

const Interner = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    map: std.StringHashMapUnmanaged(StringId) = .empty,
    values: std.ArrayList([]u8) = .empty,
    bytes: usize = 0,

    fn init(allocator: std.mem.Allocator, limits: Limits) Interner {
        return .{ .allocator = allocator, .limits = limits };
    }

    fn deinit(self: *Interner) void {
        for (self.values.items) |value| self.allocator.free(value);
        self.values.deinit(self.allocator);
        self.map.deinit(self.allocator);
    }

    fn intern(self: *Interner, value: []const u8) CompileError!StringId {
        if (self.map.get(value)) |id| return id;
        if (value.len > self.limits.max_string_bytes) return error.StringTooLarge;
        if (self.values.items.len == self.limits.max_strings) return error.TooManyStrings;
        if (value.len > self.limits.max_interned_bytes -| self.bytes) return error.InternedStringLimitExceeded;
        const owned = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned);
        const id: StringId = @fromBackingInt(try typedIndex(self.values.items.len));
        try self.map.put(self.allocator, owned, id);
        errdefer _ = self.map.remove(owned);
        try self.values.append(self.allocator, owned);
        self.bytes += owned.len;
        return id;
    }

    const Finished = struct { ranges: []const StringRange, bytes: []const u8 };

    fn finish(self: *Interner, allocator: std.mem.Allocator, owned_bytes: *usize) CompileError!Finished {
        const ranges = try allocator.alloc(StringRange, self.values.items.len);
        try accountBytes(owned_bytes, std.mem.sliceAsBytes(ranges).len, self.limits);
        const bytes = try allocator.alloc(u8, self.bytes);
        try accountBytes(owned_bytes, bytes.len, self.limits);
        var offset: usize = 0;
        for (self.values.items, ranges) |value, *range| {
            @memcpy(bytes[offset..][0..value.len], value);
            range.* = .{ .start = try typedIndex(offset), .length = try typedIndex(value.len) };
            offset += value.len;
        }
        return .{ .ranges = ranges, .bytes = bytes };
    }
};

const FinishedSources = struct {
    records: []const SourceRecord,
    bytes: []const u8,
    lines: []const u32,
};

fn finishSources(
    allocator: std.mem.Allocator,
    registry: *const seclang.source.Registry,
    interner: *Interner,
    owned_bytes: *usize,
    limits: Limits,
) CompileError!FinishedSources {
    const records = try allocator.alloc(SourceRecord, registry.sources.items.len);
    try accountBytes(owned_bytes, std.mem.sliceAsBytes(records).len, limits);
    var byte_count: usize = 0;
    var line_count: usize = 0;
    for (registry.sources.items) |item| {
        byte_count = std.math.add(usize, byte_count, item.bytes.len) catch return error.PlanStorageLimitExceeded;
        line_count = std.math.add(usize, line_count, item.line_starts.len) catch return error.PlanStorageLimitExceeded;
    }
    if (byte_count > std.math.maxInt(u32) or line_count > std.math.maxInt(u32)) return error.TypedIdOverflow;
    const bytes = try allocator.alloc(u8, byte_count);
    try accountBytes(owned_bytes, bytes.len, limits);
    const lines = try allocator.alloc(u32, line_count);
    try accountBytes(owned_bytes, std.mem.sliceAsBytes(lines).len, limits);
    var byte_offset: usize = 0;
    var line_offset: usize = 0;
    for (registry.sources.items, records) |item, *record| {
        @memcpy(bytes[byte_offset..][0..item.bytes.len], item.bytes);
        @memcpy(lines[line_offset..][0..item.line_starts.len], item.line_starts);
        record.* = .{
            .path = interner.map.get(item.path) orelse unreachable,
            .bytes_start = try typedIndex(byte_offset),
            .bytes_length = try typedIndex(item.bytes.len),
            .lines_start = try typedIndex(line_offset),
            .lines_count = try typedIndex(item.line_starts.len),
            .included_from = item.included_from,
        };
        byte_offset += item.bytes.len;
        line_offset += item.line_starts.len;
    }
    return .{ .records = records, .bytes = bytes, .lines = lines };
}

fn duplicateCounted(
    comptime T: type,
    allocator: std.mem.Allocator,
    values: []const T,
    owned_bytes: *usize,
    limits: Limits,
) CompileError![]const T {
    const result = try allocator.dupe(T, values);
    try accountBytes(owned_bytes, std.mem.sliceAsBytes(result).len, limits);
    return result;
}

fn accountBytes(total: *usize, added: usize, limits: Limits) CompileError!void {
    if (added > limits.max_owned_bytes -| total.*) return error.PlanStorageLimitExceeded;
    total.* += added;
}

fn typedIndex(value: usize) CompileError!u32 {
    if (value > std.math.maxInt(u32)) return error.TypedIdOverflow;
    return @intCast(value);
}

test "compiled plan owns compact strings rules and source locations" {
    var parsed = try seclang.parser.parseBytes(
        std.testing.allocator,
        "owned.conf",
        "SecAction pass\nSecRule ARGS|REQUEST_HEADERS:host \"@contains attack\" \"id:1,msg:'attack',deny\"",
        .{},
        .{},
    );
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    parsed.deinit();
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 2), compiled.directives.len);
    try std.testing.expectEqual(@as(usize, 1), compiled.rules.len);
    try std.testing.expectEqual(@as(usize, 2), compiled.targets.len);
    try std.testing.expectEqualStrings("SecRule", compiled.string(compiled.directives[1].name).?);
    try std.testing.expectEqualStrings("contains", compiled.string(compiled.rules[0].operator.name).?);
    const source_text = try compiled.sourceSlice(compiled.directives[1].source);
    try std.testing.expectEqualStrings("SecRule", source_text[0..7]);
    const location = try compiled.sourceLocation(compiled.directives[1].source.source, compiled.directives[1].source.start);
    try std.testing.expectEqual(@as(u32, 2), location.line);
    try std.testing.expectEqual(@as(usize, 1), compiled.phaseRules(2).len);
}

test "compiled plan interns repeated strings and enforces limits" {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "limits.conf", "SecAction pass\nSecAction pass", .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();
    try std.testing.expect(compiled.strings.len < 6);
    try std.testing.expectError(error.TooManyDirectives, compile(std.testing.allocator, &parsed.registry, &documents, .{ .max_directives = 1 }));
    try std.testing.expectError(error.StringTooLarge, compile(std.testing.allocator, &parsed.registry, &documents, .{ .max_string_bytes = 3 }));
}

test "phase defaults chains ids and transformation resets compile structurally" {
    const input =
        \\SecDefaultAction "phase:1,t:lowercase,pass"
        \\SecRule ARGS "@rx a" "id:1,t:none,t:urlDecodeUni,chain"
        \\SecRule REQUEST_HEADERS:host "@contains b" "t:trim"
        \\SecRule TX:score "@rx c" "id:2,phase:3,deny"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "structure.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 1), compiled.defaults.len);
    try std.testing.expectEqual(@as(u8, 1), compiled.rules[0].phase);
    try std.testing.expectEqual(@as(?u64, 1), compiled.rules[0].external_id);
    try std.testing.expectEqual(@as(?u64, null), compiled.rules[1].external_id);
    try std.testing.expectEqual(@as(u8, 1), compiled.rules[1].phase);
    try std.testing.expectEqual(@as(u8, 3), compiled.rules[2].phase);
    try std.testing.expectEqual(@as(?RuleId, @fromBackingInt(@intCast(1))), compiled.rules[0].chain_next);
    try std.testing.expectEqual(@as(RuleId, @fromBackingInt(@intCast(0))), compiled.rules[1].chain_head);
    try std.testing.expectEqual(@as(u32, 1), compiled.rules[1].chain_position);
    try std.testing.expectEqual(@as(usize, 1), compiled.phaseRules(1).len);
    try std.testing.expectEqual(@as(RuleId, @fromBackingInt(@intCast(0))), compiled.phaseRules(1)[0]);
    try std.testing.expectEqual(@as(usize, 1), compiled.phaseRules(3).len);
    try std.testing.expectEqual(@as(usize, 1), compiled.rules[0].transformations_count);
    const first_transformation = compiled.transformations[compiled.rules[0].transformations_start];
    try std.testing.expectEqualStrings("urlDecodeUni", compiled.string(first_transformation.name).?);
    try std.testing.expectEqual(@as(usize, 2), compiled.rules[1].transformations_count);
}

test "structural compiler rejects duplicate ids invalid phases and malformed chains" {
    const cases = [_]struct { input: []const u8, failure: CompileError }{
        .{ .input = "SecRule ARGS @rx id:1\nSecRule TX @rx id:1", .failure = error.DuplicateRuleId },
        .{ .input = "SecRule ARGS @rx id:18446744073709551616", .failure = error.InvalidRuleId },
        .{ .input = "SecRule ARGS @rx phase:6", .failure = error.InvalidPhase },
        .{ .input = "SecRule ARGS @rx chain", .failure = error.DanglingChain },
        .{ .input = "SecRule ARGS @rx chain\nSecAction pass", .failure = error.DanglingChain },
        .{ .input = "SecRule ARGS @rx \"phase:1,chain\"\nSecRule TX @rx phase:2", .failure = error.ChainPhaseMismatch },
    };
    for (cases) |case| {
        var parsed = try seclang.parser.parseBytes(std.testing.allocator, "invalid.conf", case.input, .{}, .{});
        defer parsed.deinit();
        var documents = [_]seclang.parser.Document{parsed.document};
        try std.testing.expectError(case.failure, compile(std.testing.allocator, &parsed.registry, &documents, .{}));
    }
}
