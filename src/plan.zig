//! Immutable, compact structural execution plans compiled from SecLang syntax.

const std = @import("std");
const seclang = @import("seclang/root.zig");

pub const StringId = enum(u32) { _ };
pub const DirectiveId = enum(u32) { _ };
pub const RuleId = enum(u32) { _ };
pub const DefaultId = enum(u32) { _ };
pub const MacroProgramId = enum(u32) { _ };
pub const compiler_abi_version: u32 = 2;
pub const Fingerprint = [32]u8;
pub const evidence_json = @embedFile("compatibility/evidence/structural-plan.json");

pub const Limits = struct {
    max_documents: usize = 4096,
    max_source_references: usize = 4096,
    max_directives: usize = 1_000_000,
    max_rules: usize = 500_000,
    max_rules_per_phase: usize = 500_000,
    max_chain_members: usize = 4096,
    max_graph_edges: usize = 500_000,
    max_generic_directives: usize = 500_000,
    max_markers: usize = 500_000,
    max_macro_programs: usize = 1_000_000,
    max_macro_tokens: usize = 8_000_000,
    max_targets: usize = 2_000_000,
    max_actions: usize = 4_000_000,
    max_transformations: usize = 4_000_000,
    max_prefilters: usize = 500_000,
    max_prefilter_literals: usize = 2_000_000,
    max_prefilter_bytes: usize = 128 * 1024 * 1024,
    max_defaults: usize = 100_000,
    max_arguments: usize = 4_000_000,
    max_strings: usize = 2_000_000,
    max_string_bytes: usize = 1024 * 1024,
    max_interned_bytes: usize = 256 * 1024 * 1024,
    max_owned_bytes: usize = 512 * 1024 * 1024,

    pub fn validate(self: Limits) error{InvalidPlanLimit}!void {
        if (self.max_documents == 0 or
            self.max_source_references == 0 or
            self.max_directives == 0 or
            self.max_rules == 0 or
            self.max_rules_per_phase == 0 or
            self.max_chain_members == 0 or
            self.max_graph_edges == 0 or
            self.max_generic_directives == 0 or
            self.max_markers == 0 or
            self.max_macro_programs == 0 or
            self.max_macro_tokens == 0 or
            self.max_targets == 0 or
            self.max_actions == 0 or
            self.max_transformations == 0 or
            self.max_prefilters == 0 or
            self.max_prefilter_literals == 0 or
            self.max_prefilter_bytes == 0 or
            self.max_defaults == 0 or
            self.max_arguments == 0 or
            self.max_strings == 0 or
            self.max_string_bytes == 0 or
            self.max_interned_bytes < self.max_string_bytes or
            self.max_owned_bytes < self.max_interned_bytes)
        {
            return error.InvalidPlanLimit;
        }
        if (self.max_documents > std.math.maxInt(u32) or
            self.max_source_references > std.math.maxInt(u32) or
            self.max_directives > std.math.maxInt(u32) or
            self.max_rules > std.math.maxInt(u32) or
            self.max_rules_per_phase > std.math.maxInt(u32) or
            self.max_chain_members > std.math.maxInt(u32) or
            self.max_graph_edges > std.math.maxInt(u32) or
            self.max_generic_directives > std.math.maxInt(u32) or
            self.max_markers > std.math.maxInt(u32) or
            self.max_macro_programs > std.math.maxInt(u32) or
            self.max_macro_tokens > std.math.maxInt(u32) or
            self.max_targets > std.math.maxInt(u32) or
            self.max_actions > std.math.maxInt(u32) or
            self.max_transformations > std.math.maxInt(u32) or
            self.max_prefilters > std.math.maxInt(u32) or
            self.max_prefilter_literals > std.math.maxInt(u32) or
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
    TooManySourceReferences,
    TooManyDirectives,
    TooManyRules,
    TooManyRulesInPhase,
    TooManyChainMembers,
    TooManyGraphEdges,
    TooManyGenericDirectives,
    TooManyMarkers,
    TooManyMacroPrograms,
    TooManyMacroTokens,
    TooManyTargets,
    TooManyActions,
    TooManyTransformations,
    TooManyPrefilters,
    TooManyPrefilterLiterals,
    PrefilterBytesLimitExceeded,
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
    UnterminatedMacro,
    EmptyMacroExpression,
};

pub const DiagnosticCode = enum {
    invalid_rule_id,
    duplicate_rule_id,
    invalid_phase,
    dangling_chain,
    chain_phase_mismatch,
    invalid_transformation,
    unterminated_macro,
    empty_macro_expression,

    pub fn id(self: DiagnosticCode) []const u8 {
        return switch (self) {
            .invalid_rule_id => "WAF-PLAN-0101",
            .duplicate_rule_id => "WAF-PLAN-0102",
            .invalid_phase => "WAF-PLAN-0103",
            .dangling_chain => "WAF-PLAN-0104",
            .chain_phase_mismatch => "WAF-PLAN-0105",
            .invalid_transformation => "WAF-PLAN-0106",
            .unterminated_macro => "WAF-PLAN-0107",
            .empty_macro_expression => "WAF-PLAN-0108",
        };
    }

    pub fn message(self: DiagnosticCode) []const u8 {
        return switch (self) {
            .invalid_rule_id => "rule id must be an unsigned 64-bit integer",
            .duplicate_rule_id => "rule id is already defined",
            .invalid_phase => "phase must name or number one of the five SecLang phases",
            .dangling_chain => "chain action must be followed by another SecRule in the same document",
            .chain_phase_mismatch => "all members of a rule chain must execute in the same phase",
            .invalid_transformation => "transformation action requires a non-empty name",
            .unterminated_macro => "runtime macro expression is missing a closing brace",
            .empty_macro_expression => "runtime macro expression cannot be empty",
        };
    }
};

pub const Diagnostic = struct {
    code: DiagnosticCode,
    primary: seclang.source.Span,
    secondary: ?seclang.source.Span = null,
    message: []const u8,
};

pub const CompileOutcome = union(enum) {
    plan: *Plan,
    diagnostic: Diagnostic,

    pub fn deinit(self: *CompileOutcome) void {
        switch (self.*) {
            .plan => |value| value.deinit(),
            .diagnostic => {},
        }
        self.* = undefined;
    }
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
    prefilter: ?Prefilter,
    macro: ?MacroProgramId,
};

pub const PrefilterKind = enum { exact, prefix, suffix, contains, phrases_any };

pub const Prefilter = struct {
    kind: PrefilterKind,
    literals_start: u32,
    literals_count: u32,
};

pub const Action = struct {
    raw: StringId,
    name: StringId,
    value: ?StringId,
    class: ActionClass,
    macro: ?MacroProgramId,
};

pub const ActionClass = enum { transformation, metadata, nondisruptive, disruptive, flow, unknown };

pub const Marker = struct {
    directive: DirectiveId,
    name: StringId,
};

pub const MacroTokenKind = enum { literal, scalar, collection };

pub const MacroToken = struct {
    kind: MacroTokenKind,
    source_start: u32,
    source_length: u32,
    name: ?StringId = null,
    key: ?StringId = null,
};

pub const MacroProgram = struct {
    source: StringId,
    tokens_start: u32,
    tokens_count: u32,
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

const Component = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    references: std.atomic.Value(usize) = .init(1),
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
    prefilter_literals: []const StringId,
    markers: []const Marker,
    generic_directives: []const DirectiveId,
    macro_programs: []const MacroProgram,
    macro_tokens: []const MacroToken,
    defaults: []const DefaultSnapshot,
    phase_rules: [5][]const RuleId,
    owned_bytes: usize,

    fn retain(self: *Component) void {
        const previous = self.references.fetchAdd(1, .monotonic);
        std.debug.assert(previous > 0 and previous < std.math.maxInt(usize));
    }

    fn release(self: *Component) void {
        const previous = self.references.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
        if (previous != 1) return;
        const allocator = self.allocator;
        self.arena.deinit();
        allocator.destroy(self);
    }
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    component: *Component,
    compiler_abi: u32,
    fingerprint: Fingerprint,
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
    prefilter_literals: []const StringId,
    markers: []const Marker,
    generic_directives: []const DirectiveId,
    macro_programs: []const MacroProgram,
    macro_tokens: []const MacroToken,
    defaults: []const DefaultSnapshot,
    phase_rules: [5][]const RuleId,
    owned_bytes: usize,

    pub fn deinit(self: *Plan) void {
        const allocator = self.allocator;
        self.component.release();
        allocator.destroy(self);
    }

    /// Create another owned handle to the same immutable payload.
    pub fn retain(self: *const Plan, allocator: std.mem.Allocator) std.mem.Allocator.Error!*Plan {
        const retained = try allocator.create(Plan);
        self.component.retain();
        retained.allocator = allocator;
        attachComponent(retained, self.component);
        retained.fingerprint = self.fingerprint;
        return retained;
    }

    pub fn sharedReferenceCount(self: *const Plan) usize {
        return self.component.references.load(.acquire);
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

    /// Returns false only when the advisory prefilter proves the operator cannot
    /// match. Callers must still execute the operator when this returns true.
    pub fn prefilterMayMatch(self: *const Plan, value: Prefilter, input: []const u8) bool {
        const ids = self.prefilter_literals[value.literals_start..][0..value.literals_count];
        return switch (value.kind) {
            .exact => std.mem.eql(u8, input, self.string(ids[0]).?),
            .prefix => std.mem.startsWith(u8, input, self.string(ids[0]).?),
            .suffix => std.mem.endsWith(u8, input, self.string(ids[0]).?),
            .contains => std.mem.indexOf(u8, input, self.string(ids[0]).?) != null,
            .phrases_any => for (ids) |id| {
                if (std.mem.indexOf(u8, input, self.string(id).?) != null) break true;
            } else false,
        };
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    registry: *const seclang.source.Registry,
    documents: []const seclang.parser.Document,
    limits: Limits,
) CompileError!*Plan {
    return compileDetailed(allocator, registry, documents, limits, null);
}

/// Compile transactionally, then reuse the prior immutable payload only when
/// every owned field is exactly equivalent. The public fingerprint is a fast
/// reject, never the sole equality decision.
pub fn compileWithPrevious(
    allocator: std.mem.Allocator,
    registry: *const seclang.source.Registry,
    documents: []const seclang.parser.Document,
    limits: Limits,
    previous: *const Plan,
) CompileError!*Plan {
    const candidate = try compile(allocator, registry, documents, limits);
    if (!componentsEqual(candidate, previous)) return candidate;
    candidate.component.release();
    previous.component.retain();
    attachComponent(candidate, previous.component);
    candidate.fingerprint = previous.fingerprint;
    return candidate;
}

pub fn compileOutcome(
    allocator: std.mem.Allocator,
    registry: *const seclang.source.Registry,
    documents: []const seclang.parser.Document,
    limits: Limits,
) CompileError!CompileOutcome {
    var failure: ?Failure = null;
    const plan = compileDetailed(allocator, registry, documents, limits, &failure) catch |cause| {
        if (failure) |detail| {
            const code = diagnosticCode(cause) orelse return cause;
            return .{ .diagnostic = .{
                .code = code,
                .primary = detail.primary,
                .secondary = detail.secondary,
                .message = code.message(),
            } };
        }
        return cause;
    };
    return .{ .plan = plan };
}

fn compileDetailed(
    allocator: std.mem.Allocator,
    registry: *const seclang.source.Registry,
    documents: []const seclang.parser.Document,
    limits: Limits,
    failure: ?*?Failure,
) CompileError!*Plan {
    try limits.validate();
    if (documents.len > limits.max_documents) return error.TooManyDocuments;
    if (registry.sources.items.len > limits.max_source_references) return error.TooManySourceReferences;
    var compiler = Compiler.init(allocator, limits, failure);
    defer compiler.deinit();
    for (documents) |*document| {
        try validateDocument(registry, document);
        try compiler.addDocument(document);
    }
    return compiler.finish(registry);
}

const Failure = struct {
    primary: seclang.source.Span,
    secondary: ?seclang.source.Span = null,
};

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
    prefilter_literals: std.ArrayList(StringId) = .empty,
    markers: std.ArrayList(Marker) = .empty,
    generic_directives: std.ArrayList(DirectiveId) = .empty,
    macro_programs: std.ArrayList(MacroProgram) = .empty,
    macro_tokens: std.ArrayList(MacroToken) = .empty,
    macro_program_by_source: std.AutoHashMapUnmanaged(StringId, MacroProgramId) = .empty,
    prefilter_count: usize = 0,
    prefilter_bytes: usize = 0,
    defaults: std.ArrayList(DefaultSnapshot) = .empty,
    phase_rules: [5]std.ArrayList(RuleId) = .{ .empty, .empty, .empty, .empty, .empty },
    rule_ids: std.AutoHashMapUnmanaged(u64, seclang.source.Span) = .empty,
    active_default: ?DefaultId = null,
    pending_chain: ?RuleId = null,
    pending_chain_members: usize = 0,
    graph_edges: usize = 0,
    failure: ?*?Failure,

    fn init(allocator: std.mem.Allocator, limits: Limits, failure: ?*?Failure) Compiler {
        return .{ .allocator = allocator, .limits = limits, .interner = Interner.init(allocator, limits), .failure = failure };
    }

    fn deinit(self: *Compiler) void {
        self.interner.deinit();
        self.directives.deinit(self.allocator);
        self.arguments.deinit(self.allocator);
        self.rules.deinit(self.allocator);
        self.targets.deinit(self.allocator);
        self.actions.deinit(self.allocator);
        self.transformations.deinit(self.allocator);
        self.prefilter_literals.deinit(self.allocator);
        self.markers.deinit(self.allocator);
        self.generic_directives.deinit(self.allocator);
        self.macro_programs.deinit(self.allocator);
        self.macro_tokens.deinit(self.allocator);
        self.macro_program_by_source.deinit(self.allocator);
        self.defaults.deinit(self.allocator);
        self.rule_ids.deinit(self.allocator);
        for (&self.phase_rules) |*items| items.deinit(self.allocator);
    }

    fn addDocument(self: *Compiler, document: *const seclang.parser.Document) CompileError!void {
        for (document.directives.items) |directive| try self.addDirective(directive);
        if (self.pending_chain) |pending| return self.fail(error.DanglingChain, self.rules.items[@backingInt(pending)].source, null);
    }

    fn addDirective(self: *Compiler, directive: seclang.parser.Directive) CompileError!void {
        if (self.directives.items.len == self.limits.max_directives) return error.TooManyDirectives;
        if (self.pending_chain) |pending| {
            if (directive.kind != .sec_rule)
                return self.fail(error.DanglingChain, directive.physical, self.rules.items[@backingInt(pending)].source);
        }
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
            .sec_action => action_range = self.addActions(directive.parsed_actions) catch |cause|
                return self.fail(cause, actionSpan(directive), null),
            .sec_default_action => {
                action_range = self.addActions(directive.parsed_actions) catch |cause|
                    return self.fail(cause, actionSpan(directive), null);
                if (self.defaults.items.len == self.limits.max_defaults) return error.TooManyDefaults;
                const phase = (explicitPhase(directive.parsed_actions) catch
                    return self.fail(error.InvalidPhase, actionSpan(directive), null)) orelse
                    return self.fail(error.InvalidPhase, actionSpan(directive), null);
                const default_id: DefaultId = @fromBackingInt(try typedIndex(self.defaults.items.len));
                try self.defaults.append(self.allocator, .{
                    .source = directive.physical,
                    .phase = phase,
                    .actions_start = action_range.start,
                    .actions_count = action_range.count,
                });
                self.active_default = default_id;
            },
            .sec_marker => {
                if (self.markers.items.len == self.limits.max_markers) return error.TooManyMarkers;
                try self.markers.append(self.allocator, .{
                    .directive = directive_id,
                    .name = try self.interner.intern(directive.arguments[0].content()),
                });
            },
            .generic => {
                if (self.generic_directives.items.len == self.limits.max_generic_directives)
                    return error.TooManyGenericDirectives;
                try self.generic_directives.append(self.allocator, directive_id);
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
        const action_range = self.addActions(directive.parsed_actions) catch |cause|
            return self.fail(cause, actionSpan(directive), null);
        const parsed_operator = directive.parsed_operator.?;
        const id: RuleId = @fromBackingInt(try typedIndex(self.rules.items.len));
        const pending = self.pending_chain;
        const parsed_phase = explicitPhase(directive.parsed_actions) catch
            return self.fail(error.InvalidPhase, actionSpan(directive), null);
        const phase = parsed_phase orelse if (pending) |head_member|
            self.rules.items[@backingInt(head_member)].phase
        else if (self.active_default) |default_id|
            self.defaults.items[@backingInt(default_id)].phase
        else
            2;
        if (pending) |head_member| {
            if (phase != self.rules.items[@backingInt(head_member)].phase)
                return self.fail(error.ChainPhaseMismatch, actionSpan(directive), self.rules.items[@backingInt(head_member)].source);
            if (self.pending_chain_members == self.limits.max_chain_members) return error.TooManyChainMembers;
            if (self.graph_edges == self.limits.max_graph_edges) return error.TooManyGraphEdges;
        }
        const external_id = explicitRuleId(directive.parsed_actions) catch
            return self.fail(error.InvalidRuleId, actionSpan(directive), null);
        if (external_id) |value| {
            if (self.rule_ids.get(value)) |first|
                return self.fail(error.DuplicateRuleId, actionSpan(directive), first);
            try self.rule_ids.put(self.allocator, value, directive.physical);
        }
        const transformation_range = self.addTransformations(self.active_default, action_range) catch |cause|
            return self.fail(cause, actionSpan(directive), null);
        const prefilter = try self.addPrefilter(parsed_operator);
        const operator_macro = self.addMacro(unquote(parsed_operator.parameter)) catch |cause|
            return self.fail(cause, directive.operator().?.physical, null);
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
                .prefilter = prefilter,
                .macro = operator_macro,
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
            self.pending_chain_members += 1;
            self.graph_edges += 1;
        } else {
            if (self.phase_rules[phase - 1].items.len == self.limits.max_rules_per_phase)
                return error.TooManyRulesInPhase;
            try self.phase_rules[phase - 1].append(self.allocator, id);
            self.pending_chain_members = 1;
        }
        self.pending_chain = if (hasAction(directive.parsed_actions, "chain")) id else null;
        if (self.pending_chain == null) self.pending_chain_members = 0;
        return id;
    }

    fn fail(self: *Compiler, cause: CompileError, primary: seclang.source.Span, secondary: ?seclang.source.Span) CompileError {
        if (self.failure) |output| output.* = .{ .primary = primary, .secondary = secondary };
        return cause;
    }

    const ActionRange = struct { start: u32, count: u32 };

    fn addActions(self: *Compiler, parsed_actions: []const seclang.syntax.Action) CompileError!ActionRange {
        if (parsed_actions.len > self.limits.max_actions -| self.actions.items.len) return error.TooManyActions;
        const start = try typedIndex(self.actions.items.len);
        for (parsed_actions) |action| {
            const value_id = if (action.value) |value| try self.interner.intern(value) else null;
            try self.actions.append(self.allocator, .{
                .raw = try self.interner.intern(action.raw),
                .name = try self.interner.intern(action.name),
                .value = value_id,
                .class = classifyAction(action.name),
                .macro = if (action.value) |value| try self.addMacro(unquote(value)) else null,
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

    fn addPrefilter(self: *Compiler, operator: seclang.syntax.Operator) CompileError!?Prefilter {
        // A missing literal can make a negated operator match, so it cannot be
        // used as a rejection prefilter.
        if (operator.negated) return null;
        const normalized = unquote(operator.parameter);
        const kind: PrefilterKind = if (std.ascii.eqlIgnoreCase(operator.name, "streq"))
            .exact
        else if (std.ascii.eqlIgnoreCase(operator.name, "beginsWith"))
            .prefix
        else if (std.ascii.eqlIgnoreCase(operator.name, "endsWith"))
            .suffix
        else if (std.ascii.eqlIgnoreCase(operator.name, "contains"))
            .contains
        else if (std.ascii.eqlIgnoreCase(operator.name, "pm"))
            .phrases_any
        else if (std.ascii.eqlIgnoreCase(operator.name, "rx") and isLiteralRegex(normalized))
            .contains
        else
            return null;
        const parameter = if (kind == .phrases_any) operator.parameter else normalized;
        if (parameter.len == 0) return null;
        if (std.mem.indexOf(u8, parameter, "%{") != null) return null;

        if (self.prefilter_count == self.limits.max_prefilters) return error.TooManyPrefilters;
        const start = try typedIndex(self.prefilter_literals.items.len);
        if (kind == .phrases_any) {
            if (!safePhraseList(parameter)) return null;
            var words = std.mem.tokenizeAny(u8, parameter, " \t\r\n");
            while (words.next()) |word| try self.addPrefilterLiteral(word);
            if (self.prefilter_literals.items.len == start) return null;
        } else {
            try self.addPrefilterLiteral(parameter);
        }
        self.prefilter_count += 1;
        return .{
            .kind = kind,
            .literals_start = start,
            .literals_count = try typedIndex(self.prefilter_literals.items.len - start),
        };
    }

    fn addPrefilterLiteral(self: *Compiler, literal: []const u8) CompileError!void {
        if (self.prefilter_literals.items.len == self.limits.max_prefilter_literals)
            return error.TooManyPrefilterLiterals;
        if (literal.len > self.limits.max_prefilter_bytes -| self.prefilter_bytes)
            return error.PrefilterBytesLimitExceeded;
        try self.prefilter_literals.append(self.allocator, try self.interner.intern(literal));
        self.prefilter_bytes += literal.len;
    }

    fn addMacro(self: *Compiler, source: []const u8) CompileError!?MacroProgramId {
        if (std.mem.indexOf(u8, source, "%{") == null) return null;
        const source_id = try self.interner.intern(source);
        if (self.macro_program_by_source.get(source_id)) |existing| return existing;
        if (self.macro_programs.items.len == self.limits.max_macro_programs) return error.TooManyMacroPrograms;
        const program_id: MacroProgramId = @fromBackingInt(try typedIndex(self.macro_programs.items.len));
        const tokens_start = try typedIndex(self.macro_tokens.items.len);
        var literal_start: usize = 0;
        var cursor: usize = 0;
        while (cursor < source.len) {
            const marker = std.mem.indexOfPos(u8, source, cursor, "%{") orelse break;
            if (literal_start < marker) try self.appendMacroToken(.{
                .kind = .literal,
                .source_start = try typedIndex(literal_start),
                .source_length = try typedIndex(marker - literal_start),
            });
            const expression_start = marker + 2;
            const close = std.mem.indexOfScalarPos(u8, source, expression_start, '}') orelse return error.UnterminatedMacro;
            if (close == expression_start) return error.EmptyMacroExpression;
            const expression = source[expression_start..close];
            if (std.mem.indexOfScalar(u8, expression, '.')) |dot| {
                try self.appendMacroToken(.{
                    .kind = .collection,
                    .source_start = try typedIndex(marker),
                    .source_length = try typedIndex(close + 1 - marker),
                    .name = try self.interner.intern(expression[0..dot]),
                    .key = try self.interner.intern(expression[dot + 1 ..]),
                });
            } else {
                try self.appendMacroToken(.{
                    .kind = .scalar,
                    .source_start = try typedIndex(marker),
                    .source_length = try typedIndex(close + 1 - marker),
                    .name = try self.interner.intern(expression),
                });
            }
            cursor = close + 1;
            literal_start = cursor;
        }
        if (literal_start < source.len) try self.appendMacroToken(.{
            .kind = .literal,
            .source_start = try typedIndex(literal_start),
            .source_length = try typedIndex(source.len - literal_start),
        });
        try self.macro_programs.append(self.allocator, .{
            .source = source_id,
            .tokens_start = tokens_start,
            .tokens_count = try typedIndex(self.macro_tokens.items.len - tokens_start),
        });
        try self.macro_program_by_source.put(self.allocator, source_id, program_id);
        return program_id;
    }

    fn appendMacroToken(self: *Compiler, token: MacroToken) CompileError!void {
        if (self.macro_tokens.items.len == self.limits.max_macro_tokens) return error.TooManyMacroTokens;
        try self.macro_tokens.append(self.allocator, token);
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
        const component = try self.allocator.create(Component);
        errdefer self.allocator.destroy(component);
        component.* = undefined;
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
        const prefilter_literals = try duplicateCounted(StringId, arena_allocator, self.prefilter_literals.items, &owned_bytes, self.limits);
        const markers = try duplicateCounted(Marker, arena_allocator, self.markers.items, &owned_bytes, self.limits);
        const generic_directives = try duplicateCounted(DirectiveId, arena_allocator, self.generic_directives.items, &owned_bytes, self.limits);
        const macro_programs = try duplicateCounted(MacroProgram, arena_allocator, self.macro_programs.items, &owned_bytes, self.limits);
        const macro_tokens = try duplicateCounted(MacroToken, arena_allocator, self.macro_tokens.items, &owned_bytes, self.limits);
        const defaults = try duplicateCounted(DefaultSnapshot, arena_allocator, self.defaults.items, &owned_bytes, self.limits);
        var phase_rules: [5][]const RuleId = undefined;
        for (&phase_rules, &self.phase_rules) |*destination, *items| {
            destination.* = try duplicateCounted(RuleId, arena_allocator, items.items, &owned_bytes, self.limits);
        }
        component.* = .{
            .allocator = self.allocator,
            .arena = arena,
            .references = .init(1),
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
            .prefilter_literals = prefilter_literals,
            .markers = markers,
            .generic_directives = generic_directives,
            .macro_programs = macro_programs,
            .macro_tokens = macro_tokens,
            .defaults = defaults,
            .phase_rules = phase_rules,
            .owned_bytes = owned_bytes,
        };
        plan.allocator = self.allocator;
        attachComponent(plan, component);
        plan.fingerprint = computeFingerprint(plan);
        return plan;
    }
};

fn attachComponent(plan: *Plan, component: *Component) void {
    plan.component = component;
    plan.compiler_abi = compiler_abi_version;
    plan.strings = component.strings;
    plan.string_bytes = component.string_bytes;
    plan.sources = component.sources;
    plan.source_bytes = component.source_bytes;
    plan.source_lines = component.source_lines;
    plan.directives = component.directives;
    plan.arguments = component.arguments;
    plan.rules = component.rules;
    plan.targets = component.targets;
    plan.actions = component.actions;
    plan.transformations = component.transformations;
    plan.prefilter_literals = component.prefilter_literals;
    plan.markers = component.markers;
    plan.generic_directives = component.generic_directives;
    plan.macro_programs = component.macro_programs;
    plan.macro_tokens = component.macro_tokens;
    plan.defaults = component.defaults;
    plan.phase_rules = component.phase_rules;
    plan.owned_bytes = component.owned_bytes;
}

fn componentsEqual(first: *const Plan, second: *const Plan) bool {
    if (first.compiler_abi != second.compiler_abi or
        !std.mem.eql(u8, &first.fingerprint, &second.fingerprint) or
        first.owned_bytes != second.owned_bytes or
        !slicesEqual(StringRange, first.strings, second.strings) or
        !std.mem.eql(u8, first.string_bytes, second.string_bytes) or
        !slicesEqual(SourceRecord, first.sources, second.sources) or
        !std.mem.eql(u8, first.source_bytes, second.source_bytes) or
        !std.mem.eql(u32, first.source_lines, second.source_lines) or
        !slicesEqual(Directive, first.directives, second.directives) or
        !slicesEqual(Argument, first.arguments, second.arguments) or
        !slicesEqual(Rule, first.rules, second.rules) or
        !slicesEqual(Target, first.targets, second.targets) or
        !slicesEqual(Action, first.actions, second.actions) or
        !slicesEqual(Transformation, first.transformations, second.transformations) or
        !std.mem.eql(StringId, first.prefilter_literals, second.prefilter_literals) or
        !slicesEqual(Marker, first.markers, second.markers) or
        !std.mem.eql(DirectiveId, first.generic_directives, second.generic_directives) or
        !slicesEqual(MacroProgram, first.macro_programs, second.macro_programs) or
        !slicesEqual(MacroToken, first.macro_tokens, second.macro_tokens) or
        !slicesEqual(DefaultSnapshot, first.defaults, second.defaults))
    {
        return false;
    }
    for (first.phase_rules, second.phase_rules) |first_phase, second_phase| {
        if (!std.mem.eql(RuleId, first_phase, second_phase)) return false;
    }
    return true;
}

fn slicesEqual(comptime T: type, first: []const T, second: []const T) bool {
    if (first.len != second.len) return false;
    for (first, second) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

fn computeFingerprint(plan: *const Plan) Fingerprint {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("zig-waf structural plan\x00");
    hashU32(&hasher, compiler_abi_version);

    hashU32(&hasher, @intCast(plan.directives.len));
    for (plan.directives) |directive| {
        hashString(&hasher, plan.string(directive.name).?);
        hashU8(&hasher, @intCast(@backingInt(directive.kind)));
        hashU32(&hasher, directive.arguments_count);
        hashU32(&hasher, directive.actions_count);
        hashOptionalId(&hasher, directive.rule);
    }
    hashU32(&hasher, @intCast(plan.arguments.len));
    for (plan.arguments) |argument| {
        hashString(&hasher, plan.string(argument.raw).?);
        hashU8(&hasher, @intCast(@backingInt(argument.quote)));
    }
    hashU32(&hasher, @intCast(plan.targets.len));
    for (plan.targets) |target| {
        hashU8(&hasher, @intCast(@backingInt(target.modifier)));
        hashString(&hasher, plan.string(target.collection).?);
        hashOptionalString(&hasher, plan, target.selector);
    }
    hashU32(&hasher, @intCast(plan.actions.len));
    for (plan.actions) |action| {
        hashString(&hasher, plan.string(action.name).?);
        hashOptionalString(&hasher, plan, action.value);
        hashU8(&hasher, @intCast(@backingInt(action.class)));
        hashOptionalId(&hasher, action.macro);
    }
    hashU32(&hasher, @intCast(plan.transformations.len));
    for (plan.transformations) |transformation| hashString(&hasher, plan.string(transformation.name).?);
    hashU32(&hasher, @intCast(plan.prefilter_literals.len));
    for (plan.prefilter_literals) |literal| hashString(&hasher, plan.string(literal).?);

    hashU32(&hasher, @intCast(plan.rules.len));
    for (plan.rules) |rule| {
        hashU32(&hasher, @backingInt(rule.directive));
        hashOptionalU64(&hasher, rule.external_id);
        hashU8(&hasher, rule.phase);
        hashOptionalId(&hasher, rule.default);
        hashU32(&hasher, @backingInt(rule.chain_head));
        hashOptionalId(&hasher, rule.chain_next);
        hashU32(&hasher, rule.chain_position);
        hashU32(&hasher, rule.targets_start);
        hashU32(&hasher, rule.targets_count);
        hashString(&hasher, plan.string(rule.operator.name).?);
        hashString(&hasher, plan.string(rule.operator.parameter).?);
        hashBool(&hasher, rule.operator.negated);
        hashBool(&hasher, rule.operator.implicit_regex);
        hashOptionalId(&hasher, rule.operator.macro);
        if (rule.operator.prefilter) |prefilter| {
            hashBool(&hasher, true);
            hashU8(&hasher, @intCast(@backingInt(prefilter.kind)));
            hashU32(&hasher, prefilter.literals_start);
            hashU32(&hasher, prefilter.literals_count);
        } else hashBool(&hasher, false);
        hashU32(&hasher, rule.actions_start);
        hashU32(&hasher, rule.actions_count);
        hashU32(&hasher, rule.transformations_start);
        hashU32(&hasher, rule.transformations_count);
    }

    hashU32(&hasher, @intCast(plan.defaults.len));
    for (plan.defaults) |snapshot| {
        hashU8(&hasher, snapshot.phase);
        hashU32(&hasher, snapshot.actions_start);
        hashU32(&hasher, snapshot.actions_count);
    }
    for (plan.phase_rules) |rules| {
        hashU32(&hasher, @intCast(rules.len));
        for (rules) |rule| hashU32(&hasher, @backingInt(rule));
    }
    hashU32(&hasher, @intCast(plan.markers.len));
    for (plan.markers) |marker| {
        hashU32(&hasher, @backingInt(marker.directive));
        hashString(&hasher, plan.string(marker.name).?);
    }
    hashU32(&hasher, @intCast(plan.generic_directives.len));
    for (plan.generic_directives) |directive| hashU32(&hasher, @backingInt(directive));
    hashU32(&hasher, @intCast(plan.macro_programs.len));
    for (plan.macro_programs) |program| {
        hashString(&hasher, plan.string(program.source).?);
        hashU32(&hasher, program.tokens_start);
        hashU32(&hasher, program.tokens_count);
    }
    hashU32(&hasher, @intCast(plan.macro_tokens.len));
    for (plan.macro_tokens) |token| {
        hashU8(&hasher, @intCast(@backingInt(token.kind)));
        hashU32(&hasher, token.source_start);
        hashU32(&hasher, token.source_length);
        hashOptionalString(&hasher, plan, token.name);
        hashOptionalString(&hasher, plan, token.key);
    }

    var result: Fingerprint = undefined;
    hasher.final(&result);
    return result;
}

fn hashString(hasher: *std.crypto.hash.Blake3, value: []const u8) void {
    hashU32(hasher, @intCast(value.len));
    hasher.update(value);
}

fn hashOptionalString(hasher: *std.crypto.hash.Blake3, plan: *const Plan, value: ?StringId) void {
    if (value) |id| {
        hashBool(hasher, true);
        hashString(hasher, plan.string(id).?);
    } else hashBool(hasher, false);
}

fn hashOptionalId(hasher: *std.crypto.hash.Blake3, value: anytype) void {
    if (value) |id| {
        hashBool(hasher, true);
        hashU32(hasher, @backingInt(id));
    } else hashBool(hasher, false);
}

fn hashOptionalU64(hasher: *std.crypto.hash.Blake3, value: ?u64) void {
    if (value) |number| {
        hashBool(hasher, true);
        hashU64(hasher, number);
    } else hashBool(hasher, false);
}

fn hashBool(hasher: *std.crypto.hash.Blake3, value: bool) void {
    hashU8(hasher, @intFromBool(value));
}

fn hashU8(hasher: *std.crypto.hash.Blake3, value: u8) void {
    hasher.update(&.{value});
}

fn hashU32(hasher: *std.crypto.hash.Blake3, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hasher.update(&bytes);
}

fn hashU64(hasher: *std.crypto.hash.Blake3, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hasher.update(&bytes);
}

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

fn classifyAction(name: []const u8) ActionClass {
    if (std.ascii.eqlIgnoreCase(name, "t")) return .transformation;
    if (equalsAny(name, &.{ "id", "msg", "logdata", "tag", "severity", "ver", "rev", "maturity", "accuracy" }))
        return .metadata;
    if (equalsAny(name, &.{
        "capture",              "setvar",                "setenv",                 "initcol",     "expirevar",
        "deprecatevar",         "multimatch",            "log",                    "nolog",       "auditlog",
        "noauditlog",           "ctl",                   "exec",                   "pause",       "prepend",
        "append",               "setuid",                "setsid",                 "sanitizeArg", "sanitizeMatched",
        "sanitizeMatchedBytes", "sanitizeRequestHeader", "sanitizeResponseHeader",
    })) return .nondisruptive;
    if (equalsAny(name, &.{ "allow", "block", "deny", "drop", "pass", "proxy", "redirect" }))
        return .disruptive;
    if (equalsAny(name, &.{ "chain", "skip", "skipAfter" })) return .flow;
    return .unknown;
}

fn equalsAny(value: []const u8, candidates: []const []const u8) bool {
    for (candidates) |candidate| if (std.ascii.eqlIgnoreCase(value, candidate)) return true;
    return false;
}

fn actionSpan(directive: seclang.parser.Directive) seclang.source.Span {
    return if (directive.actions()) |argument| argument.physical else directive.physical;
}

fn diagnosticCode(cause: anyerror) ?DiagnosticCode {
    return switch (cause) {
        error.InvalidRuleId => .invalid_rule_id,
        error.DuplicateRuleId => .duplicate_rule_id,
        error.InvalidPhase => .invalid_phase,
        error.DanglingChain => .dangling_chain,
        error.ChainPhaseMismatch => .chain_phase_mismatch,
        error.InvalidTransformation => .invalid_transformation,
        error.UnterminatedMacro => .unterminated_macro,
        error.EmptyMacroExpression => .empty_macro_expression,
        else => null,
    };
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

fn isLiteralRegex(pattern: []const u8) bool {
    if (pattern.len == 0) return false;
    for (pattern) |byte| switch (byte) {
        '\\', '.', '^', '$', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|' => return false,
        else => {},
    };
    return true;
}

fn safePhraseList(parameter: []const u8) bool {
    for (parameter) |byte| switch (byte) {
        '\\', '\'', '"' => return false,
        else => {},
    };
    return true;
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

const PlanReadWorker = struct {
    plan: *const Plan,
    ready: *std.atomic.Value(usize),
    release: *std.atomic.Value(bool),
    failures: *std.atomic.Value(usize),

    fn run(self: *PlanReadWorker) void {
        _ = self.ready.fetchAdd(1, .release);
        while (!self.release.load(.acquire)) std.atomic.spinLoopHint();
        for (0..10_000) |_| {
            if (self.plan.rules.len != 1 or
                self.plan.phaseRules(2).len != 1 or
                !std.mem.eql(u8, self.plan.string(self.plan.rules[0].operator.name).?, "contains"))
            {
                _ = self.failures.fetchAdd(1, .monotonic);
                return;
            }
        }
    }
};

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

test "compile outcome anchors semantic diagnostics and related definitions" {
    const duplicate =
        \\SecRule ARGS @rx id:700
        \\SecRule TX @rx id:700
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "duplicate.conf", duplicate, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    var outcome = try compileOutcome(std.testing.allocator, &parsed.registry, &documents, .{});
    defer outcome.deinit();
    switch (outcome) {
        .plan => return error.TestExpectedDiagnostic,
        .diagnostic => |value| {
            try std.testing.expectEqual(DiagnosticCode.duplicate_rule_id, value.code);
            try std.testing.expectEqualStrings("WAF-PLAN-0102", value.code.id());
            try std.testing.expectEqual(parsed.document.directives.items[1].actions().?.physical, value.primary);
            try std.testing.expectEqual(parsed.document.directives.items[0].physical, value.secondary.?);
            const location = try parsed.registry.location(value.primary.source, value.primary.start);
            try std.testing.expectEqual(@as(u32, 2), location.line);
        },
    }
}

test "compile outcome identifies chain and transformation failures" {
    const cases = [_]struct {
        input: []const u8,
        code: DiagnosticCode,
        related: bool,
    }{
        .{ .input = "SecRule ARGS @rx chain\nSecAction pass", .code = .dangling_chain, .related = true },
        .{ .input = "SecRule ARGS @rx \"phase:1,chain\"\nSecRule TX @rx phase:2", .code = .chain_phase_mismatch, .related = true },
        .{ .input = "SecRule ARGS @rx t", .code = .invalid_transformation, .related = false },
    };
    for (cases) |case| {
        var parsed = try seclang.parser.parseBytes(std.testing.allocator, "semantic.conf", case.input, .{}, .{});
        defer parsed.deinit();
        var documents = [_]seclang.parser.Document{parsed.document};
        var outcome = try compileOutcome(std.testing.allocator, &parsed.registry, &documents, .{});
        defer outcome.deinit();
        switch (outcome) {
            .plan => return error.TestExpectedDiagnostic,
            .diagnostic => |value| {
                try std.testing.expectEqual(case.code, value.code);
                try std.testing.expectEqual(case.related, value.secondary != null);
            },
        }
    }
}

test "compiler emits only conservative literal prefilters" {
    const input =
        \\SecRule ARGS "@streq alpha" id:1
        \\SecRule ARGS "@beginsWith beta" id:2
        \\SecRule ARGS "@endsWith gamma" id:3
        \\SecRule ARGS "@contains delta" id:4
        \\SecRule ARGS "@pm one two three" id:5
        \\SecRule ARGS "plain literal" id:6
        \\SecRule ARGS "^anchored$" id:7
        \\SecRule ARGS "@pm 'quoted phrase'" id:8
        \\SecRule ARGS "!@contains negated" id:9
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "prefilters.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    const expected = [_]?PrefilterKind{ .exact, .prefix, .suffix, .contains, .phrases_any, .contains, null, null, null };
    for (compiled.rules, expected) |rule, kind| {
        try std.testing.expectEqual(kind, if (rule.operator.prefilter) |value| value.kind else null);
    }
    const phrase = compiled.rules[4].operator.prefilter.?;
    try std.testing.expectEqual(@as(u32, 3), phrase.literals_count);
    const phrase_ids = compiled.prefilter_literals[phrase.literals_start..][0..phrase.literals_count];
    try std.testing.expectEqualStrings("one", compiled.string(phrase_ids[0]).?);
    try std.testing.expectEqualStrings("two", compiled.string(phrase_ids[1]).?);
    try std.testing.expectEqualStrings("three", compiled.string(phrase_ids[2]).?);

    try std.testing.expect(compiled.prefilterMayMatch(compiled.rules[0].operator.prefilter.?, "alpha"));
    try std.testing.expect(!compiled.prefilterMayMatch(compiled.rules[0].operator.prefilter.?, "alphabet"));
    try std.testing.expect(compiled.prefilterMayMatch(compiled.rules[1].operator.prefilter.?, "beta-tail"));
    try std.testing.expect(compiled.prefilterMayMatch(compiled.rules[2].operator.prefilter.?, "head-gamma"));
    try std.testing.expect(compiled.prefilterMayMatch(compiled.rules[3].operator.prefilter.?, "has delta here"));
    try std.testing.expect(compiled.prefilterMayMatch(phrase, "contains two here"));
    try std.testing.expect(!compiled.prefilterMayMatch(phrase, "absent values"));
}

test "prefilter limits fail explicitly" {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "prefilter-limits.conf", "SecRule ARGS \"@pm one two\" id:1", .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    try std.testing.expectError(error.TooManyPrefilterLiterals, compile(std.testing.allocator, &parsed.registry, &documents, .{ .max_prefilter_literals = 1 }));
    try std.testing.expectError(error.PrefilterBytesLimitExceeded, compile(std.testing.allocator, &parsed.registry, &documents, .{ .max_prefilter_bytes = 3 }));
}

test "literal prefilters never reject reference matches under mutation" {
    const input =
        \\SecRule ARGS "@streq alpha" id:1
        \\SecRule ARGS "@beginsWith beta" id:2
        \\SecRule ARGS "@endsWith gamma" id:3
        \\SecRule ARGS "@contains delta" id:4
        \\SecRule ARGS "@pm one two three" id:5
        \\SecRule ARGS "plain" id:6
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "prefilter-differential.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();
    var prng = std.Random.DefaultPrng.init(0x70_72_65_66_69_6c_74_72);
    const random = prng.random();
    const alphabet = "abcdefghijklmnopqrstuvwxyz ";
    var candidate: [96]u8 = undefined;
    for (0..10_000) |_| {
        const length = random.uintLessThan(usize, candidate.len + 1);
        for (candidate[0..length]) |*byte| byte.* = alphabet[random.uintLessThan(usize, alphabet.len)];
        const value = candidate[0..length];
        for (compiled.rules, 0..) |rule, index| {
            const prefilter = rule.operator.prefilter.?;
            const parameter = compiled.string(rule.operator.parameter).?;
            const reference_match = switch (index) {
                0 => std.mem.eql(u8, value, parameter),
                1 => std.mem.startsWith(u8, value, parameter),
                2 => std.mem.endsWith(u8, value, parameter),
                3, 5 => std.mem.indexOf(u8, value, parameter) != null,
                4 => std.mem.indexOf(u8, value, "one") != null or
                    std.mem.indexOf(u8, value, "two") != null or
                    std.mem.indexOf(u8, value, "three") != null,
                else => unreachable,
            };
            if (reference_match) try std.testing.expect(compiled.prefilterMayMatch(prefilter, value));
        }
    }
}

test "plan indexes markers generic directives and structural action families" {
    const input =
        \\SecMarker CHECKPOINT
        \\SecExample value
        \\SecAction "id:1,t:none,msg:'notice',setvar:tx.x=1,deny,skip:1,futureAction"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "indexes.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 1), compiled.markers.len);
    try std.testing.expectEqualStrings("CHECKPOINT", compiled.string(compiled.markers[0].name).?);
    try std.testing.expectEqual(@as(DirectiveId, @fromBackingInt(0)), compiled.markers[0].directive);
    try std.testing.expectEqualSlices(DirectiveId, &.{@as(DirectiveId, @fromBackingInt(1))}, compiled.generic_directives);
    const classes = [_]ActionClass{ .metadata, .transformation, .metadata, .nondisruptive, .disruptive, .flow, .unknown };
    for (compiled.actions, classes) |action, class| try std.testing.expectEqual(class, action.class);
}

test "phase chain marker and generic resource limits fail distinctly" {
    const cases = [_]struct {
        input: []const u8,
        limits: Limits,
        failure: CompileError,
    }{
        .{ .input = "SecRule ARGS @rx id:1\nSecRule TX @rx id:2", .limits = .{ .max_rules_per_phase = 1 }, .failure = error.TooManyRulesInPhase },
        .{ .input = "SecRule ARGS @rx chain\nSecRule TX @rx", .limits = .{ .max_chain_members = 1 }, .failure = error.TooManyChainMembers },
        .{ .input = "SecRule ARGS @rx chain\nSecRule TX @rx chain\nSecRule REQUEST_HEADERS @rx", .limits = .{ .max_graph_edges = 1 }, .failure = error.TooManyGraphEdges },
        .{ .input = "SecMarker one\nSecMarker two", .limits = .{ .max_markers = 1 }, .failure = error.TooManyMarkers },
        .{ .input = "SecOne value\nSecTwo value", .limits = .{ .max_generic_directives = 1 }, .failure = error.TooManyGenericDirectives },
    };
    for (cases) |case| {
        var parsed = try seclang.parser.parseBytes(std.testing.allocator, "bounded.conf", case.input, .{}, .{});
        defer parsed.deinit();
        var documents = [_]seclang.parser.Document{parsed.document};
        try std.testing.expectError(case.failure, compile(std.testing.allocator, &parsed.registry, &documents, case.limits));
    }
}

test "source reference limit is independent of document count" {
    var registry = try seclang.source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const first = try registry.add("one.conf", "SecAction pass", null);
    _ = try registry.add("included.conf", "SecAction pass", null);
    var document = try seclang.parser.parseSource(std.testing.allocator, &registry, first, .{});
    defer document.deinit();
    var documents = [_]seclang.parser.Document{document};
    try std.testing.expectError(error.TooManySourceReferences, compile(std.testing.allocator, &registry, &documents, .{ .max_source_references = 1 }));
}

test "fingerprints are deterministic semantic identities independent of paths" {
    const input =
        \\SecDefaultAction "phase:2,pass,t:lowercase"
        \\SecRule ARGS "@contains attack" "id:100,deny"
        \\SecMarker END
    ;
    var first = try seclang.parser.parseBytes(std.testing.allocator, "/tmp/first/rules.conf", input, .{}, .{});
    defer first.deinit();
    var second = try seclang.parser.parseBytes(std.testing.allocator, "/different/root/rules.conf", input, .{}, .{});
    defer second.deinit();
    var changed = try seclang.parser.parseBytes(std.testing.allocator, "/tmp/first/rules.conf", "SecRule ARGS \"@contains changed\" id:100", .{}, .{});
    defer changed.deinit();
    var first_documents = [_]seclang.parser.Document{first.document};
    var second_documents = [_]seclang.parser.Document{second.document};
    var changed_documents = [_]seclang.parser.Document{changed.document};
    const first_plan = try compile(std.testing.allocator, &first.registry, &first_documents, .{});
    defer first_plan.deinit();
    const second_plan = try compile(std.testing.allocator, &second.registry, &second_documents, .{});
    defer second_plan.deinit();
    const changed_plan = try compile(std.testing.allocator, &changed.registry, &changed_documents, .{});
    defer changed_plan.deinit();

    try std.testing.expectEqual(compiler_abi_version, first_plan.compiler_abi);
    try std.testing.expectEqualSlices(u8, &first_plan.fingerprint, &second_plan.fingerprint);
    try std.testing.expect(!std.mem.eql(u8, &first_plan.fingerprint, &changed_plan.fingerprint));
    try std.testing.expect(!std.mem.allEqual(u8, &first_plan.fingerprint, 0));
}

test "equivalent generations share immutable payloads in either destruction order" {
    const input = "SecRule ARGS \"@contains attack\" id:1";
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "shared.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};

    const first = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    const second = try compileWithPrevious(std.testing.allocator, &parsed.registry, &documents, .{}, first);
    try std.testing.expectEqual(@as(usize, 2), first.sharedReferenceCount());
    try std.testing.expectEqual(first.rules.ptr, second.rules.ptr);
    first.deinit();
    try std.testing.expectEqual(@as(usize, 1), second.sharedReferenceCount());
    try std.testing.expectEqualStrings("contains", second.string(second.rules[0].operator.name).?);
    second.deinit();

    const third = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    const fourth = try compileWithPrevious(std.testing.allocator, &parsed.registry, &documents, .{}, third);
    fourth.deinit();
    try std.testing.expectEqual(@as(usize, 1), third.sharedReferenceCount());
    try std.testing.expectEqualStrings("contains", third.string(third.rules[0].operator.name).?);
    third.deinit();
}

test "shared payload survives concurrent reads while another generation retires" {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "threaded.conf", "SecRule ARGS \"@contains attack\" id:1", .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const retiring = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    const active = try compileWithPrevious(std.testing.allocator, &parsed.registry, &documents, .{}, retiring);
    defer active.deinit();

    var ready = std.atomic.Value(usize).init(0);
    var release = std.atomic.Value(bool).init(false);
    var failures = std.atomic.Value(usize).init(0);
    var workers: [4]PlanReadWorker = undefined;
    var threads: [workers.len]std.Thread = undefined;
    for (&workers, &threads) |*worker, *thread| {
        worker.* = .{ .plan = active, .ready = &ready, .release = &release, .failures = &failures };
        thread.* = try std.Thread.spawn(.{}, PlanReadWorker.run, .{worker});
    }
    while (ready.load(.acquire) != workers.len) std.atomic.spinLoopHint();
    retiring.deinit();
    try std.testing.expectEqual(@as(usize, 1), active.sharedReferenceCount());
    release.store(true, .release);
    for (&threads) |*thread| thread.join();
    try std.testing.expectEqual(@as(usize, 0), failures.load(.acquire));
}

test "component reuse requires exact equality after fingerprint screening" {
    var first_parsed = try seclang.parser.parseBytes(std.testing.allocator, "same.conf", "SecAction pass", .{}, .{});
    defer first_parsed.deinit();
    var changed_parsed = try seclang.parser.parseBytes(std.testing.allocator, "same.conf", "SecAction deny", .{}, .{});
    defer changed_parsed.deinit();
    var first_documents = [_]seclang.parser.Document{first_parsed.document};
    var changed_documents = [_]seclang.parser.Document{changed_parsed.document};
    const first = try compile(std.testing.allocator, &first_parsed.registry, &first_documents, .{});
    defer first.deinit();
    const changed = try compileWithPrevious(std.testing.allocator, &changed_parsed.registry, &changed_documents, .{}, first);
    defer changed.deinit();
    try std.testing.expectEqual(@as(usize, 1), first.sharedReferenceCount());
    try std.testing.expectEqual(@as(usize, 1), changed.sharedReferenceCount());
    try std.testing.expect(first.actions.ptr != changed.actions.ptr);
}

test "plan compilation cleans every injected allocation failure" {
    const input =
        \\SecDefaultAction "phase:2,pass,t:lowercase"
        \\SecRule ARGS|REQUEST_HEADERS:host "@contains attack" "id:1,msg:'%{REQUEST_URI}',deny,chain"
        \\SecRule TX:score "@pm one two" "capture,setvar:tx.hit=1"
        \\SecMarker END
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "allocation-plan.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};

    var baseline_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const baseline = try compile(baseline_allocator.allocator(), &parsed.registry, &documents, .{});
    baseline.deinit();
    const allocation_count = baseline_allocator.alloc_index;
    try std.testing.expectEqual(baseline_allocator.allocated_bytes, baseline_allocator.freed_bytes);

    for (0..allocation_count) |failure_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = failure_index });
        if (compile(failing.allocator(), &parsed.registry, &documents, .{})) |compiled| {
            // Arena growth may recover from a failed resize with a fresh
            // allocation; successful fallback must still release everything.
            compiled.deinit();
        } else |failure| try std.testing.expectEqual(error.OutOfMemory, failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

test "plans compile and deinitialize repeatedly without retained allocations" {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "repeat.conf", "SecRule ARGS \"@contains stable\" \"id:1,phase:2,deny\"", .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    for (0..250) |_| {
        const value = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
        value.deinit();
    }
}

test "macro-bearing values compile into immutable deduplicated token programs" {
    const input =
        \\SecRule ARGS "@contains %{TX.needle}" "id:1,msg:'uri=%{REQUEST_URI} user=%{TX.user}',logdata:'uri=%{REQUEST_URI} user=%{TX.user}'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "macros.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 2), compiled.macro_programs.len);
    try std.testing.expect(compiled.rules[0].operator.macro != null);
    try std.testing.expect(compiled.rules[0].operator.prefilter == null);
    try std.testing.expectEqual(compiled.actions[1].macro, compiled.actions[2].macro);
    const action_program = compiled.macro_programs[@backingInt(compiled.actions[1].macro.?)];
    try std.testing.expectEqual(@as(u32, 4), action_program.tokens_count);
    const tokens = compiled.macro_tokens[action_program.tokens_start..][0..action_program.tokens_count];
    try std.testing.expectEqual(MacroTokenKind.literal, tokens[0].kind);
    try std.testing.expectEqual(MacroTokenKind.scalar, tokens[1].kind);
    try std.testing.expectEqualStrings("REQUEST_URI", compiled.string(tokens[1].name.?).?);
    try std.testing.expectEqual(MacroTokenKind.collection, tokens[3].kind);
    try std.testing.expectEqualStrings("TX", compiled.string(tokens[3].name.?).?);
    try std.testing.expectEqualStrings("user", compiled.string(tokens[3].key.?).?);
}

test "malformed macros diagnose their containing operator or action" {
    const cases = [_]struct { input: []const u8, code: DiagnosticCode }{
        .{ .input = "SecRule ARGS \"@contains %{TX.value\" id:1", .code = .unterminated_macro },
        .{ .input = "SecAction \"msg:'%{}'\"", .code = .empty_macro_expression },
    };
    for (cases) |case| {
        var parsed = try seclang.parser.parseBytes(std.testing.allocator, "bad-macro.conf", case.input, .{}, .{});
        defer parsed.deinit();
        var documents = [_]seclang.parser.Document{parsed.document};
        var outcome = try compileOutcome(std.testing.allocator, &parsed.registry, &documents, .{});
        defer outcome.deinit();
        switch (outcome) {
            .plan => return error.TestExpectedDiagnostic,
            .diagnostic => |value| try std.testing.expectEqual(case.code, value.code),
        }
    }
}

test "macro program and token limits fail distinctly" {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "macro-limits.conf", "SecAction \"msg:'%{TX.one}',logdata:'%{TX.two}'\"", .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    try std.testing.expectError(error.TooManyMacroPrograms, compile(std.testing.allocator, &parsed.registry, &documents, .{ .max_macro_programs = 1 }));
    try std.testing.expectError(error.TooManyMacroTokens, compile(std.testing.allocator, &parsed.registry, &documents, .{ .max_macro_tokens = 1 }));
}

test "structural plan evidence is valid and pinned to compiler ABI" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, evidence_json, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings("WAF-11", object.get("issue").?.string);
    try std.testing.expectEqual(@as(i64, compiler_abi_version), object.get("compilerAbi").?.integer);
    try std.testing.expectEqual(@as(i64, 58), object.get("corpus").?.object.get("files").?.integer);
    try std.testing.expectEqual(@as(i64, 0), object.get("corpus").?.object.get("unexplainedExclusions").?.integer);
}
