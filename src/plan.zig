//! Immutable, compact structural execution plans compiled from SecLang syntax.

const std = @import("std");
const action_config = @import("action_config.zig");
const collections = @import("collections.zig");
const seclang = @import("seclang/root.zig");
const variables = @import("variables.zig");
const rule_config = @import("rule_config.zig");
const remote_rules = @import("remote_rules.zig");
const regex = @import("regex");

pub const StringId = enum(u32) { _ };
pub const DirectiveId = enum(u32) { _ };
pub const RuleId = enum(u32) { _ };
pub const DefaultId = enum(u32) { _ };
pub const MacroProgramId = enum(u32) { _ };
pub const MarkerId = enum(u32) { _ };
pub const compiler_abi_version: u32 = 6;
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
    max_rule_updates: usize = 500_000,
    max_id_intervals: usize = 1_000_000,
    max_flow_targets: usize = 500_000,
    max_target_expansion: usize = 4_000_000,
    max_action_expansion: usize = 8_000_000,
    max_metadata_tags: usize = 2_000_000,
    max_nondisruptive_effects: usize = 4_000_000,
    max_configuration_warnings: usize = 1_000_000,
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
            self.max_rule_updates == 0 or
            self.max_id_intervals == 0 or
            self.max_flow_targets == 0 or
            self.max_target_expansion == 0 or
            self.max_action_expansion == 0 or
            self.max_metadata_tags == 0 or
            self.max_nondisruptive_effects == 0 or
            self.max_configuration_warnings == 0 or
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
            self.max_rule_updates > std.math.maxInt(u32) or
            self.max_id_intervals > std.math.maxInt(u32) or
            self.max_flow_targets > std.math.maxInt(u32) or
            self.max_target_expansion > std.math.maxInt(u32) or
            self.max_action_expansion > std.math.maxInt(u32) or
            self.max_metadata_tags > std.math.maxInt(u32) or
            self.max_nondisruptive_effects > std.math.maxInt(u32) or
            self.max_configuration_warnings > std.math.maxInt(u32) or
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
    TooManyRuleUpdates,
    TooManyIdIntervals,
    TooManyFlowTargets,
    TargetExpansionLimitExceeded,
    ActionExpansionLimitExceeded,
    TooManyMetadataTags,
    TooManyNondisruptiveEffects,
    TooManyConfigurationWarnings,
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
    InvalidDefaultAction,
    DuplicateDefaultPhase,
    MissingDefaultDisruptiveAction,
    InvalidRuleSelector,
    PartialChainSelection,
    MissingStaticMarker,
    InvalidRuleTargetUpdate,
    InvalidRuleActionUpdate,
    InvalidRuleMetadata,
    InvalidNondisruptiveAction,
    InvalidDisruptiveAction,
    DanglingChain,
    ChainPhaseMismatch,
    InvalidTransformation,
    UnterminatedMacro,
    EmptyMacroExpression,
    InvalidSourceTree,
};

pub const DiagnosticCode = enum {
    invalid_rule_id,
    duplicate_rule_id,
    invalid_phase,
    invalid_default_action,
    duplicate_default_phase,
    missing_default_disruptive_action,
    invalid_rule_selector,
    partial_chain_selection,
    missing_static_marker,
    invalid_rule_target_update,
    invalid_rule_action_update,
    invalid_rule_metadata,
    invalid_nondisruptive_action,
    invalid_disruptive_action,
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
            .invalid_default_action => "WAF-PLAN-0109",
            .duplicate_default_phase => "WAF-PLAN-0110",
            .missing_default_disruptive_action => "WAF-PLAN-0111",
            .invalid_rule_selector => "WAF-PLAN-0112",
            .partial_chain_selection => "WAF-PLAN-0113",
            .missing_static_marker => "WAF-PLAN-0114",
            .invalid_rule_target_update => "WAF-PLAN-0115",
            .invalid_rule_action_update => "WAF-PLAN-0116",
            .invalid_rule_metadata => "WAF-PLAN-0117",
            .invalid_nondisruptive_action => "WAF-PLAN-0118",
            .invalid_disruptive_action => "WAF-PLAN-0119",
        };
    }

    pub fn message(self: DiagnosticCode) []const u8 {
        return switch (self) {
            .invalid_rule_id => "rule id must be an unsigned 64-bit integer",
            .duplicate_rule_id => "rule id is already defined",
            .invalid_phase => "phase must name or number one of the five SecLang phases",
            .invalid_default_action => "action is not permitted in SecDefaultAction",
            .duplicate_default_phase => "SecDefaultAction is already defined for this phase",
            .missing_default_disruptive_action => "SecDefaultAction must specify a disruptive action",
            .invalid_rule_selector => "rule ID selector must contain valid unsigned IDs or inclusive ranges",
            .partial_chain_selection => "rule update cannot select a non-head chain member",
            .missing_static_marker => "static skipAfter target has no following SecMarker",
            .invalid_rule_target_update => "rule target update contains invalid target syntax",
            .invalid_rule_action_update => "rule action update contains a forbidden or invalid action",
            .invalid_rule_metadata => "rule metadata value is missing, malformed, or outside its supported range",
            .invalid_nondisruptive_action => "non-disruptive action value is missing or malformed",
            .invalid_disruptive_action => "disruptive or flow action value is missing, malformed, or conflicting",
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

pub const ExecutionValidation = union(enum) {
    valid,
    diagnostic: Diagnostic,
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

pub const SkipAfterTarget = struct {
    rule: RuleId,
    action_index: u32,
    marker: ?MarkerId,
    resume_rule: ?RuleId,
    dynamic: bool,
};

pub const MarkerResolution = struct {
    marker: MarkerId,
    resume_rule: ?RuleId,
};

pub const MacroTokenKind = enum { literal, scalar, collection };

pub const MacroToken = struct {
    kind: MacroTokenKind,
    source_start: u32,
    source_length: u32,
    name: ?StringId = null,
    key: ?StringId = null,
    scalar: ?variables.Name = null,
    collection: ?collections.Name = null,
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

pub const MetadataText = struct {
    value: StringId,
    macro: ?MacroProgramId,
};

pub const RuleMetadata = struct {
    revision: ?MetadataText = null,
    message: ?MetadataText = null,
    log_data: ?MetadataText = null,
    severity: ?action_config.Severity = null,
    maturity: ?u4 = null,
    accuracy: ?u4 = null,
    version: ?MetadataText = null,
    tags_start: u32 = 0,
    tags_count: u32 = 0,
};

pub const EffectText = struct {
    value: StringId,
    macro: ?MacroProgramId,
};

pub const EffectKind = enum {
    capture,
    log,
    nolog,
    auditlog,
    noauditlog,
    setenv,
    setvar,
    initcol,
    expirevar,
    deprecatevar,
    setuid,
    setsid,
    setrsc,
};

/// Typed request-path descriptor. Field meanings are selected by `kind`:
/// setenv uses name/value; setvar uses collection/name/value/operation;
/// init/bind uses collection/value; expiry uses collection/name/value; and
/// deprecation additionally uses auxiliary for the period.
pub const NondisruptiveEffect = struct {
    action_index: u32,
    kind: EffectKind,
    collection: ?action_config.Collection = null,
    operation: ?action_config.SetVarOperation = null,
    name: ?EffectText = null,
    value: ?EffectText = null,
    auxiliary: ?EffectText = null,
};

pub const DisruptiveKind = enum {
    pass,
    allow,
    deny,
    drop,
    proxy,
    redirect,
};

/// Effective decision for a matching rule after its phase default and explicit
/// actions have been reconciled. `block` is compiled to the referenced phase
/// default and never requires action-list scanning on the request path.
pub const DisruptiveDecision = struct {
    kind: DisruptiveKind = .pass,
    status: u16 = 403,
    status_explicit: bool = false,
    allow_scope: action_config.AllowScope = .transaction,
    destination: ?EffectText = null,
    declared_block: bool = false,
};

pub const FlowDecision = struct {
    skip: u32 = 0,
    skip_after_action: ?u32 = null,
    skip_after_target: ?u32 = null,
    skip_after_value: ?EffectText = null,
    multi_match: bool = false,
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
    metadata: RuleMetadata,
    effects_start: u32,
    effects_count: u32,
    disruptive: DisruptiveDecision,
    flow: FlowDecision,
    removed_by: ?DirectiveId,
};

pub const RuleRemoval = struct {
    directive: DirectiveId,
    chain_head: RuleId,
};

pub const MissingRuleReferenceKind = enum { remove_by_id, update_target_by_id, update_action_by_id };

pub const MissingRuleReference = struct {
    directive: DirectiveId,
    kind: MissingRuleReferenceKind,
    interval: rule_config.IdInterval,
};

pub const RemoteSource = seclang.include.RemoteSource;
pub const RemoteWarning = seclang.include.RemoteWarning;

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
    skip_after_targets: []const SkipAfterTarget,
    generic_directives: []const DirectiveId,
    macro_programs: []const MacroProgram,
    macro_tokens: []const MacroToken,
    defaults: []const DefaultSnapshot,
    metadata_tags: []const MetadataText,
    nondisruptive_effects: []const NondisruptiveEffect,
    rule_removals: []const RuleRemoval,
    missing_rule_references: []const MissingRuleReference,
    remote_sources: []const RemoteSource,
    remote_warnings: []const RemoteWarning,
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
    skip_after_targets: []const SkipAfterTarget,
    generic_directives: []const DirectiveId,
    macro_programs: []const MacroProgram,
    macro_tokens: []const MacroToken,
    defaults: []const DefaultSnapshot,
    metadata_tags: []const MetadataText,
    nondisruptive_effects: []const NondisruptiveEffect,
    rule_removals: []const RuleRemoval,
    missing_rule_references: []const MissingRuleReference,
    remote_sources: []const RemoteSource,
    remote_warnings: []const RemoteWarning,
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

    /// Resolve a dynamic skipAfter value without allocation. Duplicate marker
    /// names select the first matching marker after the executing rule.
    pub fn resolveMarkerAfter(self: *const Plan, rule_id: RuleId, name: []const u8) ?MarkerResolution {
        const rule_index: usize = @backingInt(rule_id);
        if (rule_index >= self.rules.len) return null;
        const rule = self.rules[rule_index];
        for (self.markers, 0..) |marker, marker_index| {
            if (@backingInt(marker.directive) <= @backingInt(rule.directive)) continue;
            if (!std.mem.eql(u8, self.string(marker.name).?, name)) continue;
            var resume_rule: ?RuleId = null;
            for (self.phaseRules(rule.phase)) |candidate| {
                if (@backingInt(self.rules[@backingInt(candidate)].directive) > @backingInt(marker.directive)) {
                    resume_rule = candidate;
                    break;
                }
            }
            return .{ .marker = @fromBackingInt(@as(u32, @intCast(marker_index))), .resume_rule = resume_rule };
        }
        return null;
    }

    pub fn firstUnresolvedStaticMarker(self: *const Plan) ?SkipAfterTarget {
        for (self.skip_after_targets) |target| {
            if (!target.dynamic and target.marker == null) return target;
        }
        return null;
    }

    pub fn validateExecutionPlan(self: *const Plan) ExecutionValidation {
        if (self.firstUnresolvedStaticMarker()) |target| {
            const code: DiagnosticCode = .missing_static_marker;
            return .{ .diagnostic = .{
                .code = code,
                .primary = self.rules[@backingInt(target.rule)].source,
                .message = code.message(),
            } };
        }
        return .valid;
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

/// Compile an include/remote source tree in textual directive order. Child
/// sources are visited immediately after their owning include/remote
/// directive, rather than after the remainder of the parent document.
pub fn compileTree(
    allocator: std.mem.Allocator,
    tree: *const seclang.include.Tree,
    limits: Limits,
) CompileError!*Plan {
    try limits.validate();
    if (tree.documents.items.len > limits.max_documents) return error.TooManyDocuments;
    if (tree.registry.sources.items.len > limits.max_source_references) return error.TooManySourceReferences;
    var compiler = Compiler.init(allocator, limits, null);
    defer compiler.deinit();
    var visited: std.AutoHashMapUnmanaged(seclang.source.SourceId, void) = .empty;
    defer visited.deinit(allocator);
    var roots: usize = 0;
    for (tree.documents.items, 0..) |document, document_index| {
        try validateDocument(&tree.registry, &document);
        const record = tree.registry.get(document.source_id) orelse return error.InvalidSourceId;
        if (record.included_from != null) continue;
        roots += 1;
        try compileTreeDocument(&compiler, tree, document_index, &visited);
    }
    if (roots == 0 or visited.count() != tree.documents.items.len) return error.InvalidSourceTree;
    if (compiler.pending_chain) |pending|
        return compiler.fail(error.DanglingChain, compiler.rules.items[@backingInt(pending)].source, null);
    try compiler.remote_sources.appendSlice(allocator, tree.remote_sources.items);
    try compiler.remote_warnings.appendSlice(allocator, tree.remote_warnings.items);
    return compiler.finish(&tree.registry);
}

fn compileTreeDocument(
    compiler: *Compiler,
    tree: *const seclang.include.Tree,
    document_index: usize,
    visited: *std.AutoHashMapUnmanaged(seclang.source.SourceId, void),
) CompileError!void {
    const document = tree.documents.items[document_index];
    if (visited.contains(document.source_id)) return;
    try visited.put(compiler.allocator, document.source_id, {});
    for (document.directives.items) |directive| {
        try compiler.addDirective(directive);
        for (tree.documents.items, 0..) |child, child_index| {
            const record = tree.registry.get(child.source_id) orelse return error.InvalidSourceId;
            const origin = record.included_from orelse continue;
            if (origin.parent != document.source_id or !std.meta.eql(origin.directive, directive.physical)) continue;
            try compileTreeDocument(compiler, tree, child_index, visited);
        }
    }
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

const RuleRemovalSelector = enum { id, tag, message };

const RuleRemovalOperation = struct {
    directive: DirectiveId,
    source: seclang.source.Span,
    selector: RuleRemovalSelector,
    intervals_start: u32,
    intervals_count: u32,
    requests_start: u32,
    requests_count: u32,
    pattern: ?StringId,
};

const RuleTargetUpdate = struct {
    directive: DirectiveId,
    source: seclang.source.Span,
    selector: RuleRemovalSelector,
    intervals_start: u32,
    intervals_count: u32,
    requests_start: u32,
    requests_count: u32,
    pattern: ?StringId,
    targets_start: u32,
    targets_count: u32,
};

const RuleActionUpdate = struct {
    directive: DirectiveId,
    source: seclang.source.Span,
    intervals_start: u32,
    intervals_count: u32,
    requests_start: u32,
    requests_count: u32,
    actions_start: u32,
    actions_count: u32,
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
    skip_after_targets: std.ArrayList(SkipAfterTarget) = .empty,
    generic_directives: std.ArrayList(DirectiveId) = .empty,
    macro_programs: std.ArrayList(MacroProgram) = .empty,
    macro_tokens: std.ArrayList(MacroToken) = .empty,
    macro_program_by_source: std.AutoHashMapUnmanaged(StringId, MacroProgramId) = .empty,
    prefilter_count: usize = 0,
    prefilter_bytes: usize = 0,
    defaults: std.ArrayList(DefaultSnapshot) = .empty,
    metadata_tags: std.ArrayList(MetadataText) = .empty,
    nondisruptive_effects: std.ArrayList(NondisruptiveEffect) = .empty,
    id_intervals: std.ArrayList(rule_config.IdInterval) = .empty,
    id_requests: std.ArrayList(rule_config.IdInterval) = .empty,
    rule_removal_operations: std.ArrayList(RuleRemovalOperation) = .empty,
    rule_target_updates: std.ArrayList(RuleTargetUpdate) = .empty,
    rule_action_updates: std.ArrayList(RuleActionUpdate) = .empty,
    rule_removals: std.ArrayList(RuleRemoval) = .empty,
    missing_rule_references: std.ArrayList(MissingRuleReference) = .empty,
    remote_sources: std.ArrayList(RemoteSource) = .empty,
    remote_warnings: std.ArrayList(RemoteWarning) = .empty,
    target_expansion: usize = 0,
    action_expansion: usize = 0,
    phase_rules: [5]std.ArrayList(RuleId) = .{ .empty, .empty, .empty, .empty, .empty },
    rule_ids: std.AutoHashMapUnmanaged(u64, seclang.source.Span) = .empty,
    active_defaults: [5]?DefaultId = .{ null, null, null, null, null },
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
        self.skip_after_targets.deinit(self.allocator);
        self.generic_directives.deinit(self.allocator);
        self.macro_programs.deinit(self.allocator);
        self.macro_tokens.deinit(self.allocator);
        self.macro_program_by_source.deinit(self.allocator);
        self.defaults.deinit(self.allocator);
        self.metadata_tags.deinit(self.allocator);
        self.nondisruptive_effects.deinit(self.allocator);
        self.id_intervals.deinit(self.allocator);
        self.id_requests.deinit(self.allocator);
        self.rule_removal_operations.deinit(self.allocator);
        self.rule_target_updates.deinit(self.allocator);
        self.rule_action_updates.deinit(self.allocator);
        self.rule_removals.deinit(self.allocator);
        self.missing_rule_references.deinit(self.allocator);
        self.remote_sources.deinit(self.allocator);
        self.remote_warnings.deinit(self.allocator);
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
                const phase = self.validateDefaultActions(directive) catch |cause|
                    return self.fail(cause, actionSpan(directive), null);
                if (self.active_defaults[phase - 1]) |first_id| {
                    const first = self.defaults.items[@backingInt(first_id)];
                    return self.fail(error.DuplicateDefaultPhase, actionSpan(directive), first.source);
                }
                const default_id: DefaultId = @fromBackingInt(try typedIndex(self.defaults.items.len));
                try self.defaults.append(self.allocator, .{
                    .source = directive.physical,
                    .phase = phase,
                    .actions_start = action_range.start,
                    .actions_count = action_range.count,
                });
                self.active_defaults[phase - 1] = default_id;
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
                if (std.ascii.eqlIgnoreCase(directive.name, "SecRuleRemoveById")) {
                    try self.addIdRuleRemoval(directive_id, directive);
                } else if (std.ascii.eqlIgnoreCase(directive.name, "SecRuleRemoveByTag")) {
                    try self.addRegexRuleRemoval(directive_id, directive, .tag);
                } else if (std.ascii.eqlIgnoreCase(directive.name, "SecRuleRemoveByMsg")) {
                    try self.addRegexRuleRemoval(directive_id, directive, .message);
                } else if (std.ascii.eqlIgnoreCase(directive.name, "SecRuleUpdateTargetById")) {
                    try self.addRuleTargetUpdate(directive_id, directive, .id);
                } else if (std.ascii.eqlIgnoreCase(directive.name, "SecRuleUpdateTargetByTag")) {
                    try self.addRuleTargetUpdate(directive_id, directive, .tag);
                } else if (std.ascii.eqlIgnoreCase(directive.name, "SecRuleUpdateTargetByMsg")) {
                    try self.addRuleTargetUpdate(directive_id, directive, .message);
                } else if (std.ascii.eqlIgnoreCase(directive.name, "SecRuleUpdateActionById")) {
                    try self.addRuleActionUpdate(directive_id, directive);
                }
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

    fn addIdRuleRemoval(self: *Compiler, directive_id: DirectiveId, directive: seclang.parser.Directive) CompileError!void {
        if (self.rule_removal_operations.items.len == self.limits.max_rule_updates) return error.TooManyRuleUpdates;
        if (self.id_intervals.items.len == self.limits.max_id_intervals) return error.TooManyIdIntervals;
        var fragments: std.ArrayList([]const u8) = .empty;
        defer fragments.deinit(self.allocator);
        try fragments.ensureTotalCapacity(self.allocator, directive.arguments.len);
        for (directive.arguments) |argument| fragments.appendAssumeCapacity(argument.content());
        var selector_failure: ?rule_config.IdSelectorFailure = null;
        var selector = rule_config.IdSelector.parse(self.allocator, fragments.items, .{
            .max_fragments = self.limits.max_arguments,
            .max_input_bytes = self.limits.max_string_bytes,
            .max_intervals = self.limits.max_id_intervals -| self.id_intervals.items.len,
        }, &selector_failure) catch |cause| switch (cause) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TooManyIdIntervals => return error.TooManyIdIntervals,
            // The structural compiler intentionally preserves schema-invalid
            // generic directives so the directive validator can publish its
            // stable WAF-DIRECTIVE diagnostic before a Waf is built.
            else => return,
        };
        defer selector.deinit();
        if (selector.intervals.len > self.limits.max_id_intervals -| self.id_intervals.items.len)
            return error.TooManyIdIntervals;
        if (selector.requested.len > self.limits.max_id_intervals -| self.id_requests.items.len)
            return error.TooManyIdIntervals;
        const start = try typedIndex(self.id_intervals.items.len);
        const requests_start = try typedIndex(self.id_requests.items.len);
        try self.id_intervals.appendSlice(self.allocator, selector.intervals);
        try self.id_requests.appendSlice(self.allocator, selector.requested);
        try self.rule_removal_operations.append(self.allocator, .{
            .directive = directive_id,
            .source = directive.physical,
            .selector = .id,
            .intervals_start = start,
            .intervals_count = try typedIndex(selector.intervals.len),
            .requests_start = requests_start,
            .requests_count = try typedIndex(selector.requested.len),
            .pattern = null,
        });
    }

    fn addRegexRuleRemoval(
        self: *Compiler,
        directive_id: DirectiveId,
        directive: seclang.parser.Directive,
        selector: RuleRemovalSelector,
    ) CompileError!void {
        if (self.rule_removal_operations.items.len == self.limits.max_rule_updates) return error.TooManyRuleUpdates;
        // Preserve malformed arity for WAF-DIRECTIVE validation, as with ID
        // selectors. A valid remove-by-tag/message directive has one pattern.
        if (directive.arguments.len != 1) return;
        const pattern = directive.arguments[0].content();
        if (pattern.len == 0) return;
        try self.rule_removal_operations.append(self.allocator, .{
            .directive = directive_id,
            .source = directive.physical,
            .selector = selector,
            .intervals_start = 0,
            .intervals_count = 0,
            .requests_start = 0,
            .requests_count = 0,
            .pattern = try self.interner.intern(pattern),
        });
    }

    fn addRuleTargetUpdate(
        self: *Compiler,
        directive_id: DirectiveId,
        directive: seclang.parser.Directive,
        selector: RuleRemovalSelector,
    ) CompileError!void {
        if (self.rule_target_updates.items.len == self.limits.max_rule_updates) return error.TooManyRuleUpdates;
        if (directive.arguments.len != 2) return;
        const selector_value = directive.arguments[0].content();
        const target_value = directive.arguments[1].content();
        var intervals_start: u32 = 0;
        var intervals_count: u32 = 0;
        var requests_start: u32 = 0;
        var requests_count: u32 = 0;
        var pattern: ?StringId = null;
        if (selector == .id) {
            if (self.id_intervals.items.len == self.limits.max_id_intervals) return error.TooManyIdIntervals;
            var id_selector = rule_config.IdSelector.parse(self.allocator, &.{selector_value}, .{
                .max_fragments = 1,
                .max_input_bytes = self.limits.max_string_bytes,
                .max_intervals = self.limits.max_id_intervals - self.id_intervals.items.len,
            }, null) catch |cause| switch (cause) {
                error.OutOfMemory => return error.OutOfMemory,
                error.TooManyIdIntervals => return error.TooManyIdIntervals,
                else => return,
            };
            defer id_selector.deinit();
            intervals_start = try typedIndex(self.id_intervals.items.len);
            intervals_count = try typedIndex(id_selector.intervals.len);
            if (id_selector.requested.len > self.limits.max_id_intervals -| self.id_requests.items.len)
                return error.TooManyIdIntervals;
            requests_start = try typedIndex(self.id_requests.items.len);
            requests_count = try typedIndex(id_selector.requested.len);
            try self.id_intervals.appendSlice(self.allocator, id_selector.intervals);
            try self.id_requests.appendSlice(self.allocator, id_selector.requested);
        } else {
            if (selector_value.len == 0) return;
            pattern = try self.interner.intern(selector_value);
        }
        const remaining_targets = self.limits.max_targets -| self.targets.items.len;
        const parsed_targets = seclang.syntax.parseTargets(self.allocator, target_value, .{
            .max_targets = @max(@as(usize, 1), remaining_targets),
            .max_actions = 1,
        }) catch |cause| switch (cause) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TooManyTargets => return error.TooManyTargets,
            else => return self.fail(error.InvalidRuleTargetUpdate, directive.arguments[1].physical, null),
        };
        defer self.allocator.free(parsed_targets);
        if (parsed_targets.len > remaining_targets) return error.TooManyTargets;
        const targets_start = try typedIndex(self.targets.items.len);
        for (parsed_targets) |target| try self.targets.append(self.allocator, .{
            .raw = try self.interner.intern(target.raw),
            .modifier = target.modifier,
            .collection = try self.interner.intern(target.collection),
            .selector = if (target.selector) |value| try self.interner.intern(value) else null,
        });
        try self.rule_target_updates.append(self.allocator, .{
            .directive = directive_id,
            .source = directive.physical,
            .selector = selector,
            .intervals_start = intervals_start,
            .intervals_count = intervals_count,
            .requests_start = requests_start,
            .requests_count = requests_count,
            .pattern = pattern,
            .targets_start = targets_start,
            .targets_count = try typedIndex(parsed_targets.len),
        });
    }

    fn addRuleActionUpdate(self: *Compiler, directive_id: DirectiveId, directive: seclang.parser.Directive) CompileError!void {
        if (self.rule_action_updates.items.len == self.limits.max_rule_updates) return error.TooManyRuleUpdates;
        if (directive.arguments.len != 2) return;
        if (self.id_intervals.items.len == self.limits.max_id_intervals) return error.TooManyIdIntervals;
        var id_selector = rule_config.IdSelector.parse(self.allocator, &.{directive.arguments[0].content()}, .{
            .max_fragments = 1,
            .max_input_bytes = self.limits.max_string_bytes,
            .max_intervals = self.limits.max_id_intervals - self.id_intervals.items.len,
        }, null) catch |cause| switch (cause) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TooManyIdIntervals => return error.TooManyIdIntervals,
            else => return,
        };
        defer id_selector.deinit();
        const parsed_actions = seclang.syntax.parseActions(self.allocator, directive.arguments[1].content(), .{
            .max_targets = 1,
            .max_actions = @max(@as(usize, 1), self.limits.max_actions -| self.actions.items.len),
        }) catch |cause| switch (cause) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TooManyActions => return error.TooManyActions,
            else => return self.fail(error.InvalidRuleActionUpdate, directive.arguments[1].physical, null),
        };
        defer self.allocator.free(parsed_actions);
        for (parsed_actions) |action| {
            if (equalsAny(action.name, &.{ "id", "phase", "chain" }))
                return self.fail(error.InvalidRuleActionUpdate, directive.arguments[1].physical, null);
        }
        const intervals_start = try typedIndex(self.id_intervals.items.len);
        if (id_selector.requested.len > self.limits.max_id_intervals -| self.id_requests.items.len)
            return error.TooManyIdIntervals;
        const requests_start = try typedIndex(self.id_requests.items.len);
        try self.id_intervals.appendSlice(self.allocator, id_selector.intervals);
        try self.id_requests.appendSlice(self.allocator, id_selector.requested);
        const action_range = self.addActions(parsed_actions) catch |cause|
            return self.fail(cause, directive.arguments[1].physical, null);
        try self.rule_action_updates.append(self.allocator, .{
            .directive = directive_id,
            .source = directive.physical,
            .intervals_start = intervals_start,
            .intervals_count = try typedIndex(id_selector.intervals.len),
            .requests_start = requests_start,
            .requests_count = try typedIndex(id_selector.requested.len),
            .actions_start = action_range.start,
            .actions_count = action_range.count,
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
        const default_id = self.active_defaults[phase - 1];
        const transformation_range = self.addTransformations(default_id, action_range) catch |cause|
            return self.fail(cause, actionSpan(directive), null);
        const prefilter = try self.addPrefilter(parsed_operator);
        const operator_macro = self.addMacro(unquote(parsed_operator.parameter)) catch |cause|
            return self.fail(cause, directive.operator().?.physical, null);
        try self.rules.append(self.allocator, .{
            .directive = directive_id,
            .source = directive.physical,
            .external_id = external_id,
            .phase = phase,
            .default = default_id,
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
            .metadata = .{},
            .effects_start = 0,
            .effects_count = 0,
            .disruptive = .{},
            .flow = .{},
            .removed_by = null,
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

    fn validateDefaultActions(self: *Compiler, directive: seclang.parser.Directive) CompileError!u8 {
        _ = self;
        var phase: ?u8 = null;
        var has_disruptive = false;
        for (directive.parsed_actions) |action| {
            if (std.ascii.eqlIgnoreCase(action.name, "phase")) {
                if (phase != null) return error.InvalidDefaultAction;
                phase = (explicitPhase(&.{action}) catch return error.InvalidPhase) orelse return error.InvalidPhase;
                continue;
            }
            if (std.ascii.eqlIgnoreCase(action.name, "t") and action.value != null and
                std.ascii.eqlIgnoreCase(unquote(action.value.?), "none"))
            {
                return error.InvalidDefaultAction;
            }
            const class = classifyAction(action.name);
            if (class == .metadata or class == .flow) return error.InvalidDefaultAction;
            if (equalsAny(action.name, &.{ "allow", "deny", "drop", "pass", "proxy", "redirect" }))
                has_disruptive = true;
        }
        if (!has_disruptive) return error.MissingDefaultDisruptiveAction;
        return phase orelse error.InvalidPhase;
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
                    .collection = collections.Name.parse(expression[0..dot]),
                });
            } else {
                const scalar = variables.Name.parse(expression);
                const collection = collections.Name.parse(expression);
                try self.appendMacroToken(if (collection != null and scalar == null) .{
                    .kind = .collection,
                    .source_start = try typedIndex(marker),
                    .source_length = try typedIndex(close + 1 - marker),
                    .name = try self.interner.intern(expression),
                    .collection = collection,
                } else .{
                    .kind = .scalar,
                    .source_start = try typedIndex(marker),
                    .source_length = try typedIndex(close + 1 - marker),
                    .name = try self.interner.intern(expression),
                    .scalar = scalar,
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

    fn applyRuleRemovals(self: *Compiler) CompileError!void {
        for (self.rule_removal_operations.items) |removal| {
            const intervals = self.id_intervals.items[removal.intervals_start..][0..removal.intervals_count];
            var compiled_pattern: ?regex.Regex = if (removal.pattern) |pattern|
                regex.Regex.compile(self.allocator, self.interner.values.items[@backingInt(pattern)]) catch
                    return self.fail(error.InvalidRuleSelector, removal.source, null)
            else
                null;
            defer if (compiled_pattern) |*value| value.deinit();
            var matcher = if (compiled_pattern) |*value| value.matcher() else null;
            defer if (matcher) |*value| value.deinit();
            for (self.rules.items, 0..) |rule, rule_index| {
                const selected = switch (removal.selector) {
                    .id => if (rule.external_id) |external_id| matchesIntervals(intervals, external_id) else false,
                    .tag => self.ruleActionMatches(rule, "tag", &matcher.?) catch
                        return self.fail(error.InvalidRuleSelector, removal.source, null),
                    .message => self.ruleActionMatches(rule, "msg", &matcher.?) catch
                        return self.fail(error.InvalidRuleSelector, removal.source, null),
                };
                if (!selected) continue;
                if (rule.chain_position != 0)
                    return self.fail(error.PartialChainSelection, removal.source, rule.source);
                const head: RuleId = @fromBackingInt(@as(u32, @intCast(rule_index)));
                if (self.rules.items[rule_index].removed_by != null) continue;
                if (self.rule_removals.items.len == self.limits.max_rule_updates) return error.TooManyRuleUpdates;
                try self.rule_removals.append(self.allocator, .{ .directive = removal.directive, .chain_head = head });
                var member: ?RuleId = head;
                while (member) |id| {
                    const selected_rule = &self.rules.items[@backingInt(id)];
                    selected_rule.removed_by = removal.directive;
                    member = selected_rule.chain_next;
                }
            }
            if (removal.selector == .id) try self.recordMissingRuleReferences(
                self.id_requests.items[removal.requests_start..][0..removal.requests_count],
                removal.directive,
                .remove_by_id,
            );
        }
        for (&self.phase_rules) |*phase| {
            var write: usize = 0;
            for (phase.items) |rule_id| {
                if (self.rules.items[@backingInt(rule_id)].removed_by != null) continue;
                phase.items[write] = rule_id;
                write += 1;
            }
            phase.shrinkRetainingCapacity(write);
        }
    }

    fn applyRuleTargetUpdates(self: *Compiler) CompileError!void {
        for (self.rule_target_updates.items) |update| {
            const intervals = self.id_intervals.items[update.intervals_start..][0..update.intervals_count];
            var compiled_pattern: ?regex.Regex = if (update.pattern) |pattern|
                regex.Regex.compile(self.allocator, self.interner.values.items[@backingInt(pattern)]) catch
                    return self.fail(error.InvalidRuleSelector, update.source, null)
            else
                null;
            defer if (compiled_pattern) |*value| value.deinit();
            var matcher = if (compiled_pattern) |*value| value.matcher() else null;
            defer if (matcher) |*value| value.deinit();
            for (0..self.rules.items.len) |rule_index| {
                const rule = self.rules.items[rule_index];
                const selected = switch (update.selector) {
                    .id => if (rule.external_id) |external_id| matchesIntervals(intervals, external_id) else false,
                    .tag => self.ruleActionMatches(rule, "tag", &matcher.?) catch
                        return self.fail(error.InvalidRuleSelector, update.source, null),
                    .message => self.ruleActionMatches(rule, "msg", &matcher.?) catch
                        return self.fail(error.InvalidRuleSelector, update.source, null),
                };
                if (!selected) continue;
                if (rule.chain_position != 0)
                    return self.fail(error.PartialChainSelection, update.source, rule.source);
                const expansion = @as(usize, rule.targets_count) + @as(usize, update.targets_count);
                if (expansion > self.limits.max_target_expansion -| self.target_expansion)
                    return error.TargetExpansionLimitExceeded;
                if (expansion > self.limits.max_targets -| self.targets.items.len) return error.TooManyTargets;
                try self.targets.ensureUnusedCapacity(self.allocator, expansion);
                const targets_start = try typedIndex(self.targets.items.len);
                for (0..rule.targets_count) |offset|
                    self.targets.appendAssumeCapacity(self.targets.items[rule.targets_start + offset]);
                for (0..update.targets_count) |offset|
                    self.targets.appendAssumeCapacity(self.targets.items[update.targets_start + offset]);
                self.rules.items[rule_index].targets_start = targets_start;
                self.rules.items[rule_index].targets_count = try typedIndex(expansion);
                self.target_expansion += expansion;
            }
            if (update.selector == .id) try self.recordMissingRuleReferences(
                self.id_requests.items[update.requests_start..][0..update.requests_count],
                update.directive,
                .update_target_by_id,
            );
        }
    }

    fn applyRuleActionUpdates(self: *Compiler) CompileError!void {
        var effective: std.ArrayList(Action) = .empty;
        defer effective.deinit(self.allocator);
        for (self.rule_action_updates.items) |update| {
            const intervals = self.id_intervals.items[update.intervals_start..][0..update.intervals_count];
            for (0..self.rules.items.len) |rule_index| {
                const rule = self.rules.items[rule_index];
                const external_id = rule.external_id orelse continue;
                if (!matchesIntervals(intervals, external_id)) continue;
                if (rule.chain_position != 0)
                    return self.fail(error.PartialChainSelection, update.source, rule.source);
                effective.clearRetainingCapacity();
                try effective.appendSlice(self.allocator, self.actions.items[rule.actions_start..][0..rule.actions_count]);
                const updates = self.actions.items[update.actions_start..][0..update.actions_count];
                for (updates) |replacement| {
                    const replacement_name = self.interner.values.items[@backingInt(replacement.name)];
                    if (!isRepeatableAction(replacement_name)) {
                        var write: usize = 0;
                        for (effective.items) |existing| {
                            if (sameActionFamily(self, existing, replacement)) continue;
                            effective.items[write] = existing;
                            write += 1;
                        }
                        effective.shrinkRetainingCapacity(write);
                    }
                    try effective.append(self.allocator, replacement);
                }
                if (effective.items.len > self.limits.max_action_expansion -| self.action_expansion)
                    return error.ActionExpansionLimitExceeded;
                if (effective.items.len > self.limits.max_actions -| self.actions.items.len) return error.TooManyActions;
                const actions_start = try typedIndex(self.actions.items.len);
                try self.actions.appendSlice(self.allocator, effective.items);
                const action_range: ActionRange = .{ .start = actions_start, .count = try typedIndex(effective.items.len) };
                self.rules.items[rule_index].actions_start = action_range.start;
                self.rules.items[rule_index].actions_count = action_range.count;
                const transformations = self.addTransformations(rule.default, action_range) catch |cause|
                    return self.fail(cause, update.source, null);
                self.rules.items[rule_index].transformations_start = transformations.start;
                self.rules.items[rule_index].transformations_count = transformations.count;
                self.action_expansion += effective.items.len;
            }
            try self.recordMissingRuleReferences(
                self.id_requests.items[update.requests_start..][0..update.requests_count],
                update.directive,
                .update_action_by_id,
            );
        }
    }

    fn recordMissingRuleReferences(
        self: *Compiler,
        requested: []const rule_config.IdInterval,
        directive: DirectiveId,
        kind: MissingRuleReferenceKind,
    ) CompileError!void {
        for (requested) |interval| {
            var found = false;
            for (self.rules.items) |rule| {
                if (rule.external_id) |external_id| if (interval.contains(external_id)) {
                    found = true;
                    break;
                };
            }
            if (found) continue;
            if (self.missing_rule_references.items.len == self.limits.max_configuration_warnings)
                return error.TooManyConfigurationWarnings;
            try self.missing_rule_references.append(self.allocator, .{
                .directive = directive,
                .kind = kind,
                .interval = interval,
            });
        }
    }

    fn ruleActionMatches(
        self: *Compiler,
        rule: Rule,
        action_name: []const u8,
        matcher: *regex.Regex.Matcher,
    ) CompileError!bool {
        const actions = self.actions.items[rule.actions_start..][0..rule.actions_count];
        for (actions) |action| {
            if (!std.ascii.eqlIgnoreCase(self.interner.values.items[@backingInt(action.name)], action_name)) continue;
            const value = action.value orelse continue;
            if (matcher.isMatch(unquote(self.interner.values.items[@backingInt(value)])) catch
                return error.InvalidRuleSelector)
            {
                return true;
            }
        }
        return false;
    }

    fn resolveSkipAfterTargets(self: *Compiler) CompileError!void {
        for (self.rules.items, 0..) |rule, rule_index| {
            const actions = self.actions.items[rule.actions_start..][0..rule.actions_count];
            for (actions, 0..) |action, action_offset| {
                if (!std.ascii.eqlIgnoreCase(self.interner.values.items[@backingInt(action.name)], "skipAfter")) continue;
                if (self.skip_after_targets.items.len == self.limits.max_flow_targets) return error.TooManyFlowTargets;
                const value_id = action.value orelse return self.fail(error.MissingStaticMarker, rule.source, null);
                const value = unquote(self.interner.values.items[@backingInt(value_id)]);
                const dynamic = std.mem.indexOf(u8, value, "%{") != null;
                var marker_id: ?MarkerId = null;
                var resume_rule: ?RuleId = null;
                if (!dynamic) {
                    for (self.markers.items, 0..) |marker, marker_index| {
                        if (@backingInt(marker.directive) <= @backingInt(rule.directive)) continue;
                        if (!std.mem.eql(u8, self.interner.values.items[@backingInt(marker.name)], value)) continue;
                        marker_id = @fromBackingInt(@as(u32, @intCast(marker_index)));
                        for (self.phase_rules[rule.phase - 1].items) |candidate| {
                            if (@backingInt(self.rules.items[@backingInt(candidate)].directive) > @backingInt(marker.directive)) {
                                resume_rule = candidate;
                                break;
                            }
                        }
                        break;
                    }
                }
                try self.skip_after_targets.append(self.allocator, .{
                    .rule = @fromBackingInt(@as(u32, @intCast(rule_index))),
                    .action_index = rule.actions_start + @as(u32, @intCast(action_offset)),
                    .marker = marker_id,
                    .resume_rule = resume_rule,
                    .dynamic = dynamic,
                });
                self.rules.items[rule_index].flow.skip_after_target =
                    @intCast(self.skip_after_targets.items.len - 1);
            }
        }
    }

    fn compileRuleMetadata(self: *Compiler) CompileError!void {
        for (0..self.rules.items.len) |rule_index| {
            const rule = self.rules.items[rule_index];
            var metadata: RuleMetadata = .{ .tags_start = try typedIndex(self.metadata_tags.items.len) };
            const actions = self.actions.items[rule.actions_start..][0..rule.actions_count];
            for (actions) |action| {
                const name = self.interner.values.items[@backingInt(action.name)];
                if (std.ascii.eqlIgnoreCase(name, "id")) continue;
                if (std.ascii.eqlIgnoreCase(name, "tag")) {
                    const text = self.metadataText(action) catch |cause|
                        return self.fail(cause, rule.source, null);
                    if (self.metadata_tags.items.len == self.limits.max_metadata_tags)
                        return error.TooManyMetadataTags;
                    try self.metadata_tags.append(self.allocator, text);
                    continue;
                }
                if (std.ascii.eqlIgnoreCase(name, "rev")) {
                    metadata.revision = self.metadataText(action) catch |cause|
                        return self.fail(cause, rule.source, null);
                    continue;
                }
                if (std.ascii.eqlIgnoreCase(name, "msg")) {
                    metadata.message = self.metadataText(action) catch |cause|
                        return self.fail(cause, rule.source, null);
                    continue;
                }
                if (std.ascii.eqlIgnoreCase(name, "logdata")) {
                    metadata.log_data = self.metadataText(action) catch |cause|
                        return self.fail(cause, rule.source, null);
                    continue;
                }
                if (std.ascii.eqlIgnoreCase(name, "ver") or std.ascii.eqlIgnoreCase(name, "version")) {
                    metadata.version = self.metadataText(action) catch |cause|
                        return self.fail(cause, rule.source, null);
                    continue;
                }
                if (std.ascii.eqlIgnoreCase(name, "severity")) {
                    const value = self.actionValue(action) catch |cause|
                        return self.fail(cause, rule.source, null);
                    metadata.severity = action_config.parseSeverity(value) catch
                        return self.fail(error.InvalidRuleMetadata, rule.source, null);
                    continue;
                }
                if (std.ascii.eqlIgnoreCase(name, "maturity")) {
                    const value = self.actionValue(action) catch |cause|
                        return self.fail(cause, rule.source, null);
                    metadata.maturity = action_config.parseQuality(value) catch
                        return self.fail(error.InvalidRuleMetadata, rule.source, null);
                    continue;
                }
                if (std.ascii.eqlIgnoreCase(name, "accuracy")) {
                    const value = self.actionValue(action) catch |cause|
                        return self.fail(cause, rule.source, null);
                    metadata.accuracy = action_config.parseQuality(value) catch
                        return self.fail(error.InvalidRuleMetadata, rule.source, null);
                }
            }
            metadata.tags_count = try typedIndex(self.metadata_tags.items.len - metadata.tags_start);
            self.rules.items[rule_index].metadata = metadata;
        }
    }

    fn actionValue(self: *Compiler, action: Action) CompileError![]const u8 {
        const raw = action.value orelse return error.InvalidRuleMetadata;
        const value = unquote(self.interner.values.items[@backingInt(raw)]);
        if (value.len == 0) return error.InvalidRuleMetadata;
        return value;
    }

    fn metadataText(self: *Compiler, action: Action) CompileError!MetadataText {
        const value = try self.actionValue(action);
        return .{ .value = try self.interner.intern(value), .macro = action.macro };
    }

    fn compileNondisruptiveEffects(self: *Compiler) CompileError!void {
        for (0..self.rules.items.len) |rule_index| {
            const rule = self.rules.items[rule_index];
            const start = try typedIndex(self.nondisruptive_effects.items.len);
            if (rule.default) |default_id| {
                const snapshot = self.defaults.items[@backingInt(default_id)];
                try self.compileEffectRange(rule, snapshot.actions_start, snapshot.actions_count);
            }
            try self.compileEffectRange(rule, rule.actions_start, rule.actions_count);
            self.rules.items[rule_index].effects_start = start;
            self.rules.items[rule_index].effects_count = try typedIndex(self.nondisruptive_effects.items.len - start);
        }
    }

    fn compileDisruptiveAndFlow(self: *Compiler) CompileError!void {
        for (0..self.rules.items.len) |rule_index| {
            const rule = self.rules.items[rule_index];
            var disruptive: DisruptiveDecision = .{};
            if (rule.default) |default_id| {
                const snapshot = self.defaults.items[@backingInt(default_id)];
                try self.compileDecisionRange(rule, snapshot.actions_start, snapshot.actions_count, &disruptive, null);
            }
            const phase_default = disruptive;
            var flow: FlowDecision = .{};
            try self.compileDecisionRange(rule, rule.actions_start, rule.actions_count, &disruptive, &flow);
            if (disruptive.declared_block) {
                const explicit_status = disruptive.status;
                const explicit_status_set = disruptive.status_explicit;
                disruptive = phase_default;
                disruptive.declared_block = true;
                if (explicit_status_set) {
                    disruptive.status = explicit_status;
                    disruptive.status_explicit = true;
                }
            }
            self.rules.items[rule_index].disruptive = disruptive;
            self.rules.items[rule_index].flow = flow;
        }
    }

    fn compileDecisionRange(
        self: *Compiler,
        rule: Rule,
        start: u32,
        count: u32,
        disruptive: *DisruptiveDecision,
        flow: ?*FlowDecision,
    ) CompileError!void {
        var disruptive_seen: ?Action = null;
        for (self.actions.items[start..][0..count], 0..) |action, offset| {
            const name = self.interner.values.items[@backingInt(action.name)];
            const action_index = std.math.add(u32, start, @as(u32, @intCast(offset))) catch return error.TypedIdOverflow;
            if (std.ascii.eqlIgnoreCase(name, "status")) {
                const value = self.actionValue(action) catch
                    return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                disruptive.status = action_config.parseStatus(value) catch
                    return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                disruptive.status_explicit = true;
                continue;
            }
            if (equalsAny(name, &.{ "allow", "block", "deny", "drop", "pass", "proxy", "redirect" })) {
                if (disruptive_seen) |existing| {
                    if (!self.sameDisruptiveAction(existing, action))
                        return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                    continue;
                }
                disruptive_seen = action;
                disruptive.destination = null;
                disruptive.declared_block = false;
                if (std.ascii.eqlIgnoreCase(name, "allow")) {
                    const value = if (action.value) |id| unquote(self.interner.values.items[@backingInt(id)]) else null;
                    disruptive.kind = .allow;
                    disruptive.allow_scope = action_config.parseAllowScope(value) catch
                        return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                } else if (std.ascii.eqlIgnoreCase(name, "block")) {
                    if (action.value != null or flow == null)
                        return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                    disruptive.declared_block = true;
                } else if (std.ascii.eqlIgnoreCase(name, "deny")) {
                    if (action.value != null) return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                    disruptive.kind = .deny;
                } else if (std.ascii.eqlIgnoreCase(name, "drop")) {
                    if (action.value != null) return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                    disruptive.kind = .drop;
                } else if (std.ascii.eqlIgnoreCase(name, "pass")) {
                    if (action.value != null) return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                    disruptive.kind = .pass;
                } else {
                    const destination = self.actionValue(action) catch
                        return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                    disruptive.kind = if (std.ascii.eqlIgnoreCase(name, "proxy")) .proxy else .redirect;
                    disruptive.destination = .{
                        .value = try self.interner.intern(destination),
                        .macro = action.macro,
                    };
                }
                continue;
            }
            const mutable_flow = flow orelse continue;
            if (std.ascii.eqlIgnoreCase(name, "skip")) {
                const value = self.actionValue(action) catch
                    return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                if (mutable_flow.skip != 0)
                    return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                mutable_flow.skip = action_config.parseSkip(value) catch
                    return self.fail(error.InvalidDisruptiveAction, rule.source, null);
            } else if (std.ascii.eqlIgnoreCase(name, "skipAfter")) {
                if (mutable_flow.skip_after_action != null or action.value == null)
                    return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                mutable_flow.skip_after_action = action_index;
                mutable_flow.skip_after_value = .{
                    .value = try self.interner.intern(self.actionValue(action) catch
                        return self.fail(error.InvalidDisruptiveAction, rule.source, null)),
                    .macro = action.macro,
                };
            } else if (std.ascii.eqlIgnoreCase(name, "multiMatch")) {
                if (mutable_flow.multi_match or action.value != null)
                    return self.fail(error.InvalidDisruptiveAction, rule.source, null);
                mutable_flow.multi_match = true;
            }
        }
    }

    fn sameDisruptiveAction(self: *const Compiler, first: Action, second: Action) bool {
        const first_name = self.interner.values.items[@backingInt(first.name)];
        const second_name = self.interner.values.items[@backingInt(second.name)];
        if (!std.ascii.eqlIgnoreCase(first_name, second_name)) return false;
        if (first.value == null or second.value == null) return first.value == null and second.value == null;
        return std.mem.eql(
            u8,
            unquote(self.interner.values.items[@backingInt(first.value.?)]),
            unquote(self.interner.values.items[@backingInt(second.value.?)]),
        );
    }

    fn compileEffectRange(self: *Compiler, rule: Rule, start: u32, count: u32) CompileError!void {
        for (self.actions.items[start..][0..count], 0..) |action, offset| {
            const name = self.interner.values.items[@backingInt(action.name)];
            const action_index = std.math.add(u32, start, @as(u32, @intCast(offset))) catch return error.TypedIdOverflow;
            if (std.ascii.eqlIgnoreCase(name, "capture")) {
                try self.appendFlagEffect(rule, action, action_index, .capture);
            } else if (std.ascii.eqlIgnoreCase(name, "log")) {
                try self.appendFlagEffect(rule, action, action_index, .log);
            } else if (std.ascii.eqlIgnoreCase(name, "nolog")) {
                try self.appendFlagEffect(rule, action, action_index, .nolog);
            } else if (std.ascii.eqlIgnoreCase(name, "auditlog")) {
                try self.appendFlagEffect(rule, action, action_index, .auditlog);
            } else if (std.ascii.eqlIgnoreCase(name, "noauditlog")) {
                try self.appendFlagEffect(rule, action, action_index, .noauditlog);
            } else if (std.ascii.eqlIgnoreCase(name, "setenv")) {
                const raw = self.actionValue(action) catch return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                const assignment = action_config.parseAssignment(raw) catch
                    return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                if (assignment.value.len == 0) return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                try self.appendEffect(.{
                    .action_index = action_index,
                    .kind = .setenv,
                    .name = try self.effectText(assignment.name),
                    .value = try self.effectText(assignment.value),
                });
            } else if (std.ascii.eqlIgnoreCase(name, "setvar")) {
                const raw = self.actionValue(action) catch return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                const parsed = action_config.parseSetVar(raw) catch
                    return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                try self.appendEffect(.{
                    .action_index = action_index,
                    .kind = .setvar,
                    .collection = parsed.collection,
                    .operation = parsed.operation,
                    .name = try self.effectText(parsed.key),
                    .value = if (parsed.operand) |operand| try self.effectText(operand) else null,
                });
            } else if (std.ascii.eqlIgnoreCase(name, "initcol")) {
                const raw = self.actionValue(action) catch return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                const parsed = action_config.parseInitCollection(raw) catch
                    return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                try self.appendEffect(.{
                    .action_index = action_index,
                    .kind = .initcol,
                    .collection = parsed.collection,
                    .value = try self.effectText(parsed.key),
                });
            } else if (std.ascii.eqlIgnoreCase(name, "expirevar")) {
                const raw = self.actionValue(action) catch return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                const parsed = action_config.parseExpiration(raw) catch
                    return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                if (std.mem.indexOf(u8, parsed.seconds, "%{") == null)
                    _ = action_config.parsePositiveU32(parsed.seconds) catch
                        return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                try self.appendEffect(.{
                    .action_index = action_index,
                    .kind = .expirevar,
                    .collection = parsed.collection,
                    .name = try self.effectText(parsed.key),
                    .value = try self.effectText(parsed.seconds),
                });
            } else if (std.ascii.eqlIgnoreCase(name, "deprecatevar")) {
                const raw = self.actionValue(action) catch return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                const parsed = action_config.parseDeprecation(raw) catch
                    return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                if (std.mem.indexOf(u8, parsed.amount, "%{") == null)
                    _ = action_config.parsePositiveU32(parsed.amount) catch
                        return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                if (std.mem.indexOf(u8, parsed.period_seconds, "%{") == null)
                    _ = action_config.parsePositiveU32(parsed.period_seconds) catch
                        return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
                try self.appendEffect(.{
                    .action_index = action_index,
                    .kind = .deprecatevar,
                    .collection = parsed.collection,
                    .name = try self.effectText(parsed.key),
                    .value = try self.effectText(parsed.amount),
                    .auxiliary = try self.effectText(parsed.period_seconds),
                });
            } else if (std.ascii.eqlIgnoreCase(name, "setuid")) {
                try self.appendBindingEffect(rule, action, action_index, .setuid, .user);
            } else if (std.ascii.eqlIgnoreCase(name, "setsid")) {
                try self.appendBindingEffect(rule, action, action_index, .setsid, .session);
            } else if (std.ascii.eqlIgnoreCase(name, "setrsc")) {
                try self.appendBindingEffect(rule, action, action_index, .setrsc, .resource);
            }
        }
    }

    fn appendFlagEffect(self: *Compiler, rule: Rule, action: Action, action_index: u32, kind: EffectKind) CompileError!void {
        if (action.value != null) return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
        try self.appendEffect(.{ .action_index = action_index, .kind = kind });
    }

    fn appendBindingEffect(
        self: *Compiler,
        rule: Rule,
        action: Action,
        action_index: u32,
        kind: EffectKind,
        collection: action_config.Collection,
    ) CompileError!void {
        const raw = self.actionValue(action) catch return self.fail(error.InvalidNondisruptiveAction, rule.source, null);
        try self.appendEffect(.{
            .action_index = action_index,
            .kind = kind,
            .collection = collection,
            .value = try self.effectText(raw),
        });
    }

    fn effectText(self: *Compiler, value: []const u8) CompileError!EffectText {
        return .{ .value = try self.interner.intern(value), .macro = try self.addMacro(value) };
    }

    fn appendEffect(self: *Compiler, effect: NondisruptiveEffect) CompileError!void {
        if (self.nondisruptive_effects.items.len == self.limits.max_nondisruptive_effects)
            return error.TooManyNondisruptiveEffects;
        try self.nondisruptive_effects.append(self.allocator, effect);
    }

    fn finish(self: *Compiler, registry: *const seclang.source.Registry) CompileError!*Plan {
        try self.applyRuleRemovals();
        try self.applyRuleTargetUpdates();
        try self.applyRuleActionUpdates();
        try self.compileRuleMetadata();
        try self.compileNondisruptiveEffects();
        try self.compileDisruptiveAndFlow();
        try self.resolveSkipAfterTargets();
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
        const skip_after_targets = try duplicateCounted(SkipAfterTarget, arena_allocator, self.skip_after_targets.items, &owned_bytes, self.limits);
        const generic_directives = try duplicateCounted(DirectiveId, arena_allocator, self.generic_directives.items, &owned_bytes, self.limits);
        const macro_programs = try duplicateCounted(MacroProgram, arena_allocator, self.macro_programs.items, &owned_bytes, self.limits);
        const macro_tokens = try duplicateCounted(MacroToken, arena_allocator, self.macro_tokens.items, &owned_bytes, self.limits);
        const defaults = try duplicateCounted(DefaultSnapshot, arena_allocator, self.defaults.items, &owned_bytes, self.limits);
        const metadata_tags = try duplicateCounted(MetadataText, arena_allocator, self.metadata_tags.items, &owned_bytes, self.limits);
        const nondisruptive_effects = try duplicateCounted(NondisruptiveEffect, arena_allocator, self.nondisruptive_effects.items, &owned_bytes, self.limits);
        const rule_removals = try duplicateCounted(RuleRemoval, arena_allocator, self.rule_removals.items, &owned_bytes, self.limits);
        const missing_rule_references = try duplicateCounted(MissingRuleReference, arena_allocator, self.missing_rule_references.items, &owned_bytes, self.limits);
        const remote_sources = try duplicateCounted(RemoteSource, arena_allocator, self.remote_sources.items, &owned_bytes, self.limits);
        const remote_warnings = try duplicateCounted(RemoteWarning, arena_allocator, self.remote_warnings.items, &owned_bytes, self.limits);
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
            .skip_after_targets = skip_after_targets,
            .generic_directives = generic_directives,
            .macro_programs = macro_programs,
            .macro_tokens = macro_tokens,
            .defaults = defaults,
            .metadata_tags = metadata_tags,
            .nondisruptive_effects = nondisruptive_effects,
            .rule_removals = rule_removals,
            .missing_rule_references = missing_rule_references,
            .remote_sources = remote_sources,
            .remote_warnings = remote_warnings,
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
    plan.skip_after_targets = component.skip_after_targets;
    plan.generic_directives = component.generic_directives;
    plan.macro_programs = component.macro_programs;
    plan.macro_tokens = component.macro_tokens;
    plan.defaults = component.defaults;
    plan.metadata_tags = component.metadata_tags;
    plan.nondisruptive_effects = component.nondisruptive_effects;
    plan.rule_removals = component.rule_removals;
    plan.missing_rule_references = component.missing_rule_references;
    plan.remote_sources = component.remote_sources;
    plan.remote_warnings = component.remote_warnings;
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
        !slicesEqual(SkipAfterTarget, first.skip_after_targets, second.skip_after_targets) or
        !std.mem.eql(DirectiveId, first.generic_directives, second.generic_directives) or
        !slicesEqual(MacroProgram, first.macro_programs, second.macro_programs) or
        !slicesEqual(MacroToken, first.macro_tokens, second.macro_tokens) or
        !slicesEqual(DefaultSnapshot, first.defaults, second.defaults) or
        !slicesEqual(MetadataText, first.metadata_tags, second.metadata_tags) or
        !slicesEqual(NondisruptiveEffect, first.nondisruptive_effects, second.nondisruptive_effects) or
        !slicesEqual(RuleRemoval, first.rule_removals, second.rule_removals) or
        !slicesEqual(MissingRuleReference, first.missing_rule_references, second.missing_rule_references) or
        !slicesEqual(RemoteSource, first.remote_sources, second.remote_sources) or
        !slicesEqual(RemoteWarning, first.remote_warnings, second.remote_warnings))
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
    for (plan.directives) |directive| {
        const name = plan.string(directive.name).?;
        const arguments = plan.arguments[directive.arguments_start..][0..directive.arguments_count];
        for (arguments, 0..) |argument, argument_offset| {
            if (sensitiveDirectiveArgument(name, argument_offset)) {
                hashString(&hasher, "<redacted>");
            } else {
                hashString(&hasher, plan.string(argument.raw).?);
            }
            hashU8(&hasher, @intCast(@backingInt(argument.quote)));
        }
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
        hashMetadataText(&hasher, plan, rule.metadata.revision);
        hashMetadataText(&hasher, plan, rule.metadata.message);
        hashMetadataText(&hasher, plan, rule.metadata.log_data);
        if (rule.metadata.severity) |severity| {
            hashBool(&hasher, true);
            hashU8(&hasher, @backingInt(severity));
        } else hashBool(&hasher, false);
        if (rule.metadata.maturity) |maturity| {
            hashBool(&hasher, true);
            hashU8(&hasher, maturity);
        } else hashBool(&hasher, false);
        if (rule.metadata.accuracy) |accuracy| {
            hashBool(&hasher, true);
            hashU8(&hasher, accuracy);
        } else hashBool(&hasher, false);
        hashMetadataText(&hasher, plan, rule.metadata.version);
        hashU32(&hasher, rule.metadata.tags_start);
        hashU32(&hasher, rule.metadata.tags_count);
        hashU32(&hasher, rule.effects_start);
        hashU32(&hasher, rule.effects_count);
        hashU8(&hasher, @intCast(@backingInt(rule.disruptive.kind)));
        hashU32(&hasher, rule.disruptive.status);
        hashBool(&hasher, rule.disruptive.status_explicit);
        hashU8(&hasher, @intCast(@backingInt(rule.disruptive.allow_scope)));
        hashEffectText(&hasher, plan, rule.disruptive.destination);
        hashBool(&hasher, rule.disruptive.declared_block);
        hashU32(&hasher, rule.flow.skip);
        if (rule.flow.skip_after_action) |action_index| {
            hashBool(&hasher, true);
            hashU32(&hasher, action_index);
        } else hashBool(&hasher, false);
        if (rule.flow.skip_after_target) |target_index| {
            hashBool(&hasher, true);
            hashU32(&hasher, target_index);
        } else hashBool(&hasher, false);
        hashEffectText(&hasher, plan, rule.flow.skip_after_value);
        hashBool(&hasher, rule.flow.multi_match);
        hashOptionalId(&hasher, rule.removed_by);
    }

    hashU32(&hasher, @intCast(plan.metadata_tags.len));
    for (plan.metadata_tags) |tag| {
        hashString(&hasher, plan.string(tag.value).?);
        hashOptionalId(&hasher, tag.macro);
    }
    hashU32(&hasher, @intCast(plan.nondisruptive_effects.len));
    for (plan.nondisruptive_effects) |effect| {
        hashU32(&hasher, effect.action_index);
        hashU8(&hasher, @intCast(@backingInt(effect.kind)));
        if (effect.collection) |collection| {
            hashBool(&hasher, true);
            hashU8(&hasher, @intCast(@backingInt(collection)));
        } else hashBool(&hasher, false);
        if (effect.operation) |operation| {
            hashBool(&hasher, true);
            hashU8(&hasher, @intCast(@backingInt(operation)));
        } else hashBool(&hasher, false);
        hashEffectText(&hasher, plan, effect.name);
        hashEffectText(&hasher, plan, effect.value);
        hashEffectText(&hasher, plan, effect.auxiliary);
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
    hashU32(&hasher, @intCast(plan.rule_removals.len));
    for (plan.rule_removals) |removal| {
        hashU32(&hasher, @backingInt(removal.directive));
        hashU32(&hasher, @backingInt(removal.chain_head));
    }
    hashU32(&hasher, @intCast(plan.missing_rule_references.len));
    for (plan.missing_rule_references) |reference| {
        hashU32(&hasher, @backingInt(reference.directive));
        hashU8(&hasher, @intCast(@backingInt(reference.kind)));
        hashU64(&hasher, reference.interval.first);
        hashU64(&hasher, reference.interval.last);
    }
    hashU32(&hasher, @intCast(plan.remote_sources.len));
    for (plan.remote_sources) |remote_source| {
        hashU32(&hasher, @backingInt(remote_source.source_id));
        hasher.update(&remote_source.content_digest);
    }
    hashU32(&hasher, @intCast(plan.remote_warnings.len));
    for (plan.remote_warnings) |warning| {
        hashU32(&hasher, @intCast(@backingInt(warning.code)));
        hashU32(&hasher, @backingInt(warning.directive.source));
        hashU32(&hasher, warning.directive.start);
        hashU32(&hasher, warning.directive.end);
    }
    hashU32(&hasher, @intCast(plan.markers.len));
    for (plan.markers) |marker| {
        hashU32(&hasher, @backingInt(marker.directive));
        hashString(&hasher, plan.string(marker.name).?);
    }
    hashU32(&hasher, @intCast(plan.skip_after_targets.len));
    for (plan.skip_after_targets) |target| {
        hashU32(&hasher, @backingInt(target.rule));
        hashU32(&hasher, target.action_index);
        hashOptionalId(&hasher, target.marker);
        hashOptionalId(&hasher, target.resume_rule);
        hashBool(&hasher, target.dynamic);
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
        if (token.scalar) |scalar| {
            hashBool(&hasher, true);
            hashU32(&hasher, @intCast(@backingInt(scalar)));
        } else hashBool(&hasher, false);
        if (token.collection) |collection| {
            hashBool(&hasher, true);
            hashU32(&hasher, @intCast(@backingInt(collection)));
        } else hashBool(&hasher, false);
    }

    var result: Fingerprint = undefined;
    hasher.final(&result);
    return result;
}

fn sensitiveDirectiveArgument(name: []const u8, argument_offset: usize) bool {
    if (std.ascii.eqlIgnoreCase(name, "SecRemoteRules")) return argument_offset == 0;
    return std.ascii.eqlIgnoreCase(name, "SecHttpBlKey") or std.ascii.eqlIgnoreCase(name, "SecHashKey");
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

fn hashMetadataText(hasher: *std.crypto.hash.Blake3, plan: *const Plan, value: ?MetadataText) void {
    if (value) |text| {
        hashBool(hasher, true);
        hashString(hasher, plan.string(text.value).?);
        hashOptionalId(hasher, text.macro);
    } else hashBool(hasher, false);
}

fn hashEffectText(hasher: *std.crypto.hash.Blake3, plan: *const Plan, value: ?EffectText) void {
    if (value) |text| {
        hashBool(hasher, true);
        hashString(hasher, plan.string(text.value).?);
        hashOptionalId(hasher, text.macro);
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

fn matchesIntervals(intervals: []const rule_config.IdInterval, value: u64) bool {
    var low: usize = 0;
    var high = intervals.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const interval = intervals[middle];
        if (value < interval.first) {
            high = middle;
        } else if (value > interval.last) {
            low = middle + 1;
        } else {
            return true;
        }
    }
    return false;
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
    if (equalsAny(name, &.{ "id", "msg", "logdata", "tag", "severity", "ver", "version", "rev", "maturity", "accuracy" }))
        return .metadata;
    if (equalsAny(name, &.{
        "capture",         "setvar",               "setenv",                "initcol",                "expirevar",
        "deprecatevar",    "multimatch",           "log",                   "nolog",                  "auditlog",
        "noauditlog",      "ctl",                  "exec",                  "pause",                  "prepend",
        "status",          "append",               "setuid",                "setsid",                 "sanitizeArg",
        "sanitizeMatched", "sanitizeMatchedBytes", "sanitizeRequestHeader", "sanitizeResponseHeader",
    })) return .nondisruptive;
    if (equalsAny(name, &.{ "allow", "block", "deny", "drop", "pass", "proxy", "redirect" }))
        return .disruptive;
    if (equalsAny(name, &.{ "chain", "skip", "skipAfter" })) return .flow;
    return .unknown;
}

fn isRepeatableAction(name: []const u8) bool {
    return equalsAny(name, &.{
        "t",           "tag",             "setvar",               "setenv",                "ctl",                    "initcol", "expirevar", "deprecatevar", "exec",
        "sanitizeArg", "sanitizeMatched", "sanitizeMatchedBytes", "sanitizeRequestHeader", "sanitizeResponseHeader",
    });
}

fn sameActionFamily(compiler: *const Compiler, existing: Action, replacement: Action) bool {
    if (existing.class == .disruptive and replacement.class == .disruptive) return true;
    const existing_name = compiler.interner.values.items[@backingInt(existing.name)];
    const replacement_name = compiler.interner.values.items[@backingInt(replacement.name)];
    if (equalsAny(existing_name, &.{ "log", "nolog" }) and equalsAny(replacement_name, &.{ "log", "nolog" })) return true;
    if (equalsAny(existing_name, &.{ "auditlog", "noauditlog" }) and equalsAny(replacement_name, &.{ "auditlog", "noauditlog" })) return true;
    if (equalsAny(existing_name, &.{ "ver", "version" }) and equalsAny(replacement_name, &.{ "ver", "version" })) return true;
    return std.ascii.eqlIgnoreCase(existing_name, replacement_name);
}

fn equalsAny(value: []const u8, candidates: []const []const u8) bool {
    for (candidates) |candidate| if (std.ascii.eqlIgnoreCase(value, candidate)) return true;
    return false;
}

fn actionSpan(directive: seclang.parser.Directive) seclang.source.Span {
    return if (directive.actions()) |argument| argument.physical else directive.physical;
}

fn countActions(plan: *const Plan, actions: []const Action, name: []const u8) usize {
    var count: usize = 0;
    for (actions) |action| if (std.ascii.eqlIgnoreCase(plan.string(action.name).?, name)) {
        count += 1;
    };
    return count;
}

fn diagnosticCode(cause: anyerror) ?DiagnosticCode {
    return switch (cause) {
        error.InvalidRuleId => .invalid_rule_id,
        error.DuplicateRuleId => .duplicate_rule_id,
        error.InvalidPhase => .invalid_phase,
        error.InvalidDefaultAction => .invalid_default_action,
        error.DuplicateDefaultPhase => .duplicate_default_phase,
        error.MissingDefaultDisruptiveAction => .missing_default_disruptive_action,
        error.InvalidRuleSelector => .invalid_rule_selector,
        error.PartialChainSelection => .partial_chain_selection,
        error.MissingStaticMarker => .missing_static_marker,
        error.InvalidRuleTargetUpdate => .invalid_rule_target_update,
        error.InvalidRuleActionUpdate => .invalid_rule_action_update,
        error.InvalidRuleMetadata => .invalid_rule_metadata,
        error.InvalidNondisruptiveAction => .invalid_nondisruptive_action,
        error.InvalidDisruptiveAction => .invalid_disruptive_action,
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

test "source tree compilation inserts children at directive positions" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{
        .sub_path = "main.conf",
        .data = "SecAction \"id:1,pass\"\nInclude child.conf\nSecAction \"id:3,pass\"",
    });
    try temporary.dir.writeFile(std.testing.io, .{
        .sub_path = "child.conf",
        .data = "SecAction \"id:2,pass\"",
    });
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_length = try temporary.dir.realPathFile(std.testing.io, "main.conf", &path_buffer);
    var tree = try seclang.include.parseFile(std.testing.allocator, std.testing.io, path_buffer[0..path_length], .{});
    defer tree.deinit();
    const compiled = try compileTree(std.testing.allocator, &tree, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 4), compiled.directives.len);
    const expected = [_][]const u8{ "SecAction", "Include", "SecAction", "SecAction" };
    for (compiled.directives, expected) |directive, name|
        try std.testing.expectEqualStrings(name, compiled.string(directive.name).?);
    const expected_ids = [_][]const u8{ "id:1,pass", "id:2,pass", "id:3,pass" };
    for ([_]usize{ 0, 2, 3 }, expected_ids) |directive_index, actions|
        try std.testing.expectEqualStrings(actions, unquote(compiled.string(compiled.arguments[compiled.directives[directive_index].arguments_start].raw).?));
}

const PlanRemoteFetcher = struct {
    fn fetch(_: *anyopaque, allocator: std.mem.Allocator, request: remote_rules.Request) remote_rules.FetchError!remote_rules.Response {
        if (!request.destination_policy.authorize(request.url, "203.0.113.30")) return error.PolicyRejected;
        const addresses = try allocator.alloc([]u8, 1);
        errdefer allocator.free(addresses);
        addresses[0] = try allocator.dupe(u8, "203.0.113.30");
        errdefer allocator.free(addresses[0]);
        const final_url = try allocator.dupe(u8, request.url);
        errdefer allocator.free(final_url);
        const body = try allocator.dupe(u8, "SecAction \"id:2,pass\"");
        return .{
            .allocator = allocator,
            .status = 200,
            .final_url = final_url,
            .body = body,
            .redirects = 0,
            .connected_addresses = addresses,
        };
    }

    fn authorize(_: *anyopaque, _: []const u8, _: ?[]const u8) bool {
        return true;
    }
};

test "remote source assembly compiles inline and retains immutable evidence" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{
        .sub_path = "main.conf",
        .data = "SecAction \"id:1,pass\"\nSecRemoteRules key https://rules.example.test/bundle\nSecAction \"id:3,pass\"",
    });
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_length = try temporary.dir.realPathFile(std.testing.io, "main.conf", &path_buffer);
    var fetcher_byte: u8 = 0;
    var policy_byte: u8 = 0;
    var tree = try seclang.assembly.assembleFile(
        std.testing.allocator,
        std.testing.io,
        path_buffer[0..path_length],
        .{},
        .{ .context = &fetcher_byte, .fetchFn = PlanRemoteFetcher.fetch },
        .{ .context = &policy_byte, .authorizeFn = PlanRemoteFetcher.authorize },
        .{},
    );
    defer tree.deinit();
    const compiled = try compileTree(std.testing.allocator, &tree, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 4), compiled.directives.len);
    const expected = [_][]const u8{ "SecAction", "SecRemoteRules", "SecAction", "SecAction" };
    for (compiled.directives, expected) |directive, name|
        try std.testing.expectEqualStrings(name, compiled.string(directive.name).?);
    try std.testing.expectEqual(@as(usize, 1), compiled.remote_sources.len);
    try std.testing.expectEqual(@as(usize, 0), compiled.remote_warnings.len);
    try std.testing.expectEqual(tree.remote_sources.items[0].content_digest, compiled.remote_sources[0].content_digest);
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
        \\SecRule ARGS "@rx a" "id:1,phase:1,t:none,t:urlDecodeUni,chain"
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

test "default actions are phase scoped immutable snapshots" {
    const input =
        \\SecDefaultAction "phase:1,t:lowercase,pass"
        \\SecDefaultAction "phase:2,t:trim,deny,status:403"
        \\SecRule ARGS "@rx one" "id:1,phase:1"
        \\SecRule ARGS "@rx two" "id:2"
        \\SecRule ARGS "@rx three" "id:3,phase:3,pass"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "phase-defaults.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 2), compiled.defaults.len);
    try std.testing.expectEqual(@as(?DefaultId, @fromBackingInt(0)), compiled.rules[0].default);
    try std.testing.expectEqual(@as(?DefaultId, @fromBackingInt(1)), compiled.rules[1].default);
    try std.testing.expectEqual(@as(?DefaultId, null), compiled.rules[2].default);
    try std.testing.expectEqual(@as(u8, 2), compiled.rules[1].phase);
    try std.testing.expectEqualStrings("lowercase", compiled.string(compiled.transformations[compiled.rules[0].transformations_start].name).?);
    try std.testing.expectEqualStrings("trim", compiled.string(compiled.transformations[compiled.rules[1].transformations_start].name).?);
}

test "default action compatibility failures have precise diagnostics" {
    const cases = [_]struct {
        input: []const u8,
        code: DiagnosticCode,
        related: bool = false,
    }{
        .{ .input = "SecDefaultAction pass", .code = .invalid_phase },
        .{ .input = "SecDefaultAction \"phase:2,log\"", .code = .missing_default_disruptive_action },
        .{ .input = "SecDefaultAction \"phase:2,t:none,pass\"", .code = .invalid_default_action },
        .{ .input = "SecDefaultAction \"phase:2,id:1,pass\"", .code = .invalid_default_action },
        .{ .input = "SecDefaultAction \"phase:2,pass\"\nSecDefaultAction \"phase:2,deny\"", .code = .duplicate_default_phase, .related = true },
    };
    for (cases) |case| {
        var parsed = try seclang.parser.parseBytes(std.testing.allocator, "invalid-default.conf", case.input, .{}, .{});
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

test "remove by id filters phase indexes and retains immutable evidence" {
    const input =
        \\SecRule ARGS @rx "id:1,phase:2,chain"
        \\SecRule TX @rx id:2
        \\SecRule ARGS @rx id:3
        \\SecRule ARGS @rx id:10
        \\SecRuleRemoveById "3,10-20"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "remove-id.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 1), compiled.phaseRules(2).len);
    try std.testing.expectEqual(@as(RuleId, @fromBackingInt(0)), compiled.phaseRules(2)[0]);
    try std.testing.expectEqual(@as(?DirectiveId, null), compiled.rules[0].removed_by);
    try std.testing.expectEqual(@as(?DirectiveId, @fromBackingInt(4)), compiled.rules[2].removed_by);
    try std.testing.expectEqual(@as(?DirectiveId, @fromBackingInt(4)), compiled.rules[3].removed_by);
    try std.testing.expectEqualSlices(RuleRemoval, &.{
        .{ .directive = @fromBackingInt(4), .chain_head = @fromBackingInt(2) },
        .{ .directive = @fromBackingInt(4), .chain_head = @fromBackingInt(3) },
    }, compiled.rule_removals);
}

test "removing a chain head removes every member" {
    const input =
        \\SecRule ARGS @rx "id:1,chain"
        \\SecRule TX @rx id:2
        \\SecRuleRemoveById 1
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "remove-chain.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 0), compiled.phaseRules(2).len);
    try std.testing.expectEqual(@as(?DirectiveId, @fromBackingInt(2)), compiled.rules[0].removed_by);
    try std.testing.expectEqual(@as(?DirectiveId, @fromBackingInt(2)), compiled.rules[1].removed_by);
    try std.testing.expectEqual(@as(usize, 1), compiled.rule_removals.len);
}

test "remove by id rejects partial chain selection with related rule span" {
    const input =
        \\SecRule ARGS @rx "id:1,chain"
        \\SecRule TX @rx id:2
        \\SecRuleRemoveById 2
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "partial-chain.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    var outcome = try compileOutcome(std.testing.allocator, &parsed.registry, &documents, .{});
    defer outcome.deinit();
    switch (outcome) {
        .plan => return error.TestExpectedDiagnostic,
        .diagnostic => |value| {
            try std.testing.expectEqual(DiagnosticCode.partial_chain_selection, value.code);
            try std.testing.expectEqualStrings("WAF-PLAN-0113", value.code.id());
            try std.testing.expectEqual(parsed.document.directives.items[2].physical, value.primary);
            try std.testing.expectEqual(parsed.document.directives.items[1].physical, value.secondary.?);
        },
    }
}

test "remove by tag and message compile zig-regex selectors once per operation" {
    const input =
        \\SecRule ARGS @rx "id:1,tag:'attack-dos',msg:'Directory Listing'"
        \\SecRule ARGS @rx "id:2,tag:'protocol-violation',msg:'Bad framing'"
        \\SecRule ARGS @rx "id:3,tag:'attack-sqli',msg:'Possible SQL injection'"
        \\SecRuleRemoveByTag "^attack-dos$"
        \\SecRuleRemoveByMsg "SQL injection"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "remove-regex.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    try std.testing.expectEqualSlices(RuleId, &.{@as(RuleId, @fromBackingInt(1))}, compiled.phaseRules(2));
    try std.testing.expectEqual(@as(?DirectiveId, @fromBackingInt(3)), compiled.rules[0].removed_by);
    try std.testing.expectEqual(@as(?DirectiveId, null), compiled.rules[1].removed_by);
    try std.testing.expectEqual(@as(?DirectiveId, @fromBackingInt(4)), compiled.rules[2].removed_by);
    try std.testing.expectEqualSlices(RuleRemoval, &.{
        .{ .directive = @fromBackingInt(3), .chain_head = @fromBackingInt(0) },
        .{ .directive = @fromBackingInt(4), .chain_head = @fromBackingInt(2) },
    }, compiled.rule_removals);
}

test "target updates by id tag and message materialize ordered effective ranges" {
    const input =
        \\SecRule ARGS|REQUEST_HEADERS @rx "id:1,tag:'group-a',msg:'hello world'"
        \\SecRule TX @rx id:2
        \\SecRuleUpdateTargetById 1 "!ARGS:secret|REQUEST_BODY"
        \\SecRuleUpdateTargetByTag group-a "!REQUEST_HEADERS:authorization"
        \\SecRuleUpdateTargetByMsg "hello world" FILES
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "target-updates.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    const first = compiled.rules[0];
    try std.testing.expectEqual(@as(u32, 6), first.targets_count);
    const effective = compiled.targets[first.targets_start..][0..first.targets_count];
    try std.testing.expectEqualStrings("ARGS", compiled.string(effective[0].collection).?);
    try std.testing.expectEqualStrings("REQUEST_HEADERS", compiled.string(effective[1].collection).?);
    try std.testing.expectEqual(seclang.syntax.Modifier.negated, effective[2].modifier);
    try std.testing.expectEqualStrings("secret", compiled.string(effective[2].selector.?).?);
    try std.testing.expectEqualStrings("REQUEST_BODY", compiled.string(effective[3].collection).?);
    try std.testing.expectEqual(seclang.syntax.Modifier.negated, effective[4].modifier);
    try std.testing.expectEqualStrings("authorization", compiled.string(effective[4].selector.?).?);
    try std.testing.expectEqualStrings("FILES", compiled.string(effective[5].collection).?);
    try std.testing.expectEqual(@as(u32, 1), compiled.rules[1].targets_count);
}

test "invalid target update syntax has a stable diagnostic" {
    var parsed = try seclang.parser.parseBytes(
        std.testing.allocator,
        "invalid-target-update.conf",
        "SecRuleUpdateTargetById 1 !",
        .{},
        .{},
    );
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    var outcome = try compileOutcome(std.testing.allocator, &parsed.registry, &documents, .{});
    defer outcome.deinit();
    switch (outcome) {
        .plan => return error.TestExpectedDiagnostic,
        .diagnostic => |value| {
            try std.testing.expectEqual(DiagnosticCode.invalid_rule_target_update, value.code);
            try std.testing.expectEqualStrings("WAF-PLAN-0115", value.code.id());
        },
    }
}

test "action updates replace singleton families append repeatables and rebuild transforms" {
    const input =
        \\SecRule ARGS @rx "id:1,deny,status:403,msg:'old',tag:'a',t:lowercase,log,auditlog"
        \\SecRule TX @rx "id:2,deny"
        \\SecRuleUpdateActionById 1-2 "pass,status:204,tag:'b',t:none,t:trim,nolog,noauditlog,msg:'new'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "action-updates.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    const first = compiled.rules[0];
    const actions = compiled.actions[first.actions_start..][0..first.actions_count];
    try std.testing.expectEqual(@as(usize, 0), countActions(compiled, actions, "deny"));
    try std.testing.expectEqual(@as(usize, 1), countActions(compiled, actions, "pass"));
    try std.testing.expectEqual(@as(usize, 1), countActions(compiled, actions, "status"));
    try std.testing.expectEqual(@as(usize, 2), countActions(compiled, actions, "tag"));
    try std.testing.expectEqual(@as(usize, 3), countActions(compiled, actions, "t"));
    try std.testing.expectEqual(@as(usize, 0), countActions(compiled, actions, "log"));
    try std.testing.expectEqual(@as(usize, 1), countActions(compiled, actions, "nolog"));
    try std.testing.expectEqual(@as(usize, 0), countActions(compiled, actions, "auditlog"));
    try std.testing.expectEqual(@as(usize, 1), countActions(compiled, actions, "noauditlog"));
    try std.testing.expectEqual(@as(usize, 1), first.transformations_count);
    try std.testing.expectEqualStrings("trim", compiled.string(compiled.transformations[first.transformations_start].name).?);
    const second_actions = compiled.actions[compiled.rules[1].actions_start..][0..compiled.rules[1].actions_count];
    try std.testing.expectEqual(@as(usize, 0), countActions(compiled, second_actions, "deny"));
    try std.testing.expectEqual(@as(usize, 1), countActions(compiled, second_actions, "pass"));
}

test "action updates reject id phase chain and malformed lists" {
    const cases = [_][]const u8{
        "SecRuleUpdateActionById 1 id:2",
        "SecRuleUpdateActionById 1 phase:3",
        "SecRuleUpdateActionById 1 chain",
        "SecRuleUpdateActionById 1 \"msg:'open\"",
    };
    for (cases) |input| {
        var parsed = try seclang.parser.parseBytes(std.testing.allocator, "invalid-action-update.conf", input, .{}, .{});
        defer parsed.deinit();
        var documents = [_]seclang.parser.Document{parsed.document};
        var outcome = try compileOutcome(std.testing.allocator, &parsed.registry, &documents, .{});
        defer outcome.deinit();
        switch (outcome) {
            .plan => return error.TestExpectedDiagnostic,
            .diagnostic => |value| {
                try std.testing.expectEqual(DiagnosticCode.invalid_rule_action_update, value.code);
                try std.testing.expectEqualStrings("WAF-PLAN-0116", value.code.id());
            },
        }
    }
}

test "unmatched id requests remain structured final-builder evidence" {
    const input =
        \\SecRule ARGS @rx id:1
        \\SecRuleRemoveById "1 2 10-20"
        \\SecRuleUpdateTargetById 3 TX
        \\SecRuleUpdateActionById 4 pass
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "missing-rules.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 4), compiled.missing_rule_references.len);
    try std.testing.expectEqual(MissingRuleReferenceKind.remove_by_id, compiled.missing_rule_references[0].kind);
    try std.testing.expectEqual(rule_config.IdInterval{ .first = 2, .last = 2 }, compiled.missing_rule_references[0].interval);
    try std.testing.expectEqual(rule_config.IdInterval{ .first = 10, .last = 20 }, compiled.missing_rule_references[1].interval);
    try std.testing.expectEqual(MissingRuleReferenceKind.update_target_by_id, compiled.missing_rule_references[2].kind);
    try std.testing.expectEqual(MissingRuleReferenceKind.update_action_by_id, compiled.missing_rule_references[3].kind);
}

test "static skipAfter targets resolve to the next marker and phase rule" {
    const input =
        \\SecMarker END
        \\SecRule ARGS @rx "id:1,phase:1,skipAfter:END"
        \\SecRule ARGS @rx "id:2,phase:1"
        \\SecMarker END
        \\SecRule ARGS @rx "id:3,phase:1"
        \\SecMarker END
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "markers.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 3), compiled.markers.len);
    try std.testing.expectEqual(@as(usize, 1), compiled.skip_after_targets.len);
    const target = compiled.skip_after_targets[0];
    try std.testing.expectEqual(@as(RuleId, @fromBackingInt(0)), target.rule);
    try std.testing.expectEqual(@as(?MarkerId, @fromBackingInt(1)), target.marker);
    try std.testing.expectEqual(@as(?RuleId, @fromBackingInt(2)), target.resume_rule);
    try std.testing.expect(!target.dynamic);
    const resolved = compiled.resolveMarkerAfter(@fromBackingInt(0), "END").?;
    try std.testing.expectEqual(target.marker.?, resolved.marker);
    try std.testing.expectEqual(target.resume_rule, resolved.resume_rule);
}

test "dynamic skipAfter retains bounded runtime marker resolution" {
    const input =
        \\SecRule ARGS @rx "id:1,phase:2,skipAfter:%{TX.marker}"
        \\SecMarker END
        \\SecRule ARGS @rx "id:2,phase:2"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "dynamic-marker.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 1), compiled.skip_after_targets.len);
    try std.testing.expect(compiled.skip_after_targets[0].dynamic);
    try std.testing.expectEqual(@as(?MarkerId, null), compiled.skip_after_targets[0].marker);
    const resolved = compiled.resolveMarkerAfter(@fromBackingInt(0), "END").?;
    try std.testing.expectEqual(@as(MarkerId, @fromBackingInt(0)), resolved.marker);
    try std.testing.expectEqual(@as(?RuleId, @fromBackingInt(1)), resolved.resume_rule);
}

test "unresolved static skipAfter marker is retained for final source linking" {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "missing-marker.conf", "SecRule ARGS @rx \"id:1,skipAfter:ABSENT\"", .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();
    const unresolved = compiled.firstUnresolvedStaticMarker().?;
    try std.testing.expect(!unresolved.dynamic);
    try std.testing.expectEqual(@as(?MarkerId, null), unresolved.marker);
}

test "invalid tag and message regexes produce stable plan diagnostics" {
    const cases = [_][]const u8{
        "SecRuleRemoveByTag [",
        "SecRuleRemoveByMsg (",
    };
    for (cases) |input| {
        var parsed = try seclang.parser.parseBytes(std.testing.allocator, "invalid-removal-regex.conf", input, .{}, .{});
        defer parsed.deinit();
        var documents = [_]seclang.parser.Document{parsed.document};
        var outcome = try compileOutcome(std.testing.allocator, &parsed.registry, &documents, .{});
        defer outcome.deinit();
        switch (outcome) {
            .plan => return error.TestExpectedDiagnostic,
            .diagnostic => |value| {
                try std.testing.expectEqual(DiagnosticCode.invalid_rule_selector, value.code);
                try std.testing.expectEqualStrings("WAF-PLAN-0112", value.code.id());
            },
        }
    }
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
        .{ .input = "SecRuleRemoveById 1\nSecRuleRemoveById 2", .limits = .{ .max_rule_updates = 1 }, .failure = error.TooManyRuleUpdates },
        .{ .input = "SecRuleRemoveById \"1 3\"", .limits = .{ .max_id_intervals = 1 }, .failure = error.TooManyIdIntervals },
        .{ .input = "SecRule ARGS @rx skipAfter:END\nSecRule TX @rx skipAfter:END\nSecMarker END", .limits = .{ .max_flow_targets = 1 }, .failure = error.TooManyFlowTargets },
        .{ .input = "SecRule ARGS @rx id:1\nSecRuleUpdateTargetById 1 TX", .limits = .{ .max_target_expansion = 1 }, .failure = error.TargetExpansionLimitExceeded },
        .{ .input = "SecRule ARGS @rx \"id:1,deny\"\nSecRuleUpdateActionById 1 pass", .limits = .{ .max_action_expansion = 1 }, .failure = error.ActionExpansionLimitExceeded },
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

test "structural fingerprints redact authentication and hashing secrets" {
    const first_input =
        \\SecRemoteRules first-secret https://rules.example.test/bundle
        \\SecHttpBlKey blocklist-secret-a
        \\SecHashKey hash-secret-a KeyOnly
    ;
    const second_input =
        \\SecRemoteRules second-secret https://rules.example.test/bundle
        \\SecHttpBlKey blocklist-secret-b
        \\SecHashKey hash-secret-b KeyOnly
    ;
    var first_parsed = try seclang.parser.parseBytes(std.testing.allocator, "first-secret.conf", first_input, .{}, .{});
    defer first_parsed.deinit();
    var second_parsed = try seclang.parser.parseBytes(std.testing.allocator, "second-secret.conf", second_input, .{}, .{});
    defer second_parsed.deinit();
    var first_documents = [_]seclang.parser.Document{first_parsed.document};
    var second_documents = [_]seclang.parser.Document{second_parsed.document};
    const first = try compile(std.testing.allocator, &first_parsed.registry, &first_documents, .{});
    defer first.deinit();
    const second = try compile(std.testing.allocator, &second_parsed.registry, &second_documents, .{});
    defer second.deinit();
    try std.testing.expectEqualSlices(u8, &first.fingerprint, &second.fingerprint);
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
        \\SecRule ARGS|REQUEST_HEADERS:host "@contains attack" "id:1,msg:'%{REQUEST_URI}',tag:'allocation',severity:CRITICAL,maturity:9,accuracy:8,ver:'test/1',deny,chain"
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
    try std.testing.expectEqual(variables.Name.request_uri, tokens[1].scalar.?);
    try std.testing.expectEqual(MacroTokenKind.collection, tokens[3].kind);
    try std.testing.expectEqualStrings("TX", compiled.string(tokens[3].name.?).?);
    try std.testing.expectEqualStrings("user", compiled.string(tokens[3].key.?).?);
    try std.testing.expectEqual(collections.Name.tx, tokens[3].collection.?);
}

test "unkeyed collection macros retain a typed collection descriptor" {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "collection-macro.conf", "SecRule ARGS @rx \"id:1,msg:'%{ARGS}'\"", .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();
    const program = compiled.macro_programs[@backingInt(compiled.rules[0].metadata.message.?.macro.?)];
    const token = compiled.macro_tokens[program.tokens_start];
    try std.testing.expectEqual(MacroTokenKind.collection, token.kind);
    try std.testing.expectEqual(collections.Name.args, token.collection.?);
    try std.testing.expect(token.scalar == null);
    try std.testing.expect(token.key == null);
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

test "rule metadata is typed normalized and rebuilt after action updates" {
    const input =
        \\SecRule ARGS @rx "id:42,rev:'1',msg:'old %{TX.name}',logdata:'%{TX.0}',tag:'first',tag:'second %{TX.kind}',severity:CRITICAL,maturity:9,accuracy:8,ver:'CRS/4'"
        \\SecRuleUpdateActionById 42 "msg:'new %{TX.name}',tag:'third',severity:NOTICE,version:'CRS/4.1'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "metadata.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    const metadata = compiled.rules[0].metadata;
    try std.testing.expectEqualStrings("1", compiled.string(metadata.revision.?.value).?);
    try std.testing.expectEqualStrings("new %{TX.name}", compiled.string(metadata.message.?.value).?);
    try std.testing.expect(metadata.message.?.macro != null);
    try std.testing.expectEqualStrings("%{TX.0}", compiled.string(metadata.log_data.?.value).?);
    try std.testing.expectEqual(action_config.Severity.notice, metadata.severity.?);
    try std.testing.expectEqual(@as(?u4, 9), metadata.maturity);
    try std.testing.expectEqual(@as(?u4, 8), metadata.accuracy);
    try std.testing.expectEqualStrings("CRS/4.1", compiled.string(metadata.version.?.value).?);
    try std.testing.expectEqual(@as(u32, 3), metadata.tags_count);
    const tags = compiled.metadata_tags[metadata.tags_start..][0..metadata.tags_count];
    try std.testing.expectEqualStrings("first", compiled.string(tags[0].value).?);
    try std.testing.expectEqualStrings("second %{TX.kind}", compiled.string(tags[1].value).?);
    try std.testing.expect(tags[1].macro != null);
    try std.testing.expectEqualStrings("third", compiled.string(tags[2].value).?);
}

test "invalid metadata has a stable diagnostic" {
    const cases = [_][]const u8{
        "SecRule ARGS @rx \"id:1,msg\"",
        "SecRule ARGS @rx \"id:1,severity:8\"",
        "SecRule ARGS @rx \"id:1,maturity:0\"",
        "SecRule ARGS @rx \"id:1,accuracy:10\"",
    };
    for (cases) |case| {
        var parsed = try seclang.parser.parseBytes(std.testing.allocator, "invalid-metadata.conf", case, .{}, .{});
        defer parsed.deinit();
        var documents = [_]seclang.parser.Document{parsed.document};
        var outcome = try compileOutcome(std.testing.allocator, &parsed.registry, &documents, .{});
        defer outcome.deinit();
        switch (outcome) {
            .plan => return error.TestExpectedDiagnostic,
            .diagnostic => |diagnostic| try std.testing.expectEqual(DiagnosticCode.invalid_rule_metadata, diagnostic.code),
        }
    }
    try std.testing.expectEqualStrings("WAF-PLAN-0117", DiagnosticCode.invalid_rule_metadata.id());
}

test "repeated singleton metadata uses the last value while tags append" {
    var parsed = try seclang.parser.parseBytes(
        std.testing.allocator,
        "repeated-metadata.conf",
        "SecRule ARGS @rx \"id:1,msg:'one',tag:'a',msg:'two',ver:'old',version:'new',tag:'b'\"",
        .{},
        .{},
    );
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();
    const metadata = compiled.rules[0].metadata;
    try std.testing.expectEqualStrings("two", compiled.string(metadata.message.?.value).?);
    try std.testing.expectEqualStrings("new", compiled.string(metadata.version.?.value).?);
    try std.testing.expectEqual(@as(u32, 2), metadata.tags_count);
}

test "metadata tag storage has an independent resource limit" {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "metadata-limits.conf", "SecRule ARGS @rx \"id:1,tag:'one',tag:'two'\"", .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    try std.testing.expectError(error.TooManyMetadataTags, compile(std.testing.allocator, &parsed.registry, &documents, .{ .max_metadata_tags = 1 }));
}

test "non-disruptive actions compile into ordered typed effect descriptors" {
    const input =
        \\SecDefaultAction "phase:2,log,auditlog,pass"
        \\SecRule ARGS @rx "id:1,capture,nolog,setenv:'FLAG=%{TX.flag}',setvar:'tx.score=+%{TX.delta}',initcol:'ip=%{REMOTE_ADDR}',expirevar:'ip.score=60',deprecatevar:'ip.score=5/60',setuid:'%{TX.user}',setsid:'%{TX.session}',setrsc:'%{REQUEST_URI}'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "effects.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    const rule = compiled.rules[0];
    const effects = compiled.nondisruptive_effects[rule.effects_start..][0..rule.effects_count];
    try std.testing.expectEqual(@as(usize, 12), effects.len);
    try std.testing.expectEqual(EffectKind.log, effects[0].kind);
    try std.testing.expectEqual(EffectKind.auditlog, effects[1].kind);
    try std.testing.expectEqual(EffectKind.capture, effects[2].kind);
    try std.testing.expectEqual(EffectKind.nolog, effects[3].kind);
    try std.testing.expectEqual(EffectKind.setenv, effects[4].kind);
    try std.testing.expectEqualStrings("FLAG", compiled.string(effects[4].name.?.value).?);
    try std.testing.expect(effects[4].value.?.macro != null);
    try std.testing.expectEqual(EffectKind.setvar, effects[5].kind);
    try std.testing.expectEqual(action_config.Collection.tx, effects[5].collection.?);
    try std.testing.expectEqual(action_config.SetVarOperation.add, effects[5].operation.?);
    try std.testing.expectEqualStrings("score", compiled.string(effects[5].name.?.value).?);
    try std.testing.expectEqualStrings("%{TX.delta}", compiled.string(effects[5].value.?.value).?);
    try std.testing.expectEqual(EffectKind.initcol, effects[6].kind);
    try std.testing.expectEqual(action_config.Collection.ip, effects[6].collection.?);
    try std.testing.expectEqual(EffectKind.expirevar, effects[7].kind);
    try std.testing.expectEqualStrings("60", compiled.string(effects[7].value.?.value).?);
    try std.testing.expectEqual(EffectKind.deprecatevar, effects[8].kind);
    try std.testing.expectEqualStrings("5", compiled.string(effects[8].value.?.value).?);
    try std.testing.expectEqualStrings("60", compiled.string(effects[8].auxiliary.?.value).?);
    try std.testing.expectEqual(EffectKind.setuid, effects[9].kind);
    try std.testing.expectEqual(action_config.Collection.user, effects[9].collection.?);
    try std.testing.expectEqual(EffectKind.setsid, effects[10].kind);
    try std.testing.expectEqual(EffectKind.setrsc, effects[11].kind);
}

test "invalid non-disruptive action syntax has a stable diagnostic" {
    const cases = [_][]const u8{
        "SecRule ARGS @rx \"id:1,capture:bad\"",
        "SecRule ARGS @rx \"id:1,setenv:FLAG\"",
        "SecRule ARGS @rx \"id:1,setenv:FLAG=\"",
        "SecRule ARGS @rx \"id:1,setvar:ARGS.score=1\"",
        "SecRule ARGS @rx \"id:1,initcol:session=key\"",
        "SecRule ARGS @rx \"id:1,expirevar:tx.score=60\"",
        "SecRule ARGS @rx \"id:1,expirevar:ip.score=0\"",
        "SecRule ARGS @rx \"id:1,deprecatevar:ip.score=5\"",
        "SecRule ARGS @rx \"id:1,deprecatevar:ip.score=0/60\"",
        "SecRule ARGS @rx \"id:1,setuid\"",
    };
    for (cases) |input| {
        var parsed = try seclang.parser.parseBytes(std.testing.allocator, "invalid-effect.conf", input, .{}, .{});
        defer parsed.deinit();
        var documents = [_]seclang.parser.Document{parsed.document};
        var outcome = try compileOutcome(std.testing.allocator, &parsed.registry, &documents, .{});
        defer outcome.deinit();
        switch (outcome) {
            .plan => return error.TestExpectedDiagnostic,
            .diagnostic => |diagnostic| try std.testing.expectEqual(DiagnosticCode.invalid_nondisruptive_action, diagnostic.code),
        }
    }
    try std.testing.expectEqualStrings("WAF-PLAN-0118", DiagnosticCode.invalid_nondisruptive_action.id());
}

test "non-disruptive effect storage has an independent resource limit" {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "effect-limits.conf", "SecRule ARGS @rx \"id:1,log,auditlog\"", .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    try std.testing.expectError(error.TooManyNondisruptiveEffects, compile(std.testing.allocator, &parsed.registry, &documents, .{ .max_nondisruptive_effects = 1 }));
}

test "disruptive and flow actions compile to effective typed decisions" {
    const input =
        \\SecDefaultAction "phase:2,deny,status:429"
        \\SecRule ARGS @rx "id:1,allow:request,status:204"
        \\SecRule ARGS @rx "id:2,redirect:'https://example.test/%{TX.path}',status:307,skip:2,skipAfter:END,multiMatch"
        \\SecMarker END
        \\SecRule ARGS @rx "id:3,block,status:451"
        \\SecRule ARGS @rx "id:4,deny,deny"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "decisions.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer compiled.deinit();

    try std.testing.expectEqual(DisruptiveKind.allow, compiled.rules[0].disruptive.kind);
    try std.testing.expectEqual(action_config.AllowScope.request, compiled.rules[0].disruptive.allow_scope);
    try std.testing.expectEqual(@as(u16, 204), compiled.rules[0].disruptive.status);

    const redirect = compiled.rules[1];
    try std.testing.expectEqual(DisruptiveKind.redirect, redirect.disruptive.kind);
    try std.testing.expectEqual(@as(u16, 307), redirect.disruptive.status);
    try std.testing.expectEqualStrings("https://example.test/%{TX.path}", compiled.string(redirect.disruptive.destination.?.value).?);
    try std.testing.expect(redirect.disruptive.destination.?.macro != null);
    try std.testing.expectEqual(@as(u32, 2), redirect.flow.skip);
    try std.testing.expect(redirect.flow.skip_after_action != null);
    try std.testing.expect(redirect.flow.skip_after_target != null);
    try std.testing.expectEqualStrings("END", compiled.string(redirect.flow.skip_after_value.?.value).?);
    try std.testing.expect(redirect.flow.multi_match);

    const block = compiled.rules[2].disruptive;
    try std.testing.expect(block.declared_block);
    try std.testing.expectEqual(DisruptiveKind.deny, block.kind);
    try std.testing.expectEqual(@as(u16, 451), block.status);
    try std.testing.expect(block.status_explicit);
    try std.testing.expectEqual(DisruptiveKind.deny, compiled.rules[3].disruptive.kind);
}

test "invalid disruptive and flow values have a stable diagnostic" {
    const cases = [_][]const u8{
        "SecRule ARGS @rx \"id:1,allow:response\"",
        "SecRule ARGS @rx \"id:1,status:99\"",
        "SecRule ARGS @rx \"id:1,skip:0\"",
        "SecRule ARGS @rx \"id:1,redirect\"",
        "SecRule ARGS @rx \"id:1,deny:value\"",
        "SecRule ARGS @rx \"id:1,pass,deny\"",
    };
    for (cases) |input| {
        var parsed = try seclang.parser.parseBytes(std.testing.allocator, "invalid-decision.conf", input, .{}, .{});
        defer parsed.deinit();
        var documents = [_]seclang.parser.Document{parsed.document};
        var outcome = try compileOutcome(std.testing.allocator, &parsed.registry, &documents, .{});
        defer outcome.deinit();
        switch (outcome) {
            .plan => return error.TestExpectedDiagnostic,
            .diagnostic => |diagnostic| try std.testing.expectEqual(DiagnosticCode.invalid_disruptive_action, diagnostic.code),
        }
    }
    try std.testing.expectEqualStrings("WAF-PLAN-0119", DiagnosticCode.invalid_disruptive_action.id());
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
