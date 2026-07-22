//! Core WAF ownership and transaction lifecycle contracts.

const std = @import("std");
const action_config = @import("action_config.zig");
const collections = @import("collections.zig");
const compiled_plan = @import("plan.zig");
const directives = @import("directives.zig");
const macros = @import("macros.zig");
const persistent = @import("persistent.zig");
const rule_config = @import("rule_config.zig");
const seclang = @import("seclang/root.zig");
const variables = @import("variables.zig");

pub const Mode = enum {
    enabled,
    detection_only,
};

pub const Feature = enum(u6) {
    transaction_lifecycle,
    bounded_streaming_bodies,
    detection_only,
    native_sqli,
    scalar_variables,
    collection_variables,
    runtime_macros,
    persistent_collections,
    atomic_hot_reload,
    compiled_execution_plan,
};

pub const FeatureSet = struct {
    bits: u64,

    pub fn allCompiled() FeatureSet {
        var bits: u64 = 0;
        inline for (std.meta.tags(Feature)) |feature| bits |= bit(feature);
        return .{ .bits = bits };
    }

    pub fn has(self: FeatureSet, feature: Feature) bool {
        return self.bits & bit(feature) != 0;
    }

    fn bit(feature: Feature) u64 {
        return @as(u64, 1) << @backingInt(feature);
    }
};

pub const Phase = enum(u8) {
    request_headers = 1,
    request_body = 2,
    response_headers = 3,
    response_body = 4,
    logging = 5,
};

pub const Limits = struct {
    max_request_target_bytes: usize = 16 * 1024,
    max_header_count: usize = 256,
    max_header_bytes: usize = 64 * 1024,
    max_request_body_bytes: usize = 16 * 1024 * 1024,
    max_response_body_bytes: usize = 16 * 1024 * 1024,
    max_scalar_value_bytes: usize = 32 * 1024,
    max_scalar_storage_bytes: usize = 256 * 1024,
    max_match_name_bytes: usize = 4096,
    max_match_value_bytes: usize = 1024 * 1024,
    max_captures: usize = 10,
    max_match_intents: usize = 1024,
    max_match_intent_bytes: usize = 4 * 1024 * 1024,
    max_runtime_exclusions: usize = 4096,
    max_runtime_exclusion_bytes: usize = 1024 * 1024,
    collection_limits: collections.Limits = .{},

    fn validate(self: Limits) ConfigError!void {
        if (self.max_request_target_bytes == 0 or
            self.max_header_count == 0 or
            self.max_header_bytes == 0 or
            self.max_request_body_bytes == 0 or
            self.max_response_body_bytes == 0 or
            self.max_scalar_value_bytes == 0 or
            self.max_scalar_storage_bytes < self.max_scalar_value_bytes or
            self.max_match_name_bytes == 0 or
            self.max_match_value_bytes == 0 or
            self.max_captures == 0 or
            self.max_captures > 10 or
            self.max_match_intents == 0 or
            self.max_match_intents > std.math.maxInt(u32) or
            self.max_match_intent_bytes == 0 or
            self.max_runtime_exclusions == 0 or
            self.max_runtime_exclusions > std.math.maxInt(u32) or
            self.max_runtime_exclusion_bytes == 0)
        {
            return error.InvalidLimit;
        }
        self.collection_limits.validate() catch return error.InvalidLimit;
    }
};

pub const Config = struct {
    mode: Mode = .enabled,
    limits: Limits = .{},
    macro_missing_policy: macros.MissingPolicy = .empty,
    persistent_backend: ?persistent.Backend = null,
    persistent_limits: persistent.Limits = .{},
    persistent_failure_policy: persistent.FailurePolicy = .fail_closed,
    persistent_required_features: persistent.BackendFeatureSet = persistent.BackendFeatureSet.core(),
    intervention_capabilities: InterventionCapabilities = .{},
};

pub const InterventionCapabilities = struct {
    proxy: bool = false,
    pause: bool = false,
};

pub const ClockSample = struct {
    unix_nanoseconds: i96,
    awake_nanoseconds: i96,
};

/// Optional deterministic clock provider for embedders and tests. The callback
/// must be nonblocking and thread-safe, and its context must outlive the WAF.
pub const ClockSource = struct {
    context: *anyopaque,
    nowFn: *const fn (context: *anyopaque) ClockSample,

    pub fn now(self: ClockSource) ClockSample {
        return self.nowFn(self.context);
    }
};

pub const ConfigError = error{ InvalidLimit, MissingPersistentBackendFeature, InvalidDirectiveConfiguration, InvalidExecutionPlan, MissingRuleReference };
pub const DeinitError = error{TransactionsActive};

pub const Intervention = struct {
    action: Action,
    status: u16,
    rule_id: ?u32 = null,
    destination: ?[]const u8 = null,
    enforced: bool,

    pub const Action = enum(u8) {
        deny,
        redirect,
        drop,
        pause,
        proxy,
    };
};

/// Builder for a validated immutable `Waf`.
///
/// Ruleset compilation will be added behind this type. Publishing only occurs
/// after complete validation, so callers never observe a partially compiled
/// ruleset.
pub const Builder = struct {
    allocator: std.mem.Allocator,
    config: Config = .{},
    io: std.Io,
    clock_source: ?ClockSource = null,
    retained_plan: ?*const compiled_plan.Plan = null,
    directive_capabilities: directives.CapabilitySet = .full(),
    missing_rule_policy: rule_config.MissingRulePolicy = .strict,

    pub fn init(allocator: std.mem.Allocator) Builder {
        return .{
            .allocator = allocator,
            .io = std.Io.Threaded.global_single_threaded.io(),
        };
    }

    /// Override the clock backend. The application owns the backend and must
    /// keep it alive until the WAF and all of its transactions are destroyed.
    pub fn setIo(self: *Builder, io: std.Io) void {
        self.io = io;
    }

    pub fn setClockSource(self: *Builder, source: ClockSource) void {
        self.clock_source = source;
    }

    pub fn setMode(self: *Builder, mode: Mode) void {
        self.config.mode = mode;
    }

    pub fn setLimits(self: *Builder, limits: Limits) void {
        self.config.limits = limits;
    }

    pub fn setMacroMissingPolicy(self: *Builder, policy: macros.MissingPolicy) void {
        self.config.macro_missing_policy = policy;
    }

    pub fn setPersistentBackend(self: *Builder, backend: persistent.Backend) void {
        self.config.persistent_backend = backend;
    }

    pub fn setPersistentLimits(self: *Builder, limits: persistent.Limits) void {
        self.config.persistent_limits = limits;
    }

    pub fn setPersistentFailurePolicy(self: *Builder, policy: persistent.FailurePolicy) void {
        self.config.persistent_failure_policy = policy;
    }

    pub fn setPersistentRequiredFeatures(self: *Builder, required: persistent.BackendFeatureSet) void {
        self.config.persistent_required_features = required;
    }

    pub fn setInterventionCapabilities(self: *Builder, capabilities: InterventionCapabilities) void {
        self.config.intervention_capabilities = capabilities;
    }

    /// Select the directive capabilities compiled into this WAF build. A plan
    /// using an omitted capability is rejected before publication.
    pub fn setDirectiveCapabilities(self: *Builder, capabilities: directives.CapabilitySet) void {
        self.directive_capabilities = capabilities;
    }

    pub fn setMissingRulePolicy(self: *Builder, policy: rule_config.MissingRulePolicy) void {
        self.missing_rule_policy = policy;
    }

    /// Retain the plan when `build` succeeds. The caller keeps ownership of its
    /// handle and only needs to keep it alive until `build` returns.
    pub fn setRetainedPlan(self: *Builder, value: *const compiled_plan.Plan) void {
        self.retained_plan = value;
    }

    /// Return the stable source-anchored diagnostic used by `build` without
    /// publishing or taking ownership of the plan.
    pub fn validateCompiledPlan(self: *const Builder, value: *const compiled_plan.Plan) directives.ValidationOutcome {
        return directives.validatePlan(value, self.directive_capabilities);
    }

    pub fn validateExecutionPlan(self: *const Builder, value: *const compiled_plan.Plan) compiled_plan.ExecutionValidation {
        _ = self;
        return value.validateExecutionPlan();
    }

    pub fn build(self: *const Builder) (ConfigError || std.mem.Allocator.Error)!*Waf {
        try self.validate(self.retained_plan);
        const retained = if (self.retained_plan) |value| try value.retain(self.allocator) else null;
        errdefer if (retained) |value| value.deinit();
        return self.allocate(retained);
    }

    /// Transfer `value` to the new WAF only on success. On error, ownership
    /// remains with the caller.
    pub fn buildTransferringPlan(self: *const Builder, value: *compiled_plan.Plan) (ConfigError || std.mem.Allocator.Error)!*Waf {
        try self.validate(value);
        return self.allocate(value);
    }

    fn validate(self: *const Builder, candidate: ?*const compiled_plan.Plan) ConfigError!void {
        try self.config.limits.validate();
        self.config.persistent_limits.validate() catch return error.InvalidLimit;
        if (self.config.persistent_backend) |backend| {
            if (!backend.features.containsAll(self.config.persistent_required_features)) return error.MissingPersistentBackendFeature;
        }
        if (candidate) |value| switch (self.validateCompiledPlan(value)) {
            .valid => {},
            .diagnostic => return error.InvalidDirectiveConfiguration,
        };
        if (candidate) |value| switch (self.validateExecutionPlan(value)) {
            .valid => {},
            .diagnostic => return error.InvalidExecutionPlan,
        };
        if (candidate) |value| if (self.missing_rule_policy == .strict and value.missing_rule_references.len != 0)
            return error.MissingRuleReference;
    }

    fn allocate(self: *const Builder, owned_plan: ?*compiled_plan.Plan) std.mem.Allocator.Error!*Waf {
        const waf = try self.allocator.create(Waf);
        const directive_configuration = if (owned_plan) |value| switch (directives.Configuration.init(value, self.directive_capabilities)) {
            .configuration => |configuration| configuration,
            .diagnostic => unreachable,
        } else null;
        waf.* = .{
            .allocator = self.allocator,
            .config = self.config,
            .io = self.io,
            .clock_source = self.clock_source,
            .plan = owned_plan,
            .directive_configuration = directive_configuration,
            .active_transactions = std.atomic.Value(usize).init(0),
            .transaction_sequence = std.atomic.Value(u64).init(0),
        };
        return waf;
    }

    pub fn buildRuntime(self: *const Builder) (ConfigError || RuntimeInitError)!*Runtime {
        const waf = try self.build();
        errdefer waf.deinit() catch unreachable;
        return Runtime.init(self.allocator, waf);
    }
};

/// Immutable, thread-safe compiled WAF state.
///
/// Keep the pointer stable until every child transaction is deinitialized.
/// `deinit` rejects an early destroy instead of allowing a dangling request.
pub const Waf = struct {
    allocator: std.mem.Allocator,
    config: Config,
    io: std.Io,
    clock_source: ?ClockSource,
    plan: ?*compiled_plan.Plan,
    directive_configuration: ?directives.Configuration,
    active_transactions: std.atomic.Value(usize),
    transaction_sequence: std.atomic.Value(u64),

    pub const Builder = @import("engine.zig").Builder;

    pub fn newTransaction(self: *const Waf) Transaction {
        _ = @constCast(&self.active_transactions).fetchAdd(1, .monotonic);
        const started = self.now();
        return .{
            .waf = self,
            .scalar_variables = variables.Store.init(self.allocator),
            .collection_variables = collections.Store.init(self.allocator, self.config.limits.collection_limits),
            .persistent_session = if (self.config.persistent_backend) |backend|
                persistent.Session.init(self.allocator, backend, self.config.persistent_limits) catch unreachable
            else
                null,
            .control_state = .{
                .rule_engine = if (self.config.mode == .enabled) .on else .detection_only,
                .request_body_limit = self.config.limits.max_request_body_bytes,
            },
            .started_real_nanoseconds = started.unix_nanoseconds,
            .started_awake_nanoseconds = started.awake_nanoseconds,
            .sequence = @constCast(&self.transaction_sequence).fetchAdd(1, .monotonic),
        };
    }

    pub fn activeTransactionCount(self: *const Waf) usize {
        return self.active_transactions.load(.acquire);
    }

    pub fn features(_: *const Waf) FeatureSet {
        return FeatureSet.allCompiled();
    }

    pub fn compiledPlan(self: *const Waf) ?*const compiled_plan.Plan {
        return self.plan;
    }

    pub fn directiveConfiguration(self: *const Waf) ?*const directives.Configuration {
        return if (self.directive_configuration) |*configuration| configuration else null;
    }

    fn now(self: *const Waf) ClockSample {
        if (self.clock_source) |source| return source.now();
        return .{
            .unix_nanoseconds = std.Io.Clock.now(.real, self.io).nanoseconds,
            .awake_nanoseconds = std.Io.Clock.now(.awake, self.io).nanoseconds,
        };
    }

    pub fn deinit(self: *Waf) DeinitError!void {
        if (self.active_transactions.load(.acquire) != 0) return error.TransactionsActive;
        const allocator = self.allocator;
        if (self.plan) |value| value.deinit();
        allocator.destroy(self);
    }
};

pub const RuntimeError = error{
    ShuttingDown,
    SameGeneration,
    GenerationInUse,
};

pub const RuntimeInitError = std.mem.Allocator.Error || error{GenerationInUse};

pub const RuntimeDeinitError = error{TransactionsActive};

/// Stable owner for atomically published immutable WAF generations.
///
/// The mutex protects only generation pointer acquisition and replacement.
/// Once returned, a transaction executes without touching the runtime lock and
/// remains pinned to the generation from which it was created.
pub const Runtime = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    active: ?*Waf,

    pub fn init(allocator: std.mem.Allocator, initial: *Waf) RuntimeInitError!*Runtime {
        if (initial.activeTransactionCount() != 0) return error.GenerationInUse;
        const runtime = try allocator.create(Runtime);
        runtime.* = .{ .allocator = allocator, .active = initial };
        return runtime;
    }

    pub fn newTransaction(self: *Runtime) RuntimeError!Transaction {
        lock(&self.mutex);
        defer self.mutex.unlock();
        return (self.active orelse return error.ShuttingDown).newTransaction();
    }

    /// Publish `replacement` and transfer ownership of the prior generation to
    /// the returned retirement handle. A replacement with existing requests is
    /// rejected because its ownership is not exclusive.
    pub fn reload(self: *Runtime, replacement: *Waf) RuntimeError!RetiredGeneration {
        if (replacement.activeTransactionCount() != 0) return error.GenerationInUse;
        lock(&self.mutex);
        defer self.mutex.unlock();
        const current = self.active orelse return error.ShuttingDown;
        if (current == replacement) return error.SameGeneration;
        self.active = replacement;
        return .{ .waf = current };
    }

    pub fn activeTransactionCount(self: *Runtime) RuntimeError!usize {
        lock(&self.mutex);
        defer self.mutex.unlock();
        return (self.active orelse return error.ShuttingDown).activeTransactionCount();
    }

    /// Destroy the runtime and its active generation. Callers must first stop
    /// creating transactions and separately reclaim every retired generation.
    pub fn deinit(self: *Runtime) RuntimeDeinitError!void {
        lock(&self.mutex);
        const active = self.active orelse unreachable;
        if (active.activeTransactionCount() != 0) {
            self.mutex.unlock();
            return error.TransactionsActive;
        }
        self.active = null;
        self.mutex.unlock();

        active.deinit() catch unreachable;
        const allocator = self.allocator;
        allocator.destroy(self);
    }
};

pub const RetiredGeneration = struct {
    waf: ?*Waf,

    pub fn activeTransactionCount(self: *const RetiredGeneration) usize {
        return (self.waf orelse return 0).activeTransactionCount();
    }

    pub fn tryReclaim(self: *RetiredGeneration) DeinitError!void {
        const waf = self.waf orelse return;
        try waf.deinit();
        self.waf = null;
    }

    pub fn isReclaimed(self: *const RetiredGeneration) bool {
        return self.waf == null;
    }
};

pub const TransactionError = error{
    InvalidLifecycle,
    Deinitialized,
    InvalidConnectionAddress,
    InvalidMethod,
    InvalidProtocol,
    RequestTargetTooLarge,
    InvalidHeader,
    TooManyHeaders,
    HeadersTooLarge,
    RequestBodyLimitExceeded,
    ResponseBodyLimitExceeded,
    InvalidInterventionStatus,
    InterventionAlreadyRecorded,
    TransactionTerminated,
    ClockBeforeUnixEpoch,
    MacroOutputTooLarge,
    MissingCompiledPlan,
    InvalidRuleReference,
    InvalidRuleChain,
    InvalidMatchContext,
    TooManyCaptures,
    InvalidEnvironmentName,
    InvalidActionValue,
    TooManyMatchIntents,
    MatchIntentStorageLimitExceeded,
    CollectionSizeOverflow,
    PersistentBackendNotConfigured,
    PersistentTimestampOverflow,
    ControlTooLate,
    UnsupportedRuntimeControl,
    UnsupportedIntervention,
} || variables.StoreError || collections.StoreError || collections.SelectorError || persistent.SessionError;

const Lifecycle = enum {
    created,
    connection,
    uri,
    request_headers,
    request_body_writing,
    request_body,
    response_headers,
    response_body_writing,
    response_body,
    logging,
    deinitialized,
};

pub const ArgumentOrigin = enum { query, body, path };
pub const PersistentInitialization = enum { loaded, already_initialized, failed_open };

pub const CaptureRange = struct {
    start: usize,
    end: usize,
};

/// Borrowed operator-match evidence. Capture indexes correspond directly to
/// TX.0 through TX.9; null entries represent unmatched optional groups.
pub const MatchContext = struct {
    name: []const u8,
    value: []const u8,
    source: collections.Source,
    captures: []const ?CaptureRange = &.{},
};

pub const MatchedRule = struct {
    rule: compiled_plan.RuleId,
    context: MatchContext,
};

pub const RuleProjection = struct {
    rule: compiled_plan.RuleId,
    chain_head: compiled_plan.RuleId,
    external_id: ?u64,
    severity: ?u8,
    tags_count: u32,
};

pub const MatchIntentId = enum(u32) { _ };

pub const MatchIntent = struct {
    rule: compiled_plan.RuleId,
    chain_head: compiled_plan.RuleId,
    external_id: ?u64,
    severity: ?u3,
    message: ?[]const u8,
    log_data: ?[]const u8,
    tags: []const []const u8,
    matched_name: []const u8,
    matched_value: []const u8,
    matched_source: collections.Source,
    log: bool,
    audit_log: bool,
    effects_applied: usize,
    captures_written: usize,
    pending_persistent_effects: usize,
    disruptive: compiled_plan.DisruptiveKind,
    disruptive_status: u16,
    disruptive_destination: ?[]const u8,
    allow_scope: action_config.AllowScope,
    decision_enforced: bool,
    skip: u32,
    skip_after_action: ?u32,
    skip_after_active: bool,
    skip_after_resume: ?compiled_plan.RuleId,
    multi_match: bool,
    controls_applied: usize,
};

pub const LocalEffectOutcome = struct {
    intent: MatchIntentId,
    projection: RuleProjection,
    effects_applied: usize,
    captures_written: usize,
    log: bool,
    audit_log: bool,
    pending_persistent_effects: usize,
    disruptive: compiled_plan.DisruptiveKind,
    disruptive_status: u16,
    allow_scope: action_config.AllowScope,
    decision_enforced: bool,
    skip: u32,
    skip_after_action: ?u32,
    skip_after_active: bool,
    skip_after_resume: ?compiled_plan.RuleId,
    multi_match: bool,
    controls_applied: usize,
};

pub const FlowState = struct {
    skip: u32 = 0,
    skip_after_action: ?u32 = null,
    skip_after_active: bool = false,
    skip_after_resume: ?compiled_plan.RuleId = null,
    allow_scope: ?action_config.AllowScope = null,
    phase: ?Phase = null,
};

pub const ControlState = struct {
    rule_engine: action_config.EngineMode,
    audit_engine: action_config.AuditEngine = .relevant_only,
    audit_parts: action_config.AuditParts = .{},
    force_request_body_variable: bool = false,
    request_body_access: bool = true,
    request_body_limit: usize,
    request_body_processor: ?action_config.BodyProcessor = null,
    response_body_access: bool = true,
};

pub const RuleExclusion = union(enum) {
    id: action_config.IdRange,
    tag: []const u8,
};

pub const TargetExclusion = struct {
    selector: RuleExclusion,
    target: []const u8,
};

fn deinitRuleExclusions(allocator: std.mem.Allocator, exclusions: *std.ArrayList(RuleExclusion)) void {
    for (exclusions.items) |exclusion| switch (exclusion) {
        .id => {},
        .tag => |value| allocator.free(value),
    };
    exclusions.deinit(allocator);
}

fn deinitTargetExclusions(allocator: std.mem.Allocator, exclusions: *std.ArrayList(TargetExclusion)) void {
    for (exclusions.items) |exclusion| {
        switch (exclusion.selector) {
            .id => {},
            .tag => |value| allocator.free(value),
        }
        allocator.free(exclusion.target);
    }
    exclusions.deinit(allocator);
}

pub const PersistentFailure = enum {
    unavailable,
    timeout,
    conflict_exhausted,
    corrupt_data,
    capacity_exceeded,
};

const capture_keys = [_][]const u8{ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9" };

fn appendProjectedValue(
    values: *[8]collections.Value,
    count: *usize,
    key: []const u8,
    value: []const u8,
    source: collections.Source,
) void {
    values[count.*] = .{ .collection = .rule, .key = key, .value = value, .source = source };
    count.* += 1;
}

const ShadowLookup = union(enum) { missing, removed, value: []const u8 };

const ShadowMutation = struct {
    collection: collections.Name,
    key: []u8,
    value: ?[]u8,
    source: collections.Source,
};

const ShadowBatch = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(ShadowMutation) = .empty,

    fn deinit(self: *ShadowBatch) void {
        for (self.items.items) |item| {
            self.allocator.free(item.key);
            if (item.value) |value| self.allocator.free(value);
        }
        self.items.deinit(self.allocator);
    }

    fn putOwned(
        self: *ShadowBatch,
        collection: collections.Name,
        key: []u8,
        value: ?[]u8,
        source: collections.Source,
    ) !void {
        for (self.items.items) |*item| {
            if (item.collection != collection or !collection.keysEqual(item.key, key)) continue;
            self.allocator.free(item.key);
            if (item.value) |prior| self.allocator.free(prior);
            item.* = .{ .collection = collection, .key = key, .value = value, .source = source };
            return;
        }
        try self.items.append(self.allocator, .{ .collection = collection, .key = key, .value = value, .source = source });
    }

    fn putCopy(
        self: *ShadowBatch,
        collection: collections.Name,
        key: []const u8,
        value: ?[]const u8,
        source: collections.Source,
    ) !void {
        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        const owned_value = if (value) |bytes| try self.allocator.dupe(u8, bytes) else null;
        errdefer if (owned_value) |bytes| self.allocator.free(bytes);
        try self.putOwned(collection, owned_key, owned_value, source);
    }

    fn lookup(self: *const ShadowBatch, collection: collections.Name, key: []const u8) ShadowLookup {
        for (self.items.items) |item| {
            if (item.collection != collection or !collection.keysEqual(item.key, key)) continue;
            return if (item.value) |value| .{ .value = value } else .removed;
        }
        return .missing;
    }

    fn first(self: *const ShadowBatch, collection: collections.Name) ?[]const u8 {
        for (self.items.items) |item| if (item.collection == collection) {
            if (item.value) |value| return value;
        };
        return null;
    }
};

const ScalarShadowMutation = struct {
    name: variables.Name,
    value: []u8,
    origin: variables.Origin,
    available_from: variables.Availability,
};

const ScalarShadowBatch = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(ScalarShadowMutation) = .empty,

    fn deinit(self: *ScalarShadowBatch) void {
        for (self.items.items) |item| self.allocator.free(item.value);
        self.items.deinit(self.allocator);
    }

    fn putOwned(
        self: *ScalarShadowBatch,
        name: variables.Name,
        value: []u8,
        origin: variables.Origin,
        available_from: variables.Availability,
    ) !void {
        for (self.items.items) |*item| {
            if (item.name != name) continue;
            self.allocator.free(item.value);
            item.* = .{ .name = name, .value = value, .origin = origin, .available_from = available_from };
            return;
        }
        try self.items.append(self.allocator, .{
            .name = name,
            .value = value,
            .origin = origin,
            .available_from = available_from,
        });
    }

    fn get(self: *const ScalarShadowBatch, name: variables.Name) ?[]const u8 {
        for (self.items.items) |item| if (item.name == name) return item.value;
        return null;
    }
};

const PreparedMatchIntent = struct {
    allocator: std.mem.Allocator,
    value: MatchIntent,
    owned_bytes: usize,

    fn deinit(self: *PreparedMatchIntent) void {
        deinitMatchIntent(self.allocator, &self.value);
        self.* = undefined;
    }
};

fn deinitMatchIntent(allocator: std.mem.Allocator, intent: *MatchIntent) void {
    if (intent.message) |value| allocator.free(value);
    if (intent.log_data) |value| allocator.free(value);
    for (intent.tags) |value| allocator.free(value);
    allocator.free(intent.tags);
    allocator.free(intent.matched_name);
    allocator.free(intent.matched_value);
    if (intent.disruptive_destination) |value| allocator.free(value);
}

fn effectiveDisruptiveStatus(decision: compiled_plan.DisruptiveDecision) u16 {
    return switch (decision.kind) {
        .redirect => switch (decision.status) {
            301, 302, 303, 307 => decision.status,
            else => 302,
        },
        .proxy => if (decision.status_explicit) decision.status else 200,
        else => decision.status,
    };
}

/// Isolated per-request mutable state.
///
/// The initial implementation records only bounded metadata and body byte
/// counts. Connector-controlled buffering and spooling are layered on this
/// contract; `write*Body` never implies unbounded in-memory retention.
pub const Transaction = struct {
    waf: *const Waf,
    lifecycle: Lifecycle = .created,
    request_header_count: usize = 0,
    request_header_bytes: usize = 0,
    response_header_count: usize = 0,
    response_header_bytes: usize = 0,
    request_body_bytes: usize = 0,
    response_body_bytes: usize = 0,
    pending_intervention: ?Intervention = null,
    scalar_variables: variables.Store,
    collection_variables: collections.Store,
    persistent_session: ?persistent.Session,
    last_persistent_failure: ?PersistentFailure = null,
    persistent_failed_open: u8 = 0,
    match_intents: std.ArrayList(MatchIntent) = .empty,
    match_intent_bytes: usize = 0,
    flow_state: FlowState = .{},
    control_state: ControlState,
    rule_exclusions: std.ArrayList(RuleExclusion) = .empty,
    target_exclusions: std.ArrayList(TargetExclusion) = .empty,
    rule_exclusion_bytes: usize = 0,
    phase_interrupted: bool = false,
    transaction_terminated: bool = false,
    started_real_nanoseconds: i96,
    started_awake_nanoseconds: i96,
    sequence: u64,
    highest_severity: u8 = 255,
    args_combined_size: usize = 0,
    files_combined_size: u64 = 0,

    pub fn compiledPlan(self: *const Transaction) ?*const compiled_plan.Plan {
        return self.waf.compiledPlan();
    }

    /// Atomically replace the transaction-local RULE projection with typed
    /// metadata from the chain head. Macro-bearing text remains in its
    /// compiled source form here so subsequent effects can resolve RULE.*
    /// before final event expansion.
    pub fn projectRuleMetadata(self: *Transaction, rule_id: compiled_plan.RuleId) TransactionError!RuleProjection {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const plan = self.compiledPlan() orelse return error.MissingCompiledPlan;
        const rule_index: usize = @backingInt(rule_id);
        if (rule_index >= plan.rules.len) return error.InvalidRuleReference;
        const selected = plan.rules[rule_index];
        const head_index: usize = @backingInt(selected.chain_head);
        if (head_index >= plan.rules.len) return error.InvalidRuleReference;
        const head = plan.rules[head_index];
        const metadata = head.metadata;
        var values: [8]collections.Value = undefined;
        var count: usize = 0;
        var id_buffer: [24]u8 = undefined;
        var severity_buffer: [3]u8 = undefined;
        var maturity_buffer: [3]u8 = undefined;
        var accuracy_buffer: [3]u8 = undefined;
        const source: collections.Source = .{ .origin = .rule, .offset = 0, .length = 0 };
        if (head.external_id) |external_id| {
            const value = std.fmt.bufPrint(&id_buffer, "{d}", .{external_id}) catch unreachable;
            appendProjectedValue(&values, &count, "id", value, source);
        }
        if (metadata.revision) |text| appendProjectedValue(&values, &count, "rev", plan.string(text.value).?, source);
        if (metadata.message) |text| appendProjectedValue(&values, &count, "msg", plan.string(text.value).?, source);
        if (metadata.log_data) |text| appendProjectedValue(&values, &count, "logdata", plan.string(text.value).?, source);
        if (metadata.severity) |severity| {
            const value = std.fmt.bufPrint(&severity_buffer, "{d}", .{@backingInt(severity)}) catch unreachable;
            appendProjectedValue(&values, &count, "severity", value, source);
        }
        if (metadata.maturity) |maturity| {
            const value = std.fmt.bufPrint(&maturity_buffer, "{d}", .{maturity}) catch unreachable;
            appendProjectedValue(&values, &count, "maturity", value, source);
        }
        if (metadata.accuracy) |accuracy| {
            const value = std.fmt.bufPrint(&accuracy_buffer, "{d}", .{accuracy}) catch unreachable;
            appendProjectedValue(&values, &count, "accuracy", value, source);
        }
        if (metadata.version) |text| appendProjectedValue(&values, &count, "ver", plan.string(text.value).?, source);
        try self.collection_variables.replaceCollection(.rule, values[0..count]);
        return .{
            .rule = rule_id,
            .chain_head = selected.chain_head,
            .external_id = head.external_id,
            .severity = if (metadata.severity) |severity| @backingInt(severity) else null,
            .tags_count = metadata.tags_count,
        };
    }

    /// Validate all borrowed ranges first, then atomically replace TX.0–TX.9.
    /// Unmatched and omitted groups clear stale capture state.
    pub fn replaceCaptures(self: *Transaction, context: MatchContext) TransactionError!usize {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (context.name.len == 0 or context.name.len > self.waf.config.limits.max_match_name_bytes or
            context.value.len > self.waf.config.limits.max_match_value_bytes)
        {
            return error.InvalidMatchContext;
        }
        if (context.captures.len > self.waf.config.limits.max_captures) return error.TooManyCaptures;
        var values: [10]collections.Value = undefined;
        var count: usize = 0;
        for (context.captures, 0..) |maybe_range, capture_index| {
            const range = maybe_range orelse continue;
            if (range.start > range.end or range.end > context.value.len) return error.InvalidMatchContext;
            const offset = std.math.add(usize, context.source.offset, range.start) catch return error.InvalidMatchContext;
            const length = range.end - range.start;
            _ = std.math.add(usize, offset, length) catch return error.InvalidMatchContext;
            values[count] = .{
                .collection = .tx,
                .key = capture_keys[capture_index],
                .value = context.value[range.start..range.end],
                .source = .{ .origin = context.source.origin, .offset = offset, .length = length },
            };
            count += 1;
        }
        try self.collection_variables.replaceKeys(.tx, &capture_keys, values[0..count]);
        return count;
    }

    /// Preflight and atomically commit RULE metadata, captures, ENV writes,
    /// and TX setvar effects for one matched rule/member. Persistent effects
    /// are counted for the persistence commit stage and never substituted by
    /// local storage.
    pub fn applyLocalMatchedRule(
        self: *Transaction,
        rule_id: compiled_plan.RuleId,
        context: MatchContext,
    ) TransactionError!LocalEffectOutcome {
        return self.applyMatchedRuleMode(rule_id, context, false);
    }

    /// Apply local and configured persistent non-disruptive effects. Backend
    /// mutations remain staged in the request session until the lifecycle
    /// flush boundary; all transaction-local projections commit together.
    pub fn applyMatchedRule(
        self: *Transaction,
        rule_id: compiled_plan.RuleId,
        context: MatchContext,
    ) TransactionError!LocalEffectOutcome {
        return self.applyMatchedRuleMode(rule_id, context, true);
    }

    /// Apply a fully matched chain as one ordered, atomic effect batch. The
    /// first entry must be the chain head and every compiled `chain_next`
    /// member must appear exactly once in order.
    pub fn applyLocalMatchedChain(
        self: *Transaction,
        matches: []const MatchedRule,
    ) TransactionError!LocalEffectOutcome {
        return self.applyMatchedRules(matches, false);
    }

    pub fn applyMatchedChain(
        self: *Transaction,
        matches: []const MatchedRule,
    ) TransactionError!LocalEffectOutcome {
        return self.applyMatchedRules(matches, true);
    }

    fn applyMatchedRuleMode(
        self: *Transaction,
        rule_id: compiled_plan.RuleId,
        context: MatchContext,
        include_persistent: bool,
    ) TransactionError!LocalEffectOutcome {
        const matches = [_]MatchedRule{.{ .rule = rule_id, .context = context }};
        return self.applyMatchedRules(&matches, include_persistent);
    }

    fn applyMatchedRules(
        self: *Transaction,
        matches: []const MatchedRule,
        include_persistent: bool,
    ) TransactionError!LocalEffectOutcome {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const plan = self.compiledPlan() orelse return error.MissingCompiledPlan;
        try self.validateMatchedChain(plan, matches);
        const rule_id = matches[0].rule;
        const context = matches[matches.len - 1].context;
        const rule_index: usize = @backingInt(rule_id);
        const selected = plan.rules[rule_index];
        const head_index: usize = @backingInt(selected.chain_head);
        const head = plan.rules[head_index];
        if (head.disruptive.kind == .proxy and !self.waf.config.intervention_capabilities.proxy)
            return error.UnsupportedIntervention;
        var batch: ShadowBatch = .{ .allocator = self.waf.allocator };
        defer batch.deinit();
        var scalar_batch: ScalarShadowBatch = .{ .allocator = self.waf.allocator };
        defer scalar_batch.deinit();
        try self.stageDuration(&scalar_batch);
        const persistence_checkpoint = if (include_persistent)
            if (self.persistent_session) |*session| session.checkpoint() else null
        else
            null;
        errdefer if (persistence_checkpoint) |checkpoint_value| {
            self.persistent_session.?.rollback(checkpoint_value);
        };
        const projection = try self.stageRuleProjection(&batch, rule_id, selected, head, plan);
        if (self.match_intents.items.len == self.waf.config.limits.max_match_intents)
            return error.TooManyMatchIntents;
        const intent_id: MatchIntentId = @fromBackingInt(@as(u32, @intCast(self.match_intents.items.len)));
        var result: LocalEffectOutcome = .{
            .intent = intent_id,
            .projection = projection,
            .effects_applied = 0,
            .captures_written = 0,
            .log = false,
            .audit_log = false,
            .pending_persistent_effects = 0,
            .disruptive = head.disruptive.kind,
            .disruptive_status = effectiveDisruptiveStatus(head.disruptive),
            .allow_scope = head.disruptive.allow_scope,
            .decision_enforced = self.waf.config.mode == .enabled,
            .skip = head.flow.skip,
            .skip_after_action = head.flow.skip_after_action,
            .skip_after_active = false,
            .skip_after_resume = null,
            .multi_match = head.flow.multi_match,
            .controls_applied = 0,
        };
        const source: collections.Source = .{ .origin = .rule, .offset = 0, .length = 0 };
        for (matches) |matched| {
            const member = plan.rules[@backingInt(matched.rule)];
            if (member.effects_start + member.effects_count > plan.nondisruptive_effects.len)
                return error.InvalidRuleReference;
            for (plan.nondisruptive_effects[member.effects_start..][0..member.effects_count]) |effect| {
                switch (effect.kind) {
                    .capture => {
                        result.captures_written = try self.stageCaptures(&batch, matched.context);
                        result.effects_applied += 1;
                    },
                    .log => {
                        result.log = true;
                        result.effects_applied += 1;
                    },
                    .nolog => {
                        result.log = false;
                        result.effects_applied += 1;
                    },
                    .auditlog => {
                        result.audit_log = true;
                        result.effects_applied += 1;
                    },
                    .noauditlog => {
                        result.audit_log = false;
                        result.effects_applied += 1;
                    },
                    .setenv => {
                        const name = try self.expandEffectTextStaged(effect.name orelse return error.InvalidRuleReference, &batch, &scalar_batch, plan);
                        errdefer self.waf.allocator.free(name);
                        if (!validEnvironmentName(name)) return error.InvalidEnvironmentName;
                        const value = try self.expandEffectTextStaged(effect.value orelse return error.InvalidRuleReference, &batch, &scalar_batch, plan);
                        errdefer self.waf.allocator.free(value);
                        try batch.putOwned(.env, name, value, source);
                        result.effects_applied += 1;
                    },
                    .setvar => {
                        const configured_collection = effect.collection orelse return error.InvalidRuleReference;
                        if (configured_collection.persistent() and !include_persistent) {
                            result.pending_persistent_effects += 1;
                            continue;
                        }
                        const collection_name = effectCollectionName(configured_collection);
                        const name = try self.expandEffectTextStaged(effect.name orelse return error.InvalidRuleReference, &batch, &scalar_batch, plan);
                        errdefer self.waf.allocator.free(name);
                        if (name.len == 0) return error.InvalidActionValue;
                        const operation = effect.operation orelse return error.InvalidRuleReference;
                        const expanded_operand = if (effect.value) |value|
                            try self.expandEffectTextStaged(value, &batch, &scalar_batch, plan)
                        else
                            null;
                        defer if (expanded_operand) |value| self.waf.allocator.free(value);
                        const next = try self.evaluateSetVar(&batch, collection_name, name, operation, expanded_operand);
                        errdefer if (next) |value| self.waf.allocator.free(value);
                        if (configured_collection.persistent()) {
                            const namespace = persistentNamespace(configured_collection).?;
                            if (!self.persistentNamespaceFailedOpen(namespace)) {
                                try self.stagePersistentSetVar(namespace, name, operation, expanded_operand);
                                try batch.putOwned(collection_name, name, next, source);
                            } else {
                                self.waf.allocator.free(name);
                                if (next) |value| self.waf.allocator.free(value);
                            }
                        } else {
                            try batch.putOwned(.tx, name, next, source);
                        }
                        result.effects_applied += 1;
                    },
                    .initcol => {
                        if (!include_persistent) {
                            result.pending_persistent_effects += 1;
                            continue;
                        }
                        const namespace = persistentNamespace(effect.collection orelse return error.InvalidRuleReference) orelse
                            return error.InvalidRuleReference;
                        const key = try self.expandEffectTextStaged(effect.value orelse return error.InvalidRuleReference, &batch, &scalar_batch, plan);
                        defer self.waf.allocator.free(key);
                        if (key.len == 0) return error.InvalidActionValue;
                        _ = try self.initializePersistentStaged(&batch, namespace, key);
                        result.effects_applied += 1;
                    },
                    .setuid, .setsid, .setrsc => {
                        if (!include_persistent) {
                            result.pending_persistent_effects += 1;
                            continue;
                        }
                        const namespace = persistentNamespace(effect.collection orelse return error.InvalidRuleReference) orelse
                            return error.InvalidRuleReference;
                        const key = try self.expandEffectTextStaged(effect.value orelse return error.InvalidRuleReference, &batch, &scalar_batch, plan);
                        errdefer self.waf.allocator.free(key);
                        if (key.len == 0) return error.InvalidActionValue;
                        _ = try self.initializePersistentStaged(&batch, namespace, key);
                        try scalar_batch.putOwned(bindingScalar(namespace), key, .rule, .request_headers);
                        result.effects_applied += 1;
                    },
                    .expirevar => {
                        if (!include_persistent) {
                            result.pending_persistent_effects += 1;
                            continue;
                        }
                        const namespace = persistentNamespace(effect.collection orelse return error.InvalidRuleReference) orelse
                            return error.InvalidRuleReference;
                        if (self.persistentNamespaceFailedOpen(namespace)) {
                            result.effects_applied += 1;
                            continue;
                        }
                        const name = try self.expandEffectTextStaged(effect.name orelse return error.InvalidRuleReference, &batch, &scalar_batch, plan);
                        defer self.waf.allocator.free(name);
                        const seconds_text = try self.expandEffectTextStaged(effect.value orelse return error.InvalidRuleReference, &batch, &scalar_batch, plan);
                        defer self.waf.allocator.free(seconds_text);
                        const seconds = action_config.parsePositiveU32(seconds_text) catch return error.InvalidActionValue;
                        try self.stagePersistentExpiry(namespace, name, seconds);
                        result.effects_applied += 1;
                    },
                    .deprecatevar => {
                        if (!include_persistent) {
                            result.pending_persistent_effects += 1;
                            continue;
                        }
                        const configured_collection = effect.collection orelse return error.InvalidRuleReference;
                        const namespace = persistentNamespace(configured_collection) orelse return error.InvalidRuleReference;
                        if (self.persistentNamespaceFailedOpen(namespace)) {
                            result.effects_applied += 1;
                            continue;
                        }
                        const collection_name = effectCollectionName(configured_collection);
                        const name = try self.expandEffectTextStaged(effect.name orelse return error.InvalidRuleReference, &batch, &scalar_batch, plan);
                        errdefer self.waf.allocator.free(name);
                        if (name.len == 0) return error.InvalidActionValue;
                        const amount_text = try self.expandEffectTextStaged(effect.value orelse return error.InvalidRuleReference, &batch, &scalar_batch, plan);
                        defer self.waf.allocator.free(amount_text);
                        const period_text = try self.expandEffectTextStaged(effect.auxiliary orelse return error.InvalidRuleReference, &batch, &scalar_batch, plan);
                        defer self.waf.allocator.free(period_text);
                        const amount = action_config.parsePositiveU32(amount_text) catch return error.InvalidActionValue;
                        const period_seconds = action_config.parsePositiveU32(period_text) catch return error.InvalidActionValue;
                        const current_text: ?[]const u8 = switch (batch.lookup(collection_name, name)) {
                            .value => |value| value,
                            .removed => null,
                            .missing => if (self.collection_variables.first(collection_name, name)) |value| value.value else null,
                        };
                        const period_ns = std.math.mul(i64, @as(i64, period_seconds), std.time.ns_per_s) catch
                            return error.PersistentTimestampOverflow;
                        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
                        const deprecation = try session.deprecate(
                            namespace,
                            name,
                            if (current_text) |value| persistent.parseNumericOrZero(value) else null,
                            amount,
                            period_ns,
                            try self.persistentNow(),
                        );
                        if (deprecation) |applied| {
                            const next = try std.fmt.allocPrint(self.waf.allocator, "{d}", .{applied.value});
                            errdefer self.waf.allocator.free(next);
                            try batch.putOwned(collection_name, name, next, source);
                        } else {
                            self.waf.allocator.free(name);
                        }
                        result.effects_applied += 1;
                    },
                }
            }
        }

        var staged_controls = self.control_state;
        var staged_exclusions: std.ArrayList(RuleExclusion) = .empty;
        defer deinitRuleExclusions(self.waf.allocator, &staged_exclusions);
        var staged_target_exclusions: std.ArrayList(TargetExclusion) = .empty;
        defer deinitTargetExclusions(self.waf.allocator, &staged_target_exclusions);
        var staged_exclusion_bytes: usize = 0;
        result.controls_applied = try self.stageRuntimeControls(
            matches,
            &staged_controls,
            &staged_exclusions,
            &staged_target_exclusions,
            &staged_exclusion_bytes,
            &batch,
            &scalar_batch,
            plan,
        );
        result.decision_enforced = staged_controls.rule_engine == .on;
        const has_enforced_intervention = result.decision_enforced and switch (head.disruptive.kind) {
            .deny, .drop, .proxy, .redirect => true,
            .pass, .allow => false,
        };
        if (has_enforced_intervention and self.pending_intervention != null)
            return error.InterventionAlreadyRecorded;
        const skip_after = try self.resolveSkipAfter(selected.chain_head, head, &batch, &scalar_batch, plan);
        result.skip_after_active = skip_after.active;
        result.skip_after_resume = skip_after.resume_rule;
        var prepared_intent = try self.prepareMatchIntent(rule_id, selected, head, context, result, &batch, &scalar_batch, plan);
        var intent_committed = false;
        defer if (!intent_committed) prepared_intent.deinit();
        if (prepared_intent.owned_bytes > self.waf.config.limits.max_match_intent_bytes -| self.match_intent_bytes)
            return error.MatchIntentStorageLimitExceeded;
        try self.match_intents.ensureUnusedCapacity(self.waf.allocator, 1);
        try self.rule_exclusions.ensureUnusedCapacity(self.waf.allocator, staged_exclusions.items.len);
        try self.target_exclusions.ensureUnusedCapacity(self.waf.allocator, staged_target_exclusions.items.len);

        const keys = try self.waf.allocator.alloc(collections.Key, batch.items.items.len);
        defer self.waf.allocator.free(keys);
        var value_count: usize = 0;
        for (batch.items.items, keys) |item, *key| {
            key.* = .{ .collection = item.collection, .key = item.key };
            value_count += @intFromBool(item.value != null);
        }
        const values = try self.waf.allocator.alloc(collections.Value, value_count);
        defer self.waf.allocator.free(values);
        var value_index: usize = 0;
        for (batch.items.items) |item| if (item.value) |value| {
            values[value_index] = .{ .collection = item.collection, .key = item.key, .value = value, .source = item.source };
            value_index += 1;
        };
        const scalar_values = try self.waf.allocator.alloc(variables.SetValue, scalar_batch.items.items.len);
        defer self.waf.allocator.free(scalar_values);
        for (scalar_batch.items.items, scalar_values) |item, *value| value.* = .{
            .name = item.name,
            .value = item.value,
            .origin = item.origin,
            .available_from = item.available_from,
        };
        var prepared_scalars = try self.scalar_variables.prepareBatch(
            scalar_values,
            self.waf.config.limits.max_scalar_value_bytes,
            self.waf.config.limits.max_scalar_storage_bytes,
        );
        defer prepared_scalars.deinit();
        try self.collection_variables.replaceKeyGroups(keys, values);
        self.scalar_variables.commitPreparedBatch(&prepared_scalars);
        self.match_intents.appendAssumeCapacity(prepared_intent.value);
        self.match_intent_bytes += prepared_intent.owned_bytes;
        intent_committed = true;
        self.control_state = staged_controls;
        self.rule_exclusions.appendSliceAssumeCapacity(staged_exclusions.items);
        self.target_exclusions.appendSliceAssumeCapacity(staged_target_exclusions.items);
        self.rule_exclusion_bytes += staged_exclusion_bytes;
        staged_exclusions.clearRetainingCapacity();
        staged_target_exclusions.clearRetainingCapacity();
        const committed_intent = &self.match_intents.items[self.match_intents.items.len - 1];
        self.commitDecision(head, committed_intent);
        return result;
    }

    const SkipAfterResolution = struct {
        active: bool = false,
        resume_rule: ?compiled_plan.RuleId = null,
    };

    fn stageRuntimeControls(
        self: *Transaction,
        matches: []const MatchedRule,
        staged: *ControlState,
        staged_exclusions: *std.ArrayList(RuleExclusion),
        staged_target_exclusions: *std.ArrayList(TargetExclusion),
        staged_exclusion_bytes: *usize,
        batch: *const ShadowBatch,
        scalar_batch: *const ScalarShadowBatch,
        plan: *const compiled_plan.Plan,
    ) TransactionError!usize {
        var count: usize = 0;
        for (matches) |matched| {
            const rule = plan.rules[@backingInt(matched.rule)];
            if (rule.controls_start + rule.controls_count > plan.runtime_controls.len)
                return error.InvalidRuleReference;
            for (plan.runtime_controls[rule.controls_start..][0..rule.controls_count]) |control| {
                const expanded = try self.expandEffectTextStaged(control.value, batch, scalar_batch, plan);
                defer self.waf.allocator.free(expanded);
                switch (control.kind) {
                    .rule_engine => staged.rule_engine = action_config.parseEngineMode(expanded) catch
                        return error.InvalidActionValue,
                    .audit_engine => staged.audit_engine = action_config.parseAuditEngine(expanded) catch
                        return error.InvalidActionValue,
                    .force_request_body_variable => {
                        if (self.currentPhase() != .request_headers) return error.ControlTooLate;
                        staged.force_request_body_variable = action_config.parseBoolean(expanded) catch
                            return error.InvalidActionValue;
                    },
                    .request_body_access => {
                        if (self.currentPhase() != .request_headers) return error.ControlTooLate;
                        staged.request_body_access = action_config.parseBoolean(expanded) catch
                            return error.InvalidActionValue;
                    },
                    .request_body_limit => {
                        if (self.currentPhase() != .request_headers) return error.ControlTooLate;
                        staged.request_body_limit = action_config.parsePositiveUsize(expanded) catch
                            return error.InvalidActionValue;
                    },
                    .request_body_processor => {
                        if (self.currentPhase() != .request_headers) return error.ControlTooLate;
                        staged.request_body_processor = action_config.parseBodyProcessor(expanded) catch
                            return error.InvalidActionValue;
                    },
                    .response_body_access => {
                        const phase = self.currentPhase() orelse return error.InvalidLifecycle;
                        if (@backingInt(phase) > @backingInt(Phase.response_headers)) return error.ControlTooLate;
                        staged.response_body_access = action_config.parseBoolean(expanded) catch
                            return error.InvalidActionValue;
                    },
                    .rule_remove_by_id => {
                        if (self.rule_exclusions.items.len + self.target_exclusions.items.len +
                            staged_exclusions.items.len + staged_target_exclusions.items.len ==
                            self.waf.config.limits.max_runtime_exclusions)
                        {
                            return error.CapacityExceeded;
                        }
                        try staged_exclusions.append(self.waf.allocator, .{
                            .id = action_config.parseIdRange(expanded) catch return error.InvalidActionValue,
                        });
                    },
                    .rule_remove_by_tag => {
                        if (expanded.len == 0) return error.InvalidActionValue;
                        if (self.rule_exclusions.items.len + self.target_exclusions.items.len +
                            staged_exclusions.items.len + staged_target_exclusions.items.len ==
                            self.waf.config.limits.max_runtime_exclusions or
                            expanded.len > self.waf.config.limits.max_runtime_exclusion_bytes -| self.rule_exclusion_bytes -| staged_exclusion_bytes.*)
                        {
                            return error.CapacityExceeded;
                        }
                        const owned = try self.waf.allocator.dupe(u8, expanded);
                        staged_exclusions.append(self.waf.allocator, .{ .tag = owned }) catch |err| {
                            self.waf.allocator.free(owned);
                            return err;
                        };
                        staged_exclusion_bytes.* += owned.len;
                    },
                    .rule_remove_target_by_id, .rule_remove_target_by_tag => {
                        const parsed = action_config.parseTargetControl(expanded) catch return error.InvalidActionValue;
                        if (std.mem.indexOf(u8, parsed.target, ":/") != null and std.mem.endsWith(u8, parsed.target, "/"))
                            return error.UnsupportedRuntimeControl;
                        const selector_bytes = if (control.kind == .rule_remove_target_by_tag) parsed.selector.len else 0;
                        const added_bytes = std.math.add(usize, selector_bytes, parsed.target.len) catch return error.CapacityExceeded;
                        if (self.rule_exclusions.items.len + self.target_exclusions.items.len +
                            staged_exclusions.items.len + staged_target_exclusions.items.len ==
                            self.waf.config.limits.max_runtime_exclusions or
                            added_bytes > self.waf.config.limits.max_runtime_exclusion_bytes -| self.rule_exclusion_bytes -| staged_exclusion_bytes.*)
                        {
                            return error.CapacityExceeded;
                        }
                        const id_range = if (control.kind == .rule_remove_target_by_id)
                            action_config.parseIdRange(parsed.selector) catch return error.InvalidActionValue
                        else
                            null;
                        const owned_target = try self.waf.allocator.dupe(u8, parsed.target);
                        const selector: RuleExclusion = if (control.kind == .rule_remove_target_by_id)
                            .{ .id = id_range.? }
                        else blk: {
                            const owned_tag = self.waf.allocator.dupe(u8, parsed.selector) catch |err| {
                                self.waf.allocator.free(owned_target);
                                return err;
                            };
                            break :blk .{ .tag = owned_tag };
                        };
                        staged_target_exclusions.append(self.waf.allocator, .{
                            .selector = selector,
                            .target = owned_target,
                        }) catch |err| {
                            switch (selector) {
                                .id => {},
                                .tag => |value| self.waf.allocator.free(value),
                            }
                            self.waf.allocator.free(owned_target);
                            return err;
                        };
                        staged_exclusion_bytes.* += added_bytes;
                    },
                    .audit_log_parts => staged.audit_parts = action_config.applyAuditParts(staged.audit_parts, expanded) catch
                        return error.InvalidActionValue,
                }
                count += 1;
            }
        }
        return count;
    }

    fn resolveSkipAfter(
        self: *Transaction,
        rule_id: compiled_plan.RuleId,
        head: compiled_plan.Rule,
        batch: *const ShadowBatch,
        scalar_batch: *const ScalarShadowBatch,
        plan: *const compiled_plan.Plan,
    ) TransactionError!SkipAfterResolution {
        const target_index = head.flow.skip_after_target orelse return .{};
        if (target_index >= plan.skip_after_targets.len) return error.InvalidRuleReference;
        const target = plan.skip_after_targets[target_index];
        if (target.rule != rule_id or target.action_index != head.flow.skip_after_action)
            return error.InvalidRuleReference;
        if (!target.dynamic) return .{ .active = true, .resume_rule = target.resume_rule };
        const value = head.flow.skip_after_value orelse return error.InvalidRuleReference;
        const expanded = try self.expandEffectTextStaged(value, batch, scalar_batch, plan);
        defer self.waf.allocator.free(expanded);
        const resolved = plan.resolveMarkerAfter(rule_id, expanded) orelse return .{};
        return .{ .active = true, .resume_rule = resolved.resume_rule };
    }

    fn commitDecision(self: *Transaction, head: compiled_plan.Rule, intent: *const MatchIntent) void {
        self.flow_state.phase = self.currentPhase();
        self.flow_state.skip = if (!intent.skip_after_active) head.flow.skip else 0;
        self.flow_state.skip_after_action = head.flow.skip_after_action;
        self.flow_state.skip_after_active = intent.skip_after_active;
        self.flow_state.skip_after_resume = intent.skip_after_resume;
        if (head.disruptive.kind == .allow) {
            if (intent.decision_enforced) {
                self.flow_state.allow_scope = head.disruptive.allow_scope;
                self.phase_interrupted = true;
            }
            return;
        }
        const action: Intervention.Action = switch (head.disruptive.kind) {
            .deny => .deny,
            .drop => .drop,
            .redirect => .redirect,
            .proxy => .proxy,
            .pass, .allow => return,
        };
        if (self.pending_intervention == null) self.pending_intervention = .{
            .action = action,
            .status = intent.disruptive_status,
            .rule_id = if (head.external_id) |value| if (value <= std.math.maxInt(u32)) @intCast(value) else null else null,
            .destination = intent.disruptive_destination,
            .enforced = intent.decision_enforced,
        };
        if (intent.decision_enforced) {
            self.phase_interrupted = true;
            self.transaction_terminated = action == .drop;
        }
    }

    pub fn processConnection(
        self: *Transaction,
        client_address: []const u8,
        client_port: u16,
        server_address: []const u8,
        server_port: u16,
    ) TransactionError!void {
        try self.require(.created);
        if (!validAddress(client_address) or !validAddress(server_address) or client_port == 0 or server_port == 0) {
            return error.InvalidConnectionAddress;
        }
        try self.setScalar(.remote_addr, client_address, .connection, .connection);
        try self.setScalarUnsigned(.remote_port, client_port, .connection, .connection);
        try self.setScalar(.server_addr, server_address, .connection, .connection);
        try self.setScalarUnsigned(.server_port, server_port, .connection, .connection);
        try self.initializeCompatibilityScalars();
        self.lifecycle = .connection;
    }

    pub fn processUri(
        self: *Transaction,
        uri: []const u8,
        method: []const u8,
        protocol: []const u8,
    ) TransactionError!void {
        try self.require(.connection);
        if (uri.len == 0 or uri.len > self.waf.config.limits.max_request_target_bytes) {
            return error.RequestTargetTooLarge;
        }
        if (!validToken(method)) return error.InvalidMethod;
        if (!validProtocol(protocol)) return error.InvalidProtocol;
        try self.setScalar(.request_uri_raw, uri, .request_target, .request_headers);
        try self.setScalar(.request_uri, uri, .request_target, .request_headers);
        const query_start = std.mem.indexOfScalar(u8, uri, '?');
        const filename = if (query_start) |index| uri[0..index] else uri;
        const query = if (query_start) |index| uri[index + 1 ..] else "";
        try self.setScalar(.request_filename, filename, .request_target, .request_headers);
        try self.setScalar(.path_info, filename, .request_target, .request_headers);
        const slash = std.mem.lastIndexOfAny(u8, filename, "/\\");
        const basename = if (slash) |index| filename[index + 1 ..] else filename;
        try self.setScalar(.request_basename, basename, .request_target, .request_headers);
        try self.setScalar(.query_string, query, .request_target, .request_headers);
        try self.setScalar(.request_method, method, .request_target, .request_headers);
        try self.setScalar(.request_protocol, protocol, .request_target, .request_headers);
        const request_line = try std.fmt.allocPrint(self.waf.allocator, "{s} {s} {s}", .{ method, uri, protocol });
        defer self.waf.allocator.free(request_line);
        try self.setScalar(.request_line, request_line, .request_target, .request_headers);
        self.lifecycle = .uri;
    }

    pub fn addRequestHeader(self: *Transaction, name: []const u8, value: []const u8) TransactionError!void {
        try self.require(.uri);
        const added = try self.validateHeader(name, value, self.request_header_count, self.request_header_bytes);
        const name_source: collections.Source = .{
            .origin = .request_header,
            .offset = self.request_header_bytes,
            .length = name.len,
        };
        const value_source: collections.Source = .{
            .origin = .request_header,
            .offset = self.request_header_bytes + name.len + 2,
            .length = value.len,
        };
        try self.collection_variables.addPair(
            .{ .collection = .request_headers, .key = name, .value = value, .source = value_source },
            .{ .collection = .request_headers_names, .key = name, .value = name, .source = name_source },
        );
        if (std.ascii.eqlIgnoreCase(name, "content-type")) {
            if (startsWithIgnoreCase(value, "multipart/form-data")) {
                try self.setScalar(.reqbody_processor, "MULTIPART", .request_header, .request_headers);
            } else if (startsWithIgnoreCase(value, "application/x-www-form-urlencoded")) {
                try self.setScalar(.reqbody_processor, "URLENCODED", .request_header, .request_headers);
            } else if (startsWithIgnoreCase(value, "application/json")) {
                try self.setScalar(.reqbody_processor, "JSON", .request_header, .request_headers);
            } else if (startsWithIgnoreCase(value, "application/xml") or startsWithIgnoreCase(value, "text/xml")) {
                try self.setScalar(.reqbody_processor, "XML", .request_header, .request_headers);
            }
        } else if (std.ascii.eqlIgnoreCase(name, "authorization")) {
            const end = std.mem.indexOfScalar(u8, value, ' ') orelse value.len;
            if (end != 0) try self.setScalar(.auth_type, value[0..end], .request_header, .request_headers);
        } else if (std.ascii.eqlIgnoreCase(name, "host")) {
            const host = hostWithoutPort(value);
            if (host.len != 0) try self.setScalar(.server_name, host, .request_header, .request_headers);
        }
        self.request_header_count += 1;
        self.request_header_bytes += added;
    }

    pub fn processRequestHeaders(self: *Transaction) TransactionError!void {
        try self.require(.uri);
        self.phase_interrupted = false;
        self.lifecycle = .request_headers;
    }

    pub fn writeRequestBody(self: *Transaction, chunk: []const u8) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body_writing });
        if (chunk.len > self.control_state.request_body_limit -| self.request_body_bytes) {
            return error.RequestBodyLimitExceeded;
        }
        const next_body_bytes = self.request_body_bytes + chunk.len;
        try self.setScalarUnsigned(.request_body_length, next_body_bytes, .request_body, .request_body);
        self.request_body_bytes = next_body_bytes;
        self.lifecycle = .request_body_writing;
    }

    pub fn processRequestBody(self: *Transaction) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body_writing });
        if (self.scalar_variables.get(.request_body_length, .request_body) == null) {
            try self.setScalarUnsigned(.request_body_length, 0, .request_body, .request_body);
        }
        try self.setFlagIfMissing(.reqbody_error, false, .request_body, .request_body);
        try self.setFlagIfMissing(.reqbody_processor_error, false, .request_body, .request_body);
        try self.setFlagIfMissing(.inbound_data_error, false, .request_body, .request_body);
        self.phase_interrupted = false;
        self.lifecycle = .request_body;
    }

    pub fn addResponseHeader(self: *Transaction, name: []const u8, value: []const u8) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body });
        const added = try self.validateHeader(name, value, self.response_header_count, self.response_header_bytes);
        const name_source: collections.Source = .{
            .origin = .response_header,
            .offset = self.response_header_bytes,
            .length = name.len,
        };
        const value_source: collections.Source = .{
            .origin = .response_header,
            .offset = self.response_header_bytes + name.len + 2,
            .length = value.len,
        };
        try self.collection_variables.addPair(
            .{ .collection = .response_headers, .key = name, .value = value, .source = value_source },
            .{ .collection = .response_headers_names, .key = name, .value = name, .source = name_source },
        );
        if (std.ascii.eqlIgnoreCase(name, "content-type")) {
            try self.setScalar(.response_content_type, value, .response_header, .response_headers);
        }
        self.response_header_count += 1;
        self.response_header_bytes += added;
    }

    pub fn processResponseHeaders(self: *Transaction, status: u16, protocol: []const u8) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body });
        if (status < 100 or status > 599) return error.InvalidInterventionStatus;
        if (!validProtocol(protocol)) return error.InvalidProtocol;
        try self.setScalarUnsigned(.response_status, status, .response, .response_headers);
        try self.setScalarUnsigned(.status, status, .compatibility, .response_headers);
        try self.setScalar(.response_protocol, protocol, .response, .response_headers);
        const status_line = try std.fmt.allocPrint(self.waf.allocator, "{s} {d}", .{ protocol, status });
        defer self.waf.allocator.free(status_line);
        try self.setScalar(.status_line, status_line, .compatibility, .response_headers);
        self.phase_interrupted = false;
        self.lifecycle = .response_headers;
    }

    pub fn writeResponseBody(self: *Transaction, chunk: []const u8) TransactionError!void {
        try self.requireAny(&.{ .response_headers, .response_body_writing });
        if (chunk.len > self.waf.config.limits.max_response_body_bytes - self.response_body_bytes) {
            return error.ResponseBodyLimitExceeded;
        }
        const next_body_bytes = self.response_body_bytes + chunk.len;
        try self.setScalarUnsigned(.response_content_length, next_body_bytes, .response, .response_body);
        self.response_body_bytes = next_body_bytes;
        self.lifecycle = .response_body_writing;
    }

    pub fn processResponseBody(self: *Transaction) TransactionError!void {
        try self.requireAny(&.{ .response_headers, .response_body_writing });
        if (self.scalar_variables.get(.response_content_length, .response_body) == null) {
            try self.setScalarUnsigned(.response_content_length, 0, .response, .response_body);
        }
        try self.setFlagIfMissing(.outbound_data_error, false, .response, .response_body);
        try self.setFlagIfMissing(.res_body_error, false, .response, .response_body);
        try self.setFlagIfMissing(.res_body_processor_error, false, .response, .response_body);
        self.phase_interrupted = false;
        self.lifecycle = .response_body;
    }

    pub fn processLogging(self: *Transaction) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (self.lifecycle == .created or self.lifecycle == .connection or self.lifecycle == .logging) {
            return error.InvalidLifecycle;
        }
        _ = try self.flushPersistentCollections();
        self.phase_interrupted = false;
        self.lifecycle = .logging;
    }

    pub fn intervention(self: *const Transaction) TransactionError!?Intervention {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        return self.pending_intervention;
    }

    /// Execution-engine hook. Detection-only mode preserves the decision while
    /// marking it non-enforcing for connector policy.
    pub fn recordIntervention(
        self: *Transaction,
        action: Intervention.Action,
        status: u16,
        rule_id: ?u32,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (self.currentPhase() == null) return error.InvalidLifecycle;
        if (self.pending_intervention != null) return error.InterventionAlreadyRecorded;
        if (status < 100 or status > 599) return error.InvalidInterventionStatus;
        self.pending_intervention = .{
            .action = action,
            .status = status,
            .rule_id = rule_id,
            .enforced = self.control_state.rule_engine == .on,
        };
        if (self.control_state.rule_engine == .on) {
            self.phase_interrupted = true;
            self.transaction_terminated = action == .drop;
        }
    }

    pub fn currentPhase(self: *const Transaction) ?Phase {
        return switch (self.lifecycle) {
            .created, .connection, .deinitialized => null,
            .uri, .request_headers => .request_headers,
            .request_body_writing, .request_body => .request_body,
            .response_headers => .response_headers,
            .response_body_writing, .response_body => .response_body,
            .logging => .logging,
        };
    }

    pub fn isPhaseInterrupted(self: *const Transaction) bool {
        return self.phase_interrupted;
    }

    pub fn isTerminated(self: *const Transaction) bool {
        return self.transaction_terminated;
    }

    pub fn isLoggingFinalized(self: *const Transaction) bool {
        return self.lifecycle == .logging;
    }

    pub fn scalar(self: *Transaction, name: variables.Name) TransactionError!?variables.View {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (name == .duration) try self.updateDuration();
        const availability = self.currentAvailability() orelse return null;
        return self.scalar_variables.get(name, availability);
    }

    pub fn scalarBySecLangName(self: *Transaction, name: []const u8) TransactionError!?variables.View {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (variables.Name.parse(name)) |parsed| if (parsed == .duration) try self.updateDuration();
        const availability = self.currentAvailability() orelse return null;
        return self.scalar_variables.getBySecLangName(name, availability);
    }

    pub fn collection(self: *const Transaction, name: collections.Name, selector: collections.Selector) TransactionError!?collections.Iterator {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const availability = self.currentAvailability() orelse return null;
        if (@backingInt(availability) < @backingInt(name.minimumAvailability())) return null;
        return self.collection_variables.select(name, selector);
    }

    pub fn collectionFirst(self: *const Transaction, name: collections.Name, key: []const u8) TransactionError!?collections.View {
        var iterator = (try self.collection(name, .{ .key = key })) orelse return null;
        return try iterator.next();
    }

    pub fn collectionTarget(self: *const Transaction, target: collections.Target, exclusions: []const collections.Target) TransactionError!?collections.TargetIterator {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const availability = self.currentAvailability() orelse return null;
        if (@backingInt(availability) < @backingInt(target.collection.minimumAvailability())) return null;
        return self.collection_variables.selectTarget(target, exclusions);
    }

    pub fn collectionCount(self: *const Transaction, target: collections.Target, exclusions: []const collections.Target) TransactionError!?usize {
        if ((try self.collectionTarget(target, exclusions)) == null) return null;
        return try self.collection_variables.countTarget(target, exclusions);
    }

    pub fn addCollectionValue(
        self: *Transaction,
        name: collections.Name,
        key: []const u8,
        value: []const u8,
        source: collections.Source,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.collection_variables.add(name, key, value, source);
    }

    pub fn addArgument(
        self: *Transaction,
        argument_origin: ArgumentOrigin,
        key: []const u8,
        value: []const u8,
        source: collections.Source,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const mapping: struct {
            specific: collections.Name,
            names: collections.Name,
            availability: variables.Availability,
        } = switch (argument_origin) {
            .query => .{ .specific = .args_get, .names = .args_get_names, .availability = .request_headers },
            .body => .{ .specific = .args_post, .names = .args_post_names, .availability = .request_body },
            .path => .{ .specific = .args_path, .names = .args_names, .availability = .request_headers },
        };
        const values = [_]collections.Value{
            .{ .collection = mapping.specific, .key = key, .value = value, .source = source },
            .{ .collection = mapping.names, .key = key, .value = key, .source = source },
            .{ .collection = .args, .key = key, .value = value, .source = source },
            .{ .collection = .args_names, .key = key, .value = key, .source = source },
        };
        const added = std.math.add(usize, key.len, value.len) catch return error.CollectionSizeOverflow;
        const next_combined_size = std.math.add(usize, self.args_combined_size, added) catch return error.CollectionSizeOverflow;
        try self.collection_variables.addBatch(&values);
        self.args_combined_size = next_combined_size;
        try self.setScalarUnsigned(.args_combined_size, self.args_combined_size, .parser, mapping.availability);
    }

    pub fn addRequestCookie(self: *Transaction, key: []const u8, value: []const u8, source: collections.Source) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.collection_variables.addPair(
            .{ .collection = .request_cookies, .key = key, .value = value, .source = source },
            .{ .collection = .request_cookies_names, .key = key, .value = key, .source = source },
        );
    }

    pub fn addFileMetadata(
        self: *Transaction,
        field: []const u8,
        original_name: []const u8,
        temporary_name: []const u8,
        size: u64,
        source: collections.Source,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        var size_buffer: [32]u8 = undefined;
        const size_text = std.fmt.bufPrint(&size_buffer, "{d}", .{size}) catch unreachable;
        const values = [_]collections.Value{
            .{ .collection = .files, .key = field, .value = temporary_name, .source = source },
            .{ .collection = .files_names, .key = field, .value = original_name, .source = source },
            .{ .collection = .files_sizes, .key = field, .value = size_text, .source = source },
            .{ .collection = .files_tmp_names, .key = field, .value = temporary_name, .source = source },
        };
        const next_combined_size = std.math.add(u64, self.files_combined_size, size) catch return error.CollectionSizeOverflow;
        try self.collection_variables.addBatch(&values);
        self.files_combined_size = next_combined_size;
        try self.setScalarUnsigned(.files_combined_size, self.files_combined_size, .parser, .request_body);
    }

    pub fn setCollectionValue(
        self: *Transaction,
        name: collections.Name,
        key: []const u8,
        value: []const u8,
        source: collections.Source,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.collection_variables.set(name, key, value, source);
    }

    pub fn addTransactionCollectionValue(self: *Transaction, name: []const u8, delta: i64) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const current = if (self.collection_variables.first(.tx, name)) |value|
            persistent.parseNumericOrZero(value.value)
        else
            0;
        const next = std.math.add(i64, current, delta) catch return error.CapacityExceeded;
        var value_buffer: [24]u8 = undefined;
        const value = std.fmt.bufPrint(&value_buffer, "{d}", .{next}) catch unreachable;
        try self.collection_variables.set(
            .tx,
            name,
            value,
            .{ .origin = .rule, .offset = 0, .length = value.len },
        );
    }

    pub fn initializePersistentCollection(
        self: *Transaction,
        namespace: persistent.Namespace,
        collection_key: []const u8,
    ) TransactionError!PersistentInitialization {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const availability = self.currentAvailability() orelse return error.InvalidLifecycle;
        if (@backingInt(availability) < @backingInt(variables.Availability.request_headers)) return error.InvalidLifecycle;
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        var snapshot = (session.initialize(namespace, collection_key, try self.persistentNow()) catch |err| {
            if (try self.handlePersistentFailure(err)) {
                self.markPersistentNamespaceFailedOpen(namespace);
                return .failed_open;
            }
            return err;
        }) orelse return .already_initialized;
        defer snapshot.deinit();
        errdefer session.cancelInitialization(namespace);

        var batch: std.ArrayList(collections.Value) = .empty;
        defer batch.deinit(self.waf.allocator);
        try batch.ensureTotalCapacity(self.waf.allocator, snapshot.values.items.len);
        for (snapshot.values.items) |value| batch.appendAssumeCapacity(.{
            .collection = namespace.collectionName(),
            .key = value.name,
            .value = value.value,
            .source = .{ .origin = .persistent, .offset = 0, .length = value.value.len },
        });
        try self.collection_variables.addBatch(batch.items);
        return .loaded;
    }

    pub fn setSessionCollection(self: *Transaction, session_id: []const u8) TransactionError!PersistentInitialization {
        const result = try self.initializePersistentCollection(.session, session_id);
        try self.setScalar(.session_id, session_id, .rule, .request_headers);
        return result;
    }

    pub fn setUserCollection(self: *Transaction, user_id: []const u8) TransactionError!PersistentInitialization {
        const result = try self.initializePersistentCollection(.user, user_id);
        try self.setScalar(.user_id, user_id, .rule, .request_headers);
        return result;
    }

    pub fn setResourceCollection(self: *Transaction, resource_id: []const u8) TransactionError!PersistentInitialization {
        const result = try self.initializePersistentCollection(.resource, resource_id);
        try self.setScalar(.resource, resource_id, .rule, .request_headers);
        return result;
    }

    pub fn setPersistentCollectionValue(
        self: *Transaction,
        namespace: persistent.Namespace,
        name: []const u8,
        value: []const u8,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        try session.set(namespace, name, value, null);
        self.collection_variables.set(
            namespace.collectionName(),
            name,
            value,
            .{ .origin = .rule, .offset = 0, .length = value.len },
        ) catch |err| {
            session.discardLastMutation(namespace);
            return err;
        };
    }

    pub fn addPersistentCollectionValue(
        self: *Transaction,
        namespace: persistent.Namespace,
        name: []const u8,
        delta: i64,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        const current = if (self.collection_variables.first(namespace.collectionName(), name)) |value|
            persistent.parseNumericOrZero(value.value)
        else
            0;
        const next = std.math.add(i64, current, delta) catch return error.CapacityExceeded;
        var value_buffer: [24]u8 = undefined;
        const value = std.fmt.bufPrint(&value_buffer, "{d}", .{next}) catch unreachable;
        try session.add(namespace, name, delta);
        self.collection_variables.set(
            namespace.collectionName(),
            name,
            value,
            .{ .origin = .rule, .offset = 0, .length = value.len },
        ) catch |err| {
            session.discardLastMutation(namespace);
            return err;
        };
    }

    pub fn removePersistentCollectionValue(self: *Transaction, namespace: persistent.Namespace, name: []const u8) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        try session.remove(namespace, name);
        _ = try self.collection_variables.remove(namespace.collectionName(), .{ .key = name });
    }

    pub fn expirePersistentCollectionValue(
        self: *Transaction,
        namespace: persistent.Namespace,
        name: []const u8,
        ttl_seconds: u32,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        const ttl_ns = std.math.mul(i64, @as(i64, ttl_seconds), std.time.ns_per_s) catch return error.PersistentTimestampOverflow;
        const expires_at_ns = std.math.add(i64, try self.persistentNow(), ttl_ns) catch return error.PersistentTimestampOverflow;
        try session.expire(namespace, name, expires_at_ns);
    }

    pub fn flushPersistentCollections(self: *Transaction) TransactionError!usize {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const session = &(self.persistent_session orelse return 0);
        return session.flush(try self.persistentNow()) catch |err| {
            if (try self.handlePersistentFailure(err)) return 0;
            return err;
        };
    }

    pub fn lastPersistentFailure(self: *const Transaction) ?PersistentFailure {
        return self.last_persistent_failure;
    }

    pub fn matchIntentCount(self: *const Transaction) usize {
        return self.match_intents.items.len;
    }

    pub fn matchIntent(self: *const Transaction, id: MatchIntentId) ?MatchIntent {
        const index: usize = @backingInt(id);
        if (index >= self.match_intents.items.len) return null;
        return self.match_intents.items[index];
    }

    pub fn flowState(self: *const Transaction) FlowState {
        return self.flow_state;
    }

    pub fn controlState(self: *const Transaction) ControlState {
        return self.control_state;
    }

    pub fn ruleExcluded(self: *const Transaction, rule_id: compiled_plan.RuleId) bool {
        const plan = self.compiledPlan() orelse return false;
        const index: usize = @backingInt(rule_id);
        if (index >= plan.rules.len) return false;
        return self.ruleExcludedCompiled(plan, plan.rules[index]);
    }

    fn ruleExcludedCompiled(self: *const Transaction, plan: *const compiled_plan.Plan, rule: compiled_plan.Rule) bool {
        for (self.rule_exclusions.items) |exclusion| if (exclusionMatchesRule(plan, rule, exclusion)) return true;
        return false;
    }

    pub fn targetExcluded(self: *const Transaction, rule_id: compiled_plan.RuleId, target: []const u8) bool {
        const plan = self.compiledPlan() orelse return false;
        const index: usize = @backingInt(rule_id);
        if (index >= plan.rules.len) return false;
        const rule = plan.rules[index];
        for (self.target_exclusions.items) |exclusion| {
            if (!std.ascii.eqlIgnoreCase(exclusion.target, target)) continue;
            if (exclusionMatchesRule(plan, rule, exclusion.selector)) return true;
        }
        return false;
    }

    fn exclusionMatchesRule(plan: *const compiled_plan.Plan, rule: compiled_plan.Rule, exclusion: RuleExclusion) bool {
        return switch (exclusion) {
            .id => |range| if (rule.external_id) |external_id| {
                return range.contains(external_id);
            } else false,
            .tag => |excluded_tag| {
                if (rule.metadata.tags_start + rule.metadata.tags_count > plan.metadata_tags.len) return false;
                for (plan.metadata_tags[rule.metadata.tags_start..][0..rule.metadata.tags_count]) |tag| {
                    if (std.mem.eql(u8, plan.string(tag.value) orelse continue, excluded_tag)) return true;
                }
                return false;
            },
        };
    }

    pub fn removeCollectionValues(self: *Transaction, name: collections.Name, selector: collections.Selector) TransactionError!usize {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        return try self.collection_variables.remove(name, selector);
    }

    pub fn expandMacro(
        self: *Transaction,
        compiled: *const macros.Compiled,
        allocator: std.mem.Allocator,
    ) TransactionError![]u8 {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.updateDuration();
        return compiled.expand(allocator, .{
            .context = self,
            .scalarFn = resolveMacroScalar,
            .collectionFn = resolveMacroCollection,
        }, self.waf.config.macro_missing_policy) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.MacroOutputTooLarge => return error.MacroOutputTooLarge,
        };
    }

    /// Expand a compiler-owned action subexpression without reparsing macro
    /// names on the request path. The caller owns the returned bytes.
    pub fn expandEffectText(
        self: *Transaction,
        text: compiled_plan.EffectText,
        allocator: std.mem.Allocator,
    ) TransactionError![]u8 {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        const plan = self.compiledPlan() orelse return error.MissingCompiledPlan;
        const source = plan.string(text.value) orelse return error.InvalidRuleReference;
        const program_id = text.macro orelse return allocator.dupe(u8, source);
        const program_index: usize = @backingInt(program_id);
        if (program_index >= plan.macro_programs.len) return error.InvalidRuleReference;
        const program = plan.macro_programs[program_index];
        if (program.tokens_start + program.tokens_count > plan.macro_tokens.len)
            return error.InvalidRuleReference;
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);
        for (plan.macro_tokens[program.tokens_start..][0..program.tokens_count]) |token| {
            if (token.source_start + token.source_length > source.len) return error.InvalidRuleReference;
            const raw = source[token.source_start..][0..token.source_length];
            const value = switch (token.kind) {
                .literal => raw,
                .scalar => if (token.scalar) |name|
                    resolveMacroScalar(self, name) orelse missingPlanMacro(raw, self.waf.config.macro_missing_policy)
                else
                    missingPlanMacro(raw, self.waf.config.macro_missing_policy),
                .collection => if (token.collection) |name|
                    resolveMacroCollection(self, name, if (token.key) |key| plan.string(key) else null) orelse
                        missingPlanMacro(raw, self.waf.config.macro_missing_policy)
                else
                    missingPlanMacro(raw, self.waf.config.macro_missing_policy),
            };
            if (value.len > self.waf.config.limits.max_scalar_value_bytes -| output.items.len)
                return error.MacroOutputTooLarge;
            try output.appendSlice(allocator, value);
        }
        return output.toOwnedSlice(allocator);
    }

    pub fn setIdentity(self: *Transaction, remote_user: []const u8, user_id: []const u8) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.setScalar(.remote_user, remote_user, .connector, .request_headers);
        try self.setScalar(.user_id, user_id, .connector, .request_headers);
    }

    pub fn setServerName(self: *Transaction, server_name: []const u8) TransactionError!void {
        try self.requireBeforeRequestHeaders();
        try self.setScalar(.server_name, server_name, .connector, .request_headers);
    }

    pub fn setCompatibilityIdentity(
        self: *Transaction,
        session_id: []const u8,
        webapp_id: []const u8,
    ) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.setScalar(.session_id, session_id, .connector, .request_headers);
        try self.setScalar(.webapp_id, webapp_id, .connector, .request_headers);
    }

    pub fn recordRequestBodyError(self: *Transaction, processor: []const u8, message: []const u8) TransactionError!void {
        try self.requireAny(&.{ .request_headers, .request_body_writing });
        if (processor.len != 0) try self.setScalar(.reqbody_processor, processor, .parser, .request_body);
        try self.setScalar(.reqbody_error, "1", .parser, .request_body);
        try self.setScalar(.reqbody_error_msg, message, .parser, .request_body);
        try self.setScalar(.reqbody_processor_error, "1", .parser, .request_body);
        try self.setScalar(.reqbody_processor_error_msg, message, .parser, .request_body);
    }

    pub fn recordResponseBodyError(self: *Transaction, processor: []const u8, message: []const u8) TransactionError!void {
        try self.requireAny(&.{ .response_headers, .response_body_writing });
        if (processor.len != 0) try self.setScalar(.res_body_processor, processor, .parser, .response_body);
        try self.setScalar(.res_body_error, "1", .parser, .response_body);
        try self.setScalar(.res_body_error_msg, message, .parser, .response_body);
        try self.setScalar(.res_body_processor_error, "1", .parser, .response_body);
        try self.setScalar(.res_body_processor_error_msg, message, .parser, .response_body);
    }

    pub fn recordRegexError(self: *Transaction, limits_exceeded: bool) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.setScalar(.msc_pcre_error, "1", .compatibility, .request_headers);
        if (limits_exceeded) try self.setScalar(.msc_pcre_limits_exceeded, "1", .compatibility, .request_headers);
    }

    pub fn recordMatch(self: *Transaction, name: []const u8, value: []const u8, severity: u8) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        try self.collection_variables.addPair(
            .{ .collection = .matched_vars, .key = name, .value = value, .source = .{ .origin = .rule, .offset = 0, .length = value.len } },
            .{ .collection = .matched_vars_names, .key = name, .value = name, .source = .{ .origin = .rule, .offset = 0, .length = name.len } },
        );
        try self.setScalar(.matched_var_name, name, .rule, .request_headers);
        try self.setScalar(.matched_var, value, .rule, .request_headers);
        if (severity < self.highest_severity) {
            self.highest_severity = severity;
            try self.setScalarUnsigned(.highest_severity, severity, .rule, .request_headers);
        }
    }

    fn validateMatchContext(self: *const Transaction, context: MatchContext) TransactionError!void {
        if (context.name.len == 0 or context.name.len > self.waf.config.limits.max_match_name_bytes or
            context.value.len > self.waf.config.limits.max_match_value_bytes)
        {
            return error.InvalidMatchContext;
        }
        if (context.captures.len > self.waf.config.limits.max_captures) return error.TooManyCaptures;
        _ = std.math.add(usize, context.source.offset, context.source.length) catch return error.InvalidMatchContext;
        for (context.captures) |maybe_range| if (maybe_range) |range| {
            if (range.start > range.end or range.end > context.value.len) return error.InvalidMatchContext;
            const offset = std.math.add(usize, context.source.offset, range.start) catch return error.InvalidMatchContext;
            _ = std.math.add(usize, offset, range.end - range.start) catch return error.InvalidMatchContext;
        };
    }

    fn validateMatchedChain(
        self: *const Transaction,
        plan: *const compiled_plan.Plan,
        matches: []const MatchedRule,
    ) TransactionError!void {
        if (matches.len == 0 or matches.len > plan.rules.len) return error.InvalidRuleChain;
        const head_id = matches[0].rule;
        const head_index: usize = @backingInt(head_id);
        if (head_index >= plan.rules.len) return error.InvalidRuleReference;
        if (plan.rules[head_index].chain_head != head_id) return error.InvalidRuleChain;

        var expected: ?compiled_plan.RuleId = head_id;
        for (matches) |matched| {
            if (expected == null or matched.rule != expected.?) return error.InvalidRuleChain;
            const index: usize = @backingInt(matched.rule);
            if (index >= plan.rules.len) return error.InvalidRuleReference;
            const rule = plan.rules[index];
            if (rule.chain_head != head_id) return error.InvalidRuleChain;
            try self.validateMatchContext(matched.context);
            expected = rule.chain_next;
        }
        if (expected != null) return error.InvalidRuleChain;
    }

    fn stageRuleProjection(
        self: *Transaction,
        batch: *ShadowBatch,
        rule_id: compiled_plan.RuleId,
        selected: compiled_plan.Rule,
        head: compiled_plan.Rule,
        plan: *const compiled_plan.Plan,
    ) TransactionError!RuleProjection {
        _ = self;
        const source: collections.Source = .{ .origin = .rule, .offset = 0, .length = 0 };
        const rule_keys = [_][]const u8{ "id", "rev", "msg", "logdata", "severity", "maturity", "accuracy", "ver" };
        for (rule_keys) |key| try batch.putCopy(.rule, key, null, source);
        var id_buffer: [24]u8 = undefined;
        var severity_buffer: [3]u8 = undefined;
        var maturity_buffer: [3]u8 = undefined;
        var accuracy_buffer: [3]u8 = undefined;
        if (head.external_id) |external_id| {
            const value = std.fmt.bufPrint(&id_buffer, "{d}", .{external_id}) catch unreachable;
            try batch.putCopy(.rule, "id", value, source);
        }
        const metadata = head.metadata;
        if (metadata.revision) |text| try batch.putCopy(.rule, "rev", plan.string(text.value).?, source);
        if (metadata.message) |text| try batch.putCopy(.rule, "msg", plan.string(text.value).?, source);
        if (metadata.log_data) |text| try batch.putCopy(.rule, "logdata", plan.string(text.value).?, source);
        if (metadata.severity) |severity| {
            const value = std.fmt.bufPrint(&severity_buffer, "{d}", .{@backingInt(severity)}) catch unreachable;
            try batch.putCopy(.rule, "severity", value, source);
        }
        if (metadata.maturity) |maturity| {
            const value = std.fmt.bufPrint(&maturity_buffer, "{d}", .{maturity}) catch unreachable;
            try batch.putCopy(.rule, "maturity", value, source);
        }
        if (metadata.accuracy) |accuracy| {
            const value = std.fmt.bufPrint(&accuracy_buffer, "{d}", .{accuracy}) catch unreachable;
            try batch.putCopy(.rule, "accuracy", value, source);
        }
        if (metadata.version) |text| try batch.putCopy(.rule, "ver", plan.string(text.value).?, source);
        return .{
            .rule = rule_id,
            .chain_head = selected.chain_head,
            .external_id = head.external_id,
            .severity = if (metadata.severity) |severity| @backingInt(severity) else null,
            .tags_count = metadata.tags_count,
        };
    }

    fn stageCaptures(self: *Transaction, batch: *ShadowBatch, context: MatchContext) TransactionError!usize {
        try self.validateMatchContext(context);
        const empty_source: collections.Source = .{ .origin = context.source.origin, .offset = context.source.offset, .length = 0 };
        for (capture_keys) |key| try batch.putCopy(.tx, key, null, empty_source);
        var count: usize = 0;
        for (context.captures, 0..) |maybe_range, capture_index| {
            const range = maybe_range orelse continue;
            const offset = context.source.offset + range.start;
            const length = range.end - range.start;
            try batch.putCopy(
                .tx,
                capture_keys[capture_index],
                context.value[range.start..range.end],
                .{ .origin = context.source.origin, .offset = offset, .length = length },
            );
            count += 1;
        }
        return count;
    }

    fn prepareMatchIntent(
        self: *Transaction,
        rule_id: compiled_plan.RuleId,
        selected: compiled_plan.Rule,
        head: compiled_plan.Rule,
        context: MatchContext,
        outcome: LocalEffectOutcome,
        batch: *const ShadowBatch,
        scalar_batch: *const ScalarShadowBatch,
        plan: *const compiled_plan.Plan,
    ) TransactionError!PreparedMatchIntent {
        const metadata = head.metadata;
        if (metadata.tags_start + metadata.tags_count > plan.metadata_tags.len)
            return error.InvalidRuleReference;
        const limit = self.waf.config.limits.max_match_intent_bytes;
        var owned_bytes: usize = @sizeOf(MatchIntent);
        const tag_table_bytes = std.math.mul(usize, metadata.tags_count, @sizeOf([]const u8)) catch
            return error.MatchIntentStorageLimitExceeded;
        if (tag_table_bytes > limit -| owned_bytes) return error.MatchIntentStorageLimitExceeded;
        owned_bytes += tag_table_bytes;

        const message = if (metadata.message) |text|
            try self.expandEffectTextStaged(text, batch, scalar_batch, plan)
        else
            null;
        errdefer if (message) |value| self.waf.allocator.free(value);
        if (message) |value| {
            if (value.len > limit -| owned_bytes) return error.MatchIntentStorageLimitExceeded;
            owned_bytes += value.len;
        }
        const log_data = if (metadata.log_data) |text|
            try self.expandEffectTextStaged(text, batch, scalar_batch, plan)
        else
            null;
        errdefer if (log_data) |value| self.waf.allocator.free(value);
        if (log_data) |value| {
            if (value.len > limit -| owned_bytes) return error.MatchIntentStorageLimitExceeded;
            owned_bytes += value.len;
        }
        const disruptive_destination = if (head.disruptive.destination) |text|
            try self.expandEffectTextStaged(text, batch, scalar_batch, plan)
        else
            null;
        errdefer if (disruptive_destination) |value| self.waf.allocator.free(value);
        if (disruptive_destination) |value| {
            if (value.len == 0) return error.InvalidActionValue;
            if (value.len > limit -| owned_bytes) return error.MatchIntentStorageLimitExceeded;
            owned_bytes += value.len;
        }

        const tags = try self.waf.allocator.alloc([]const u8, metadata.tags_count);
        var initialized_tags: usize = 0;
        errdefer {
            for (tags[0..initialized_tags]) |value| self.waf.allocator.free(value);
            self.waf.allocator.free(tags);
        }
        for (plan.metadata_tags[metadata.tags_start..][0..metadata.tags_count], tags) |text, *destination| {
            const expanded = try self.expandEffectTextStaged(text, batch, scalar_batch, plan);
            errdefer self.waf.allocator.free(expanded);
            if (expanded.len > limit -| owned_bytes) return error.MatchIntentStorageLimitExceeded;
            owned_bytes += expanded.len;
            destination.* = expanded;
            initialized_tags += 1;
        }

        const matched_name = try self.waf.allocator.dupe(u8, context.name);
        errdefer self.waf.allocator.free(matched_name);
        if (matched_name.len > limit -| owned_bytes) return error.MatchIntentStorageLimitExceeded;
        owned_bytes += matched_name.len;
        const matched_value = try self.waf.allocator.dupe(u8, context.value);
        errdefer self.waf.allocator.free(matched_value);
        if (matched_value.len > limit -| owned_bytes) return error.MatchIntentStorageLimitExceeded;
        owned_bytes += matched_value.len;

        return .{
            .allocator = self.waf.allocator,
            .owned_bytes = owned_bytes,
            .value = .{
                .rule = rule_id,
                .chain_head = selected.chain_head,
                .external_id = head.external_id,
                .severity = if (metadata.severity) |severity| @backingInt(severity) else null,
                .message = message,
                .log_data = log_data,
                .tags = tags,
                .matched_name = matched_name,
                .matched_value = matched_value,
                .matched_source = context.source,
                .log = outcome.log,
                .audit_log = outcome.audit_log,
                .effects_applied = outcome.effects_applied,
                .captures_written = outcome.captures_written,
                .pending_persistent_effects = outcome.pending_persistent_effects,
                .disruptive = outcome.disruptive,
                .disruptive_status = outcome.disruptive_status,
                .disruptive_destination = disruptive_destination,
                .allow_scope = outcome.allow_scope,
                .decision_enforced = outcome.decision_enforced,
                .skip = outcome.skip,
                .skip_after_action = outcome.skip_after_action,
                .skip_after_active = outcome.skip_after_active,
                .skip_after_resume = outcome.skip_after_resume,
                .multi_match = outcome.multi_match,
                .controls_applied = outcome.controls_applied,
            },
        };
    }

    fn stageDuration(self: *Transaction, scalar_batch: *ScalarShadowBatch) TransactionError!void {
        const now = self.waf.now();
        const elapsed = @max(@as(i96, 0), now.awake_nanoseconds - self.started_awake_nanoseconds);
        const rendered = try std.fmt.allocPrint(self.waf.allocator, "{d}", .{@divTrunc(elapsed, std.time.ns_per_ms)});
        errdefer self.waf.allocator.free(rendered);
        try scalar_batch.putOwned(.duration, rendered, .timing, .request_headers);
    }

    fn expandEffectTextStaged(
        self: *Transaction,
        text: anytype,
        batch: *const ShadowBatch,
        scalar_batch: *const ScalarShadowBatch,
        plan: *const compiled_plan.Plan,
    ) TransactionError![]u8 {
        const source = plan.string(text.value) orelse return error.InvalidRuleReference;
        const program_id = text.macro orelse return self.waf.allocator.dupe(u8, source);
        const program_index: usize = @backingInt(program_id);
        if (program_index >= plan.macro_programs.len) return error.InvalidRuleReference;
        const program = plan.macro_programs[program_index];
        if (program.tokens_start + program.tokens_count > plan.macro_tokens.len) return error.InvalidRuleReference;
        try self.updateDuration();
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(self.waf.allocator);
        for (plan.macro_tokens[program.tokens_start..][0..program.tokens_count]) |token| {
            if (token.source_start + token.source_length > source.len) return error.InvalidRuleReference;
            const raw = source[token.source_start..][0..token.source_length];
            const value = switch (token.kind) {
                .literal => raw,
                .scalar => if (token.scalar) |name|
                    scalar_batch.get(name) orelse resolveMacroScalar(self, name) orelse
                        missingPlanMacro(raw, self.waf.config.macro_missing_policy)
                else
                    missingPlanMacro(raw, self.waf.config.macro_missing_policy),
                .collection => if (token.collection) |name| blk: {
                    const key = if (token.key) |key_id| plan.string(key_id) else null;
                    if (key) |selected_key| switch (batch.lookup(name, selected_key)) {
                        .value => |staged| break :blk staged,
                        .removed => break :blk missingPlanMacro(raw, self.waf.config.macro_missing_policy),
                        .missing => {},
                    } else if (batch.first(name)) |staged| break :blk staged;
                    break :blk resolveMacroCollection(self, name, key) orelse
                        missingPlanMacro(raw, self.waf.config.macro_missing_policy);
                } else missingPlanMacro(raw, self.waf.config.macro_missing_policy),
            };
            if (value.len > self.waf.config.limits.max_scalar_value_bytes -| output.items.len)
                return error.MacroOutputTooLarge;
            try output.appendSlice(self.waf.allocator, value);
        }
        return output.toOwnedSlice(self.waf.allocator);
    }

    fn initializePersistentStaged(
        self: *Transaction,
        batch: *ShadowBatch,
        namespace: persistent.Namespace,
        collection_key: []const u8,
    ) TransactionError!PersistentInitialization {
        if (self.persistentNamespaceFailedOpen(namespace)) return .failed_open;
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        var snapshot = (session.initialize(namespace, collection_key, try self.persistentNow()) catch |err| {
            if (try self.handlePersistentFailure(err)) {
                self.markPersistentNamespaceFailedOpen(namespace);
                return .failed_open;
            }
            return err;
        }) orelse return .already_initialized;
        defer snapshot.deinit();

        const collection_name = namespace.collectionName();
        var existing = self.collection_variables.select(collection_name, .all);
        while (try existing.next()) |value| {
            try batch.putCopy(collection_name, value.key, null, value.source);
        }
        for (snapshot.values.items) |value| {
            try batch.putCopy(
                collection_name,
                value.name,
                value.value,
                .{ .origin = .persistent, .offset = 0, .length = value.value.len },
            );
        }
        return .loaded;
    }

    fn stagePersistentSetVar(
        self: *Transaction,
        namespace: persistent.Namespace,
        name: []const u8,
        operation: action_config.SetVarOperation,
        operand: ?[]const u8,
    ) TransactionError!void {
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        switch (operation) {
            .set_one => try session.set(namespace, name, "1", null),
            .set => try session.set(namespace, name, operand orelse "", null),
            .remove => try session.remove(namespace, name),
            .add => try session.add(namespace, name, persistent.parseNumericOrZero(operand orelse "")),
            .subtract => try session.subtract(namespace, name, persistent.parseNumericOrZero(operand orelse "")),
        }
    }

    fn stagePersistentExpiry(
        self: *Transaction,
        namespace: persistent.Namespace,
        name: []const u8,
        ttl_seconds: u32,
    ) TransactionError!void {
        const session = &(self.persistent_session orelse return error.PersistentBackendNotConfigured);
        const ttl_ns = std.math.mul(i64, @as(i64, ttl_seconds), std.time.ns_per_s) catch
            return error.PersistentTimestampOverflow;
        const expires_at_ns = std.math.add(i64, try self.persistentNow(), ttl_ns) catch
            return error.PersistentTimestampOverflow;
        try session.expire(namespace, name, expires_at_ns);
    }

    fn persistentNamespaceFailedOpen(self: *const Transaction, namespace: persistent.Namespace) bool {
        const bit = @as(u8, 1) << @as(u3, @intCast(@backingInt(namespace)));
        return self.persistent_failed_open & bit != 0;
    }

    fn markPersistentNamespaceFailedOpen(self: *Transaction, namespace: persistent.Namespace) void {
        self.persistent_failed_open |= @as(u8, 1) << @as(u3, @intCast(@backingInt(namespace)));
    }

    fn evaluateSetVar(
        self: *Transaction,
        batch: *const ShadowBatch,
        collection_name: collections.Name,
        name: []const u8,
        operation: action_config.SetVarOperation,
        operand: ?[]const u8,
    ) TransactionError!?[]u8 {
        return switch (operation) {
            .set_one => try self.waf.allocator.dupe(u8, "1"),
            .set => try self.waf.allocator.dupe(u8, operand orelse ""),
            .remove => null,
            .add, .subtract => blk: {
                const current_text = switch (batch.lookup(collection_name, name)) {
                    .value => |value| value,
                    .removed => "",
                    .missing => if (self.collection_variables.first(collection_name, name)) |value| value.value else "",
                };
                const current = persistent.parseNumericOrZero(current_text);
                const delta = persistent.parseNumericOrZero(operand orelse "");
                const next = if (operation == .add)
                    std.math.add(i64, current, delta) catch return error.CapacityExceeded
                else
                    std.math.sub(i64, current, delta) catch return error.CapacityExceeded;
                break :blk try std.fmt.allocPrint(self.waf.allocator, "{d}", .{next});
            },
        };
    }

    pub fn deinit(self: *Transaction) void {
        if (self.lifecycle == .deinitialized) return;
        if (self.persistent_session) |*session| session.deinit();
        for (self.match_intents.items) |*intent| deinitMatchIntent(self.waf.allocator, intent);
        self.match_intents.deinit(self.waf.allocator);
        self.match_intent_bytes = 0;
        deinitRuleExclusions(self.waf.allocator, &self.rule_exclusions);
        deinitTargetExclusions(self.waf.allocator, &self.target_exclusions);
        self.rule_exclusion_bytes = 0;
        self.scalar_variables.deinit();
        self.collection_variables.deinit();
        self.lifecycle = .deinitialized;
        _ = @constCast(&self.waf.active_transactions).fetchSub(1, .release);
    }

    fn validateHeader(
        self: *Transaction,
        name: []const u8,
        value: []const u8,
        count: usize,
        bytes: usize,
    ) TransactionError!usize {
        if (!validToken(name) or containsLineBreak(value)) return error.InvalidHeader;
        if (count == self.waf.config.limits.max_header_count) return error.TooManyHeaders;
        const added = name.len + value.len;
        if (added > self.waf.config.limits.max_header_bytes - bytes) return error.HeadersTooLarge;
        return added;
    }

    fn require(self: *const Transaction, expected: Lifecycle) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (self.transaction_terminated) return error.TransactionTerminated;
        if (self.lifecycle != expected) return error.InvalidLifecycle;
    }

    fn requireAny(self: *const Transaction, expected: []const Lifecycle) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (self.transaction_terminated) return error.TransactionTerminated;
        for (expected) |candidate| if (self.lifecycle == candidate) return;
        return error.InvalidLifecycle;
    }

    fn currentAvailability(self: *const Transaction) ?variables.Availability {
        return switch (self.lifecycle) {
            .created, .deinitialized => null,
            .connection => .connection,
            .uri, .request_headers => .request_headers,
            .request_body_writing, .request_body => .request_body,
            .response_headers => .response_headers,
            .response_body_writing, .response_body => .response_body,
            .logging => .logging,
        };
    }

    fn initializeCompatibilityScalars(self: *Transaction) TransactionError!void {
        if (self.started_real_nanoseconds < 0) return error.ClockBeforeUnixEpoch;
        try self.setScalar(.remote_host, (self.scalar_variables.get(.remote_addr, .connection) orelse unreachable).value, .compatibility, .connection);
        try self.setScalar(.modsec_build, "zig-waf/0.0.0-dev", .compatibility, .request_headers);
        try self.setScalar(.msc_pcre_error, "0", .compatibility, .request_headers);
        try self.setScalar(.msc_pcre_limits_exceeded, "0", .compatibility, .request_headers);
        try self.setScalar(.urlencoded_error, "0", .parser, .request_headers);
        try self.setScalar(.highest_severity, "255", .rule, .request_headers);
        try self.setScalar(.duration, "0", .timing, .request_headers);

        var id_buffer: [64]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buffer, "zigwaf-{x}-{x}", .{ self.started_real_nanoseconds, self.sequence }) catch unreachable;
        try self.setScalar(.unique_id, id, .engine, .request_headers);
        try self.setTimeScalars();
    }

    fn setTimeScalars(self: *Transaction) TransactionError!void {
        const seconds: u64 = @intCast(@divFloor(self.started_real_nanoseconds, std.time.ns_per_s));
        const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = seconds };
        const day_seconds = epoch_seconds.getDaySeconds();
        const year_day = epoch_seconds.getEpochDay().calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const hour = day_seconds.getHoursIntoDay();
        const minute = day_seconds.getMinutesIntoHour();
        const second = day_seconds.getSecondsIntoMinute();
        var time_buffer: [8]u8 = undefined;
        const formatted_time = std.fmt.bufPrint(&time_buffer, "{d:0>2}:{d:0>2}:{d:0>2}", .{ hour, minute, second }) catch unreachable;
        try self.setScalar(.time, formatted_time, .timing, .request_headers);
        try self.setScalarUnsigned(.time_day, @as(u8, month_day.day_index) + 1, .timing, .request_headers);
        try self.setScalarUnsigned(.time_epoch, seconds, .timing, .request_headers);
        try self.setScalarUnsigned(.time_hour, hour, .timing, .request_headers);
        try self.setScalarUnsigned(.time_min, minute, .timing, .request_headers);
        try self.setScalarUnsigned(.time_mon, month_day.month.numeric(), .timing, .request_headers);
        try self.setScalarUnsigned(.time_sec, second, .timing, .request_headers);
        // POSIX/Go convention: Sunday=0. 1970-01-01 was Thursday (4).
        try self.setScalarUnsigned(.time_wday, (epoch_seconds.getEpochDay().day + 4) % 7, .timing, .request_headers);
        try self.setScalarUnsigned(.time_year, year_day.year, .timing, .request_headers);
    }

    fn updateDuration(self: *Transaction) TransactionError!void {
        const now = self.waf.now();
        const elapsed = @max(@as(i96, 0), now.awake_nanoseconds - self.started_awake_nanoseconds);
        try self.setScalarUnsigned(.duration, @divTrunc(elapsed, std.time.ns_per_ms), .timing, .request_headers);
    }

    fn persistentNow(self: *const Transaction) TransactionError!i64 {
        const now = self.waf.now().unix_nanoseconds;
        if (now < 0 or now > std.math.maxInt(i64)) return error.PersistentTimestampOverflow;
        return @intCast(now);
    }

    fn handlePersistentFailure(self: *Transaction, err: persistent.SessionError) TransactionError!bool {
        const failure: PersistentFailure = switch (err) {
            error.Unavailable => .unavailable,
            error.Timeout => .timeout,
            error.RetryLimitExceeded, error.Conflict => .conflict_exhausted,
            error.CorruptData => .corrupt_data,
            error.CapacityExceeded => .capacity_exceeded,
            else => return err,
        };
        self.last_persistent_failure = failure;
        return self.waf.config.persistent_failure_policy == .fail_open;
    }

    fn setFlagIfMissing(
        self: *Transaction,
        name: variables.Name,
        value: bool,
        origin: variables.Origin,
        available_from: variables.Availability,
    ) TransactionError!void {
        if (self.scalar_variables.get(name, available_from) == null) {
            try self.setScalar(name, if (value) "1" else "0", origin, available_from);
        }
    }

    fn requireBeforeRequestHeaders(self: *const Transaction) TransactionError!void {
        if (self.lifecycle == .deinitialized) return error.Deinitialized;
        if (self.lifecycle != .created and self.lifecycle != .connection and self.lifecycle != .uri) return error.InvalidLifecycle;
    }

    fn setScalar(
        self: *Transaction,
        name: variables.Name,
        value: []const u8,
        origin: variables.Origin,
        available_from: variables.Availability,
    ) TransactionError!void {
        try self.scalar_variables.set(
            name,
            value,
            origin,
            available_from,
            self.waf.config.limits.max_scalar_value_bytes,
            self.waf.config.limits.max_scalar_storage_bytes,
        );
    }

    fn setScalarUnsigned(
        self: *Transaction,
        name: variables.Name,
        value: anytype,
        origin: variables.Origin,
        available_from: variables.Availability,
    ) TransactionError!void {
        try self.scalar_variables.setUnsigned(
            name,
            value,
            origin,
            available_from,
            self.waf.config.limits.max_scalar_value_bytes,
            self.waf.config.limits.max_scalar_storage_bytes,
        );
    }
};

/// Allocation-free traversal of immutable chain heads for one active phase.
/// Flow state is read from the transaction after each matched rule commits, so
/// callers do not need to copy or mutate the compiled plan.
pub const PhaseCursor = struct {
    transaction: *Transaction,
    phase: Phase,
    index: usize = 0,

    pub fn init(transaction: *Transaction, phase: Phase) TransactionError!PhaseCursor {
        if (transaction.lifecycle == .deinitialized) return error.Deinitialized;
        if (transaction.currentPhase() != phase) return error.InvalidLifecycle;
        if (transaction.compiledPlan() == null) return error.MissingCompiledPlan;
        return .{ .transaction = transaction, .phase = phase };
    }

    pub fn next(self: *PhaseCursor) TransactionError!?compiled_plan.RuleId {
        if (self.transaction.lifecycle == .deinitialized) return error.Deinitialized;
        if (self.transaction.currentPhase() != self.phase) return error.InvalidLifecycle;
        if (self.phase != .logging and
            (self.transaction.control_state.rule_engine == .off or
                self.transaction.transaction_terminated or
                self.transaction.phase_interrupted or
                self.allowSuppressesPhase()))
        {
            return null;
        }
        const plan = self.transaction.compiledPlan() orelse return error.MissingCompiledPlan;
        const rules = plan.phaseRules(@backingInt(self.phase));
        if (self.transaction.flow_state.phase == self.phase and self.transaction.flow_state.skip_after_active) {
            const resume_rule = self.transaction.flow_state.skip_after_resume;
            self.transaction.flow_state.skip_after_active = false;
            self.transaction.flow_state.skip_after_resume = null;
            if (resume_rule) |rule_id| {
                var found = false;
                while (self.index < rules.len) : (self.index += 1) {
                    if (rules[self.index] != rule_id) continue;
                    found = true;
                    break;
                }
                if (!found) return error.InvalidRuleReference;
            } else {
                self.index = rules.len;
            }
        }
        if (self.transaction.flow_state.phase == self.phase and self.transaction.flow_state.skip != 0) {
            var remaining = self.transaction.flow_state.skip;
            self.transaction.flow_state.skip = 0;
            while (self.index < rules.len and remaining != 0) {
                const candidate = plan.rules[@backingInt(rules[self.index])];
                self.index += 1;
                if (candidate.removed_by == null and !self.transaction.ruleExcludedCompiled(plan, candidate)) remaining -= 1;
            }
        }
        while (self.index < rules.len) {
            const rule_id = rules[self.index];
            self.index += 1;
            const candidate = plan.rules[@backingInt(rule_id)];
            if (candidate.removed_by != null or self.transaction.ruleExcludedCompiled(plan, candidate)) continue;
            return rule_id;
        }
        return null;
    }

    fn allowSuppressesPhase(self: *const PhaseCursor) bool {
        const flow = self.transaction.flow_state;
        const scope = flow.allow_scope orelse return false;
        return switch (scope) {
            .transaction => true,
            .request => self.phase == .request_headers or self.phase == .request_body,
            .phase => flow.phase == self.phase,
        };
    }
};

fn lock(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

fn validAddress(address: []const u8) bool {
    if (address.len == 0 or address.len > 255) return false;
    return !containsLineBreak(address) and std.mem.indexOfScalar(u8, address, 0) == null;
}

fn validProtocol(protocol: []const u8) bool {
    return std.mem.eql(u8, protocol, "HTTP/1.0") or
        std.mem.eql(u8, protocol, "HTTP/1.1") or
        std.mem.eql(u8, protocol, "HTTP/2") or
        std.mem.eql(u8, protocol, "HTTP/2.0");
}

fn validToken(token: []const u8) bool {
    if (token.len == 0) return false;
    for (token) |byte| {
        if (byte <= 0x20 or byte >= 0x7f or switch (byte) {
            '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}' => true,
            else => false,
        }) return false;
    }
    return true;
}

fn validEnvironmentName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (byte == 0 or byte == '=' or byte == '\r' or byte == '\n') return false;
    }
    return true;
}

fn effectCollectionName(name: action_config.Collection) collections.Name {
    return switch (name) {
        .tx => .tx,
        .ip => .ip,
        .session => .session,
        .user => .user,
        .global => .global,
        .resource => .resource,
    };
}

fn persistentNamespace(name: action_config.Collection) ?persistent.Namespace {
    return switch (name) {
        .tx => null,
        .ip => .ip,
        .session => .session,
        .user => .user,
        .global => .global,
        .resource => .resource,
    };
}

fn bindingScalar(namespace: persistent.Namespace) variables.Name {
    return switch (namespace) {
        .session => .session_id,
        .user => .user_id,
        .resource => .resource,
        .ip, .global => unreachable,
    };
}

fn containsLineBreak(value: []const u8) bool {
    return std.mem.indexOfAny(u8, value, "\r\n\x00") != null;
}

fn startsWithIgnoreCase(value: []const u8, prefix: []const u8) bool {
    return value.len >= prefix.len and std.ascii.eqlIgnoreCase(value[0..prefix.len], prefix);
}

fn hostWithoutPort(value: []const u8) []const u8 {
    if (value.len == 0) return value;
    if (value[0] == '[') {
        const close = std.mem.indexOfScalar(u8, value, ']') orelse return value;
        return value[1..close];
    }
    const first_colon = std.mem.indexOfScalar(u8, value, ':') orelse return value;
    if (std.mem.indexOfScalarPos(u8, value, first_colon + 1, ':') != null) return value;
    return value[0..first_colon];
}

fn resolveMacroScalar(context: *anyopaque, name: variables.Name) ?[]const u8 {
    const transaction: *Transaction = @ptrCast(@alignCast(context));
    const availability = transaction.currentAvailability() orelse return null;
    return (transaction.scalar_variables.get(name, availability) orelse return null).value;
}

fn resolveMacroCollection(context: *anyopaque, name: collections.Name, key: ?[]const u8) ?[]const u8 {
    const transaction: *Transaction = @ptrCast(@alignCast(context));
    const availability = transaction.currentAvailability() orelse return null;
    if (@backingInt(availability) < @backingInt(name.minimumAvailability())) return null;
    const found = if (key) |selected_key|
        transaction.collection_variables.first(name, selected_key)
    else
        transaction.collection_variables.firstAny(name);
    return (found orelse return null).value;
}

fn missingPlanMacro(raw: []const u8, policy: macros.MissingPolicy) []const u8 {
    return switch (policy) {
        .empty => "",
        .expression => if (raw.len >= 3 and std.mem.startsWith(u8, raw, "%{") and raw[raw.len - 1] == '}')
            raw[2 .. raw.len - 1]
        else
            raw,
    };
}

const ReloadWorker = struct {
    runtime: *Runtime,
    pinned: *std.atomic.Value(usize),
    release: *std.atomic.Value(bool),
    failures: *std.atomic.Value(usize),

    fn run(self: *ReloadWorker) void {
        var pinned_tx = self.runtime.newTransaction() catch {
            _ = self.failures.fetchAdd(1, .monotonic);
            return;
        };
        _ = self.pinned.fetchAdd(1, .release);
        while (!self.release.load(.acquire)) std.atomic.spinLoopHint();
        pinned_tx.deinit();

        for (0..500) |_| {
            var tx = self.runtime.newTransaction() catch {
                _ = self.failures.fetchAdd(1, .monotonic);
                return;
            };
            tx.deinit();
        }
    }
};

const TestClock = struct {
    unix_nanoseconds: i96,
    awake_nanoseconds: i96,

    fn now(context: *anyopaque) ClockSample {
        const self: *TestClock = @ptrCast(@alignCast(context));
        return .{
            .unix_nanoseconds = self.unix_nanoseconds,
            .awake_nanoseconds = self.awake_nanoseconds,
        };
    }
};

const UnavailablePersistence = struct {
    context: u8 = 0,

    fn backend(self: *UnavailablePersistence) persistent.Backend {
        return .{
            .context = &self.context,
            .loadFn = load,
            .commitFn = commit,
            .cleanupFn = cleanup,
        };
    }

    fn load(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: persistent.Namespace,
        _: []const u8,
        _: i64,
        _: persistent.Limits,
    ) persistent.BackendError!persistent.Snapshot {
        return error.Unavailable;
    }

    fn commit(_: *anyopaque, _: persistent.CommitRequest) persistent.BackendError!u64 {
        return error.Unavailable;
    }

    fn cleanup(_: *anyopaque, _: i64, _: persistent.CleanupBudget) persistent.BackendError!persistent.CleanupResult {
        return error.Unavailable;
    }
};

test "executes the complete connector lifecycle" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();

    var tx = waf.newTransaction();
    try tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try std.testing.expect(tx.currentPhase() == null);
    try tx.processUri("/login", "POST", "HTTP/1.1");
    try std.testing.expectEqual(Phase.request_headers, tx.currentPhase().?);
    try tx.addRequestHeader("content-type", "application/json");
    try tx.processRequestHeaders();
    try tx.writeRequestBody("{\"user\":");
    try tx.writeRequestBody("\"alice\"}");
    try tx.processRequestBody();
    try tx.addResponseHeader("content-type", "application/json");
    try tx.processResponseHeaders(200, "HTTP/1.1");
    try tx.writeResponseBody("{\"ok\":true}");
    try tx.processResponseBody();
    try tx.processLogging();
    try std.testing.expectEqual(Phase.logging, tx.currentPhase().?);
    tx.deinit();
    try waf.deinit();
}

test "uses the five stable SecLang phase numbers" {
    try std.testing.expectEqual(@as(u8, 1), @backingInt(Phase.request_headers));
    try std.testing.expectEqual(@as(u8, 2), @backingInt(Phase.request_body));
    try std.testing.expectEqual(@as(u8, 3), @backingInt(Phase.response_headers));
    try std.testing.expectEqual(@as(u8, 4), @backingInt(Phase.response_body));
    try std.testing.expectEqual(@as(u8, 5), @backingInt(Phase.logging));
}

test "rejects invalid phase order and use after deinit" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    var tx = waf.newTransaction();
    try std.testing.expectError(error.InvalidLifecycle, tx.processRequestHeaders());
    tx.deinit();
    try std.testing.expectError(error.Deinitialized, tx.intervention());
    try waf.deinit();
}

test "enforces header and body limits before counters overflow" {
    var builder = Builder.init(std.testing.allocator);
    builder.setLimits(.{
        .max_header_count = 1,
        .max_header_bytes = 8,
        .max_request_body_bytes = 4,
        .max_response_body_bytes = 4,
    });
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("::1", 1234, "::1", 8080);
    try tx.processUri("/", "POST", "HTTP/2");
    try tx.addRequestHeader("x", "1234567");
    try std.testing.expectError(error.TooManyHeaders, tx.addRequestHeader("y", "1"));
    try tx.processRequestHeaders();
    try tx.writeRequestBody("1234");
    try std.testing.expectError(error.RequestBodyLimitExceeded, tx.writeRequestBody("5"));
}

test "prevents WAF destruction while transactions are active" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    var first = waf.newTransaction();
    var second = waf.newTransaction();
    try std.testing.expectEqual(@as(usize, 2), waf.activeTransactionCount());
    try std.testing.expectError(error.TransactionsActive, waf.deinit());
    first.deinit();
    second.deinit();
    try waf.deinit();
}

test "detection-only interventions are visible but not enforced" {
    var builder = Builder.init(std.testing.allocator);
    builder.setMode(.detection_only);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    try tx.recordIntervention(.deny, 403, 941100);
    const pending = (try tx.intervention()).?;
    try std.testing.expectEqual(Intervention.Action.deny, pending.action);
    try std.testing.expect(!pending.enforced);
    try std.testing.expect(!tx.isPhaseInterrupted());
    try std.testing.expect(!tx.isTerminated());
}

test "enabled interventions interrupt a phase and logging finalizes once" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    try tx.recordIntervention(.deny, 403, 1001);
    try std.testing.expect(tx.isPhaseInterrupted());
    try std.testing.expect(!tx.isTerminated());
    try std.testing.expectError(error.InterventionAlreadyRecorded, tx.recordIntervention(.deny, 404, 1002));

    try tx.processResponseHeaders(403, "HTTP/1.1");
    try std.testing.expect(!tx.isPhaseInterrupted());
    try tx.processLogging();
    try std.testing.expect(tx.isLoggingFinalized());
    try std.testing.expectError(error.InvalidLifecycle, tx.processLogging());
}

test "drop terminates inspection but still permits logging finalization" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    try tx.recordIntervention(.drop, 403, 1001);
    try std.testing.expect(tx.isTerminated());
    try std.testing.expectError(error.TransactionTerminated, tx.processResponseHeaders(403, "HTTP/1.1"));
    try tx.processLogging();
    try std.testing.expect(tx.isLoggingFinalized());
}

test "owns scalar variables and exposes them only in valid phases" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    var client = [_]u8{ '1', '9', '2', '.', '0', '.', '2', '.', '1' };
    try tx.processConnection(&client, 54321, "198.51.100.10", 443);
    client[0] = '9';
    try std.testing.expectEqualStrings("192.0.2.1", (try tx.scalar(.remote_addr)).?.value);
    try std.testing.expect((try tx.scalar(.request_method)) == null);

    try tx.processUri("/search?q=zig", "GET", "HTTP/2");
    try std.testing.expectEqualStrings("q=zig", (try tx.scalarBySecLangName("QUERY_STRING")).?.value);
    try std.testing.expectEqualStrings("/search", (try tx.scalar(.request_filename)).?.value);
    try std.testing.expect((try tx.scalar(.response_status)) == null);
    try tx.processRequestHeaders();
    try tx.processResponseHeaders(403, "HTTP/2");
    try std.testing.expectEqualStrings("403", (try tx.scalar(.response_status)).?.value);
}

test "populates timing and compatibility scalars from an injectable clock" {
    var clock: TestClock = .{ .unix_nanoseconds = 0, .awake_nanoseconds = 1_000_000 };
    var builder = Builder.init(std.testing.allocator);
    builder.setClockSource(.{ .context = &clock, .nowFn = TestClock.now });
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try std.testing.expect((try tx.scalar(.time_epoch)) == null);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectEqualStrings("0", (try tx.scalar(.time_epoch)).?.value);
    try std.testing.expectEqualStrings("00:00:00", (try tx.scalar(.time)).?.value);
    try std.testing.expectEqualStrings("1", (try tx.scalar(.time_day)).?.value);
    try std.testing.expectEqualStrings("1", (try tx.scalar(.time_mon)).?.value);
    try std.testing.expectEqualStrings("1970", (try tx.scalar(.time_year)).?.value);
    try std.testing.expectEqualStrings("4", (try tx.scalar(.time_wday)).?.value);
    try std.testing.expectEqualStrings("255", (try tx.scalar(.highest_severity)).?.value);
    try std.testing.expectEqualStrings("0", (try tx.scalar(.msc_pcre_error)).?.value);
    try std.testing.expect(std.mem.startsWith(u8, (try tx.scalar(.unique_id)).?.value, "zigwaf-"));

    clock.awake_nanoseconds += 12 * std.time.ns_per_ms + 999;
    try std.testing.expectEqualStrings("12", (try tx.scalar(.duration)).?.value);
}

test "derives header, identity, match, body error, and response scalars" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("192.0.2.1", 1234, "2001:db8::1", 443);
    try tx.processUri("/submit?q=1", "POST", "HTTP/1.1");
    try tx.setIdentity("alice", "user-7");
    try tx.setCompatibilityIdentity("session-8", "shop");
    try tx.addRequestHeader("Host", "[2001:db8::2]:8443");
    try tx.addRequestHeader("Authorization", "Bearer token");
    try tx.addRequestHeader("Content-Type", "application/json; charset=utf-8");
    try tx.processRequestHeaders();
    try std.testing.expectEqualStrings("2001:db8::2", (try tx.scalar(.server_name)).?.value);
    try std.testing.expectEqualStrings("Bearer", (try tx.scalar(.auth_type)).?.value);
    try std.testing.expectEqualStrings("JSON", (try tx.scalar(.reqbody_processor)).?.value);
    try std.testing.expectEqualStrings("alice", (try tx.scalar(.remote_user)).?.value);
    try std.testing.expectEqualStrings("session-8", (try tx.scalar(.session_id)).?.value);

    try tx.recordMatch("ARGS:q", "attack", 4);
    try tx.recordMatch("REQUEST_URI", "/submit", 7);
    try std.testing.expectEqualStrings("4", (try tx.scalar(.highest_severity)).?.value);
    try tx.recordMatch("REQUEST_URI", "/submit", 1);
    try std.testing.expectEqualStrings("1", (try tx.scalar(.highest_severity)).?.value);
    try std.testing.expectEqualStrings("REQUEST_URI", (try tx.scalar(.matched_var_name)).?.value);

    try tx.writeRequestBody("invalid");
    try tx.recordRequestBodyError("JSON", "unexpected token");
    try tx.processRequestBody();
    try std.testing.expectEqualStrings("1", (try tx.scalar(.reqbody_error)).?.value);
    try std.testing.expectEqualStrings("unexpected token", (try tx.scalar(.reqbody_processor_error_msg)).?.value);
    try std.testing.expectEqualStrings("0", (try tx.scalar(.inbound_data_error)).?.value);

    try tx.addResponseHeader("Content-Type", "application/problem+json");
    try tx.processResponseHeaders(422, "HTTP/1.1");
    try std.testing.expectEqualStrings("application/problem+json", (try tx.scalar(.response_content_type)).?.value);
    try std.testing.expectEqualStrings("HTTP/1.1 422", (try tx.scalar(.status_line)).?.value);
    try tx.writeResponseBody("problem");
    try tx.recordResponseBodyError("JSON", "invalid response");
    try tx.processResponseBody();
    try std.testing.expectEqualStrings("7", (try tx.scalar(.response_content_length)).?.value);
    try std.testing.expectEqualStrings("1", (try tx.scalar(.res_body_error)).?.value);
    try std.testing.expectEqualStrings("0", (try tx.scalar(.outbound_data_error)).?.value);
}

test "publishes repeated header collections with phase gates and origins" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    var first_value = [_]u8{ 'o', 'n', 'e' };
    try tx.addRequestHeader("X-Test", &first_value);
    first_value[0] = 'x';
    try tx.addRequestHeader("x-test", "two");
    var headers = (try tx.collection(.request_headers, .{ .key = "X-TEST" })).?;
    const first = (try headers.next()).?;
    try std.testing.expectEqualStrings("one", first.value);
    try std.testing.expectEqual(variables.Origin.request_header, first.source.origin);
    try std.testing.expectEqualStrings("two", (try headers.next()).?.value);
    try std.testing.expect(try headers.next() == null);
    try std.testing.expect((try tx.collection(.response_headers, .all)) == null);

    var names = (try tx.collection(.request_headers_names, .all)).?;
    try std.testing.expectEqualStrings("X-Test", (try names.next()).?.value);
    try std.testing.expectEqualStrings("x-test", (try names.next()).?.value);

    try tx.processRequestHeaders();
    try tx.addResponseHeader("Content-Type", "text/plain");
    try std.testing.expect((try tx.collection(.response_headers, .all)) == null);
    try tx.processResponseHeaders(200, "HTTP/1.1");
    try std.testing.expectEqualStrings("text/plain", (try tx.collectionFirst(.response_headers, "content-type")).?.value);
}

test "transaction macros resolve current scalar and collection state" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();

    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/orders", "GET", "HTTP/1.1");
    try tx.addCollectionValue(.tx, "tenant", "north", .{ .origin = .rule, .offset = 0, .length = 5 });
    var compiled = try macros.Compiled.compile(std.testing.allocator, "%{REQUEST_METHOD} %{TX.tenant} %{RESPONSE_STATUS}", .{});
    defer compiled.deinit();
    const expanded = try tx.expandMacro(&compiled, std.testing.allocator);
    defer std.testing.allocator.free(expanded);
    try std.testing.expectEqualStrings("GET north ", expanded);
}

test "transaction collection targets apply exclusions, counts, replacement, and removal" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.addRequestHeader("X-One", "1");
    try tx.addRequestHeader("Authorization", "secret");

    const target: collections.Target = .{ .collection = .request_headers, .count_only = true };
    const exclusions = [_]collections.Target{.{ .collection = .request_headers, .selector = .{ .key = "authorization" } }};
    try std.testing.expectEqual(@as(usize, 1), (try tx.collectionCount(target, &exclusions)).?);

    const source: collections.Source = .{ .origin = .rule, .offset = 0, .length = 1 };
    try tx.setCollectionValue(.tx, "score", "1", source);
    try tx.setCollectionValue(.tx, "SCORE", "2", source);
    try std.testing.expectEqualStrings("2", (try tx.collectionFirst(.tx, "score")).?.value);
    try std.testing.expectEqual(@as(usize, 1), try tx.removeCollectionValues(.tx, .{ .key = "score" }));
    try std.testing.expect((try tx.collectionFirst(.tx, "score")) == null);
}

test "WAF configuration selects macro missing-value compatibility" {
    var builder = Builder.init(std.testing.allocator);
    builder.setMacroMissingPolicy(.expression);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    var compiled = try macros.Compiled.compile(std.testing.allocator, "x=%{TX.missing}", .{});
    defer compiled.deinit();
    const expanded = try tx.expandMacro(&compiled, std.testing.allocator);
    defer std.testing.allocator.free(expanded);
    try std.testing.expectEqualStrings("x=TX.missing", expanded);
}

test "argument cookie and file producers maintain derived collections and sizes" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/", "POST", "HTTP/1.1");

    const query_source: collections.Source = .{ .origin = .request_target, .offset = 3, .length = 5 };
    try tx.addArgument(.query, "q", "zig", query_source);
    try tx.addRequestCookie("Session", "abc", .{ .origin = .request_header, .offset = 20, .length = 3 });
    try std.testing.expectEqualStrings("zig", (try tx.collectionFirst(.args_get, "q")).?.value);
    try std.testing.expectEqualStrings("zig", (try tx.collectionFirst(.args, "q")).?.value);
    try std.testing.expectEqualStrings("q", (try tx.collectionFirst(.args_names, "q")).?.value);
    try std.testing.expectEqualStrings("4", (try tx.scalar(.args_combined_size)).?.value);
    try std.testing.expect((try tx.collectionFirst(.request_cookies, "session")) == null);
    try std.testing.expectEqualStrings("abc", (try tx.collectionFirst(.request_cookies, "Session")).?.value);

    try tx.processRequestHeaders();
    try tx.addArgument(.body, "name", "alice", .{ .origin = .request_body, .offset = 0, .length = 5 });
    try tx.addFileMetadata("avatar", "me.png", "/tmp/upload-1", 42, .{ .origin = .request_body, .offset = 10, .length = 42 });
    try tx.processRequestBody();
    try std.testing.expectEqualStrings("alice", (try tx.collectionFirst(.args_post, "name")).?.value);
    try std.testing.expectEqualStrings("13", (try tx.scalar(.args_combined_size)).?.value);
    try std.testing.expectEqualStrings("42", (try tx.scalar(.files_combined_size)).?.value);
    try std.testing.expectEqualStrings("me.png", (try tx.collectionFirst(.files_names, "avatar")).?.value);
    try std.testing.expectEqualStrings("/tmp/upload-1", (try tx.collectionFirst(.files_tmp_names, "avatar")).?.value);
}

test "engine initializes mutates flushes and expires persistent collections" {
    var memory = persistent.InMemoryBackend.init(std.testing.allocator);
    defer memory.deinit();
    var clock: TestClock = .{ .unix_nanoseconds = 5 * std.time.ns_per_s, .awake_nanoseconds = 0 };
    var builder = Builder.init(std.testing.allocator);
    builder.setPersistentBackend(memory.backend());
    builder.setClockSource(.{ .context = &clock, .nowFn = TestClock.now });
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;

    var first = waf.newTransaction();
    try first.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try first.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectEqual(PersistentInitialization.loaded, try first.initializePersistentCollection(.ip, "192.0.2.20"));
    try std.testing.expectEqual(PersistentInitialization.already_initialized, try first.initializePersistentCollection(.ip, "192.0.2.20"));
    try first.setPersistentCollectionValue(.ip, "score", "not-a-number");
    try first.addPersistentCollectionValue(.ip, "score", 2);
    try first.expirePersistentCollectionValue(.ip, "score", 1);
    try std.testing.expectEqualStrings("2", (try first.collectionFirst(.ip, "SCORE")).?.value);
    try first.processLogging();
    first.deinit();

    var second = waf.newTransaction();
    try second.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try second.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectEqual(PersistentInitialization.loaded, try second.initializePersistentCollection(.ip, "192.0.2.20"));
    try std.testing.expectEqualStrings("2", (try second.collectionFirst(.ip, "score")).?.value);
    second.deinit();

    clock.unix_nanoseconds += std.time.ns_per_s;
    var expired = waf.newTransaction();
    try expired.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try expired.processUri("/", "GET", "HTTP/1.1");
    _ = try expired.initializePersistentCollection(.ip, "192.0.2.20");
    try std.testing.expect((try expired.collectionFirst(.ip, "score")) == null);
    expired.deinit();
}

test "persistent engine APIs reject absent backend explicitly" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectError(error.PersistentBackendNotConfigured, tx.initializePersistentCollection(.ip, "192.0.2.20"));
}

test "persistent backend failure policy is explicit and observable" {
    var unavailable: UnavailablePersistence = .{};
    var open_builder = Builder.init(std.testing.allocator);
    open_builder.setPersistentBackend(unavailable.backend());
    open_builder.setPersistentFailurePolicy(.fail_open);
    const open_waf = try open_builder.build();
    defer open_waf.deinit() catch unreachable;
    var open_tx = open_waf.newTransaction();
    defer open_tx.deinit();
    try open_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try open_tx.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectEqual(PersistentInitialization.failed_open, try open_tx.initializePersistentCollection(.ip, "192.0.2.20"));
    try std.testing.expectEqual(PersistentFailure.unavailable, open_tx.lastPersistentFailure().?);

    var closed_builder = Builder.init(std.testing.allocator);
    closed_builder.setPersistentBackend(unavailable.backend());
    closed_builder.setPersistentFailurePolicy(.fail_closed);
    const closed_waf = try closed_builder.build();
    defer closed_waf.deinit() catch unreachable;
    var closed_tx = closed_waf.newTransaction();
    defer closed_tx.deinit();
    try closed_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try closed_tx.processUri("/", "GET", "HTTP/1.1");
    try std.testing.expectError(error.Unavailable, closed_tx.initializePersistentCollection(.ip, "192.0.2.20"));
    try std.testing.expectEqual(PersistentFailure.unavailable, closed_tx.lastPersistentFailure().?);
}

test "builder rejects missing persistent backend capabilities" {
    var unavailable: UnavailablePersistence = .{};
    var required = persistent.BackendFeatureSet.core();
    required.insert(.hard_deadlines);
    var builder = Builder.init(std.testing.allocator);
    builder.setPersistentBackend(unavailable.backend());
    builder.setPersistentRequiredFeatures(required);
    try std.testing.expectError(error.MissingPersistentBackendFeature, builder.build());
}

test "TX numeric mutation follows setvar prefix and overflow semantics" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    const source: collections.Source = .{ .origin = .rule, .offset = 0, .length = 0 };
    try tx.setCollectionValue(.tx, "score", "  -2tail", source);
    try tx.addTransactionCollectionValue("SCORE", 5);
    try std.testing.expectEqualStrings("3", (try tx.collectionFirst(.tx, "score")).?.value);
    try tx.setCollectionValue(.tx, "bad", "not-numeric", source);
    try tx.addTransactionCollectionValue("bad", 4);
    try std.testing.expectEqualStrings("4", (try tx.collectionFirst(.tx, "bad")).?.value);
    try tx.setCollectionValue(.tx, "maximum", "9223372036854775807", source);
    try std.testing.expectError(error.CapacityExceeded, tx.addTransactionCollectionValue("maximum", 1));
    try std.testing.expectEqualStrings("9223372036854775807", (try tx.collectionFirst(.tx, "maximum")).?.value);
}

test "setsid setuid and setrsc bind keys and compatibility scalars" {
    var memory = persistent.InMemoryBackend.init(std.testing.allocator);
    defer memory.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setPersistentBackend(memory.backend());
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/account", "GET", "HTTP/1.1");
    try std.testing.expectEqual(PersistentInitialization.loaded, try tx.setSessionCollection("session-1"));
    try std.testing.expectEqual(PersistentInitialization.loaded, try tx.setUserCollection("alice"));
    try std.testing.expectEqual(PersistentInitialization.loaded, try tx.setResourceCollection("/account"));
    try std.testing.expectEqualStrings("session-1", (try tx.scalar(.session_id)).?.value);
    try std.testing.expectEqualStrings("alice", (try tx.scalar(.user_id)).?.value);
    try std.testing.expectEqualStrings("/account", (try tx.scalar(.resource)).?.value);
}

test "rule projection uses chain-head metadata and capture replacement is bounded" {
    const input =
        \\SecRule ARGS @rx "id:42,chain,msg:'head message',rev:'2',severity:CRITICAL,maturity:9,accuracy:8,ver:'test/1',tag:'one',tag:'two'"
        \\SecRule TX @rx capture
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "match-projection.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();

    const projection = try tx.projectRuleMetadata(@fromBackingInt(1));
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(0)), projection.chain_head);
    try std.testing.expectEqual(@as(?u64, 42), projection.external_id);
    try std.testing.expectEqual(@as(?u8, 2), projection.severity);
    try std.testing.expectEqual(@as(u32, 2), projection.tags_count);
    try std.testing.expectEqualStrings("42", (try tx.collectionFirst(.rule, "id")).?.value);
    try std.testing.expectEqualStrings("head message", (try tx.collectionFirst(.rule, "msg")).?.value);
    try std.testing.expectEqualStrings("2", (try tx.collectionFirst(.rule, "severity")).?.value);
    try std.testing.expectEqualStrings("test/1", (try tx.collectionFirst(.rule, "ver")).?.value);

    const source: collections.Source = .{ .origin = .request_body, .offset = 100, .length = 5 };
    try tx.setCollectionValue(.tx, "1", "stale", source);
    try tx.setCollectionValue(.tx, "9", "stale", source);
    const capture_ranges = [_]?CaptureRange{
        .{ .start = 0, .end = 5 },
        null,
        .{ .start = 2, .end = 3 },
        .{ .start = 4, .end = 4 },
    };
    try std.testing.expectEqual(@as(usize, 3), try tx.replaceCaptures(.{
        .name = "ARGS:value",
        .value = "ab\x00cd",
        .source = source,
        .captures = &capture_ranges,
    }));
    try std.testing.expectEqualSlices(u8, "ab\x00cd", (try tx.collectionFirst(.tx, "0")).?.value);
    try std.testing.expect((try tx.collectionFirst(.tx, "1")) == null);
    try std.testing.expectEqualSlices(u8, "\x00", (try tx.collectionFirst(.tx, "2")).?.value);
    try std.testing.expectEqualStrings("", (try tx.collectionFirst(.tx, "3")).?.value);
    try std.testing.expect((try tx.collectionFirst(.tx, "9")) == null);
    try std.testing.expectEqual(@as(usize, 102), (try tx.collectionFirst(.tx, "2")).?.source.offset);

    const invalid = [_]?CaptureRange{.{ .start = 0, .end = 6 }};
    try std.testing.expectError(error.InvalidMatchContext, tx.replaceCaptures(.{
        .name = "ARGS:value",
        .value = "ab\x00cd",
        .source = source,
        .captures = &invalid,
    }));
    try std.testing.expectEqualSlices(u8, "ab\x00cd", (try tx.collectionFirst(.tx, "0")).?.value);
    const too_many = [_]?CaptureRange{ null, null, null, null, null, null, null, null, null, null, null };
    try std.testing.expectError(error.TooManyCaptures, tx.replaceCaptures(.{
        .name = "ARGS:value",
        .value = "value",
        .source = source,
        .captures = &too_many,
    }));
}

test "compiled effect text expands typed scalar keyed and unkeyed macros" {
    var parsed = try seclang.parser.parseBytes(
        std.testing.allocator,
        "effect-expansion.conf",
        "SecRule ARGS @rx \"id:1,setenv:'RESULT=%{REQUEST_URI}-%{TX.user}-%{ARGS}-%{TX.missing}'\"",
        .{},
        .{},
    );
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/macro", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    const source: collections.Source = .{ .origin = .rule, .offset = 0, .length = 1 };
    try tx.setCollectionValue(.tx, "user", "alice", source);
    try tx.setCollectionValue(.args, "first", "value", source);
    const effect = plan.nondisruptive_effects[plan.rules[0].effects_start];
    const expanded = try tx.expandEffectText(effect.value.?, std.testing.allocator);
    defer std.testing.allocator.free(expanded);
    try std.testing.expectEqualStrings("/macro-alice-value-", expanded);

    var expression_builder = Builder.init(std.testing.allocator);
    expression_builder.setRetainedPlan(plan);
    expression_builder.setMacroMissingPolicy(.expression);
    const expression_waf = try expression_builder.build();
    defer expression_waf.deinit() catch unreachable;
    var expression_tx = expression_waf.newTransaction();
    defer expression_tx.deinit();
    try expression_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try expression_tx.processUri("/macro", "GET", "HTTP/1.1");
    try expression_tx.processRequestHeaders();
    const preserved = try expression_tx.expandEffectText(effect.value.?, std.testing.allocator);
    defer std.testing.allocator.free(preserved);
    try std.testing.expectEqualStrings("/macro-TX.user-ARGS-TX.missing", preserved);
}

test "local matched-rule effects preflight sequential shadow state and commit atomically" {
    const input =
        \\SecDefaultAction "phase:2,log,auditlog,pass"
        \\SecRule ARGS @rx "id:42,msg:'rule %{TX.a}',logdata:'score=%{TX.b}',tag:'first',tag:'score-%{TX.a}',severity:CRITICAL,capture,nolog,setvar:'tx.a=1',setvar:'tx.b=+2',setvar:'tx.c=%{TX.a}',setvar:'tx.a=+%{TX.b}',setvar:'!tx.old',setvar:'tx.rule_msg=%{RULE.msg}',setenv:'ZIG_WAF_TEST_ENV_SHOULD_NOT_EXIST=%{TX.a}'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "local-effects.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    const source: collections.Source = .{ .origin = .request_body, .offset = 50, .length = 5 };
    try tx.setCollectionValue(.tx, "b", "3", source);
    try tx.setCollectionValue(.tx, "old", "stale", source);
    try tx.setCollectionValue(.tx, "9", "stale-capture", source);
    const captures = [_]?CaptureRange{ .{ .start = 0, .end = 5 }, null, .{ .start = 1, .end = 3 } };
    try std.testing.expect(std.c.getenv("ZIG_WAF_TEST_ENV_SHOULD_NOT_EXIST") == null);
    const outcome = try tx.applyLocalMatchedRule(@fromBackingInt(0), .{
        .name = "ARGS:value",
        .value = "value",
        .source = source,
        .captures = &captures,
    });
    try std.testing.expectEqual(@as(usize, 11), outcome.effects_applied);
    try std.testing.expectEqual(@as(usize, 2), outcome.captures_written);
    try std.testing.expect(!outcome.log);
    try std.testing.expect(outcome.audit_log);
    try std.testing.expectEqual(@as(usize, 0), outcome.pending_persistent_effects);
    try std.testing.expectEqualStrings("6", (try tx.collectionFirst(.tx, "a")).?.value);
    try std.testing.expectEqualStrings("5", (try tx.collectionFirst(.tx, "b")).?.value);
    try std.testing.expectEqualStrings("1", (try tx.collectionFirst(.tx, "c")).?.value);
    try std.testing.expect((try tx.collectionFirst(.tx, "old")) == null);
    try std.testing.expectEqualStrings("rule %{TX.a}", (try tx.collectionFirst(.tx, "rule_msg")).?.value);
    try std.testing.expectEqualStrings("6", (try tx.collectionFirst(.env, "ZIG_WAF_TEST_ENV_SHOULD_NOT_EXIST")).?.value);
    try std.testing.expectEqualStrings("rule %{TX.a}", (try tx.collectionFirst(.rule, "msg")).?.value);
    try std.testing.expectEqualStrings("value", (try tx.collectionFirst(.tx, "0")).?.value);
    try std.testing.expect((try tx.collectionFirst(.tx, "1")) == null);
    try std.testing.expectEqualStrings("al", (try tx.collectionFirst(.tx, "2")).?.value);
    try std.testing.expect((try tx.collectionFirst(.tx, "9")) == null);
    try std.testing.expect(std.c.getenv("ZIG_WAF_TEST_ENV_SHOULD_NOT_EXIST") == null);
    try std.testing.expectEqual(@as(usize, 1), tx.matchIntentCount());
    const intent = tx.matchIntent(outcome.intent).?;
    try std.testing.expectEqual(@as(?u64, 42), intent.external_id);
    try std.testing.expectEqual(@as(?u3, 2), intent.severity);
    try std.testing.expectEqualStrings("rule 6", intent.message.?);
    try std.testing.expectEqualStrings("score=5", intent.log_data.?);
    try std.testing.expectEqual(@as(usize, 2), intent.tags.len);
    try std.testing.expectEqualStrings("first", intent.tags[0]);
    try std.testing.expectEqualStrings("score-6", intent.tags[1]);
    try std.testing.expectEqualStrings("ARGS:value", intent.matched_name);
    try std.testing.expectEqualStrings("value", intent.matched_value);
    try std.testing.expect(!intent.log);
    try std.testing.expect(intent.audit_log);
    try std.testing.expectEqual(@as(usize, 11), intent.effects_applied);
}

test "failed local effect preflight preserves RULE ENV and TX state" {
    const input =
        \\SecRule ARGS @rx "id:7,msg:'new',setenv:'SHOULD_NOT_COMMIT=changed',setvar:'tx.maximum=+1'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "failed-local-effects.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var clock: TestClock = .{ .unix_nanoseconds = 0, .awake_nanoseconds = 0 };
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    builder.setClockSource(.{ .context = &clock, .nowFn = TestClock.now });
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    const source: collections.Source = .{ .origin = .rule, .offset = 0, .length = 1 };
    try tx.setCollectionValue(.rule, "msg", "old", source);
    try tx.setCollectionValue(.tx, "maximum", "9223372036854775807", source);
    clock.awake_nanoseconds = 5 * std.time.ns_per_ms;
    try std.testing.expectError(error.CapacityExceeded, tx.applyLocalMatchedRule(@fromBackingInt(0), .{
        .name = "ARGS:value",
        .value = "value",
        .source = source,
    }));
    try std.testing.expectEqualStrings("old", (try tx.collectionFirst(.rule, "msg")).?.value);
    try std.testing.expectEqualStrings("9223372036854775807", (try tx.collectionFirst(.tx, "maximum")).?.value);
    try std.testing.expect((try tx.collectionFirst(.env, "SHOULD_NOT_COMMIT")) == null);
    try std.testing.expectEqualStrings("0", tx.scalar_variables.get(.duration, .request_headers).?.value);
    try std.testing.expectEqual(@as(usize, 0), tx.matchIntentCount());
}

test "matched-rule application preserves visible state across every allocation failure" {
    const input =
        \\SecRule ARGS @rx "id:77,msg:'score=%{TX.score}',tag:'allocation-%{TX.score}',tag:'allocation-target',capture,setvar:'tx.score=+1',setenv:'SCORE=%{TX.score}',ctl:ruleRemoveById=77,ctl:ruleRemoveTargetByTag=allocation-target;ARGS:secret"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "action-allocation.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, retained_plan: *const compiled_plan.Plan) !void {
            var builder = Builder.init(allocator);
            builder.setRetainedPlan(retained_plan);
            const waf = try builder.build();
            defer waf.deinit() catch unreachable;
            var tx = waf.newTransaction();
            defer tx.deinit();
            try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
            try tx.processUri("/", "POST", "HTTP/1.1");
            try tx.processRequestHeaders();
            const source: collections.Source = .{ .origin = .request_body, .offset = 0, .length = 5 };
            try tx.setCollectionValue(.tx, "score", "4", source);
            const captures = [_]?CaptureRange{.{ .start = 0, .end = 5 }};
            const outcome = tx.applyLocalMatchedRule(@fromBackingInt(0), .{
                .name = "ARGS:value",
                .value = "value",
                .source = source,
                .captures = &captures,
            }) catch |err| {
                if (err == error.OutOfMemory) {
                    try std.testing.expectEqualStrings("4", (try tx.collectionFirst(.tx, "score")).?.value);
                    try std.testing.expect((try tx.collectionFirst(.env, "SCORE")) == null);
                    try std.testing.expect((try tx.collectionFirst(.tx, "0")) == null);
                    try std.testing.expectEqual(@as(usize, 0), tx.matchIntentCount());
                    try std.testing.expect(!tx.ruleExcluded(@fromBackingInt(0)));
                    try std.testing.expect(!tx.targetExcluded(@fromBackingInt(0), "ARGS:secret"));
                }
                return err;
            };
            try std.testing.expectEqualStrings("5", (try tx.collectionFirst(.tx, "score")).?.value);
            try std.testing.expectEqualStrings("value", tx.matchIntent(outcome.intent).?.matched_value);
            try std.testing.expect(tx.ruleExcluded(@fromBackingInt(0)));
            try std.testing.expect(tx.targetExcluded(@fromBackingInt(0), "ARGS:secret"));
        }
    }.run, .{plan});
}

test "matched-rule effects bind mutate expire and flush persistent namespaces" {
    const input =
        \\SecRule ARGS @rx "id:8,initcol:'ip=%{REMOTE_ADDR}',setvar:'ip.score=1',setvar:'ip.score=+2',deprecatevar:'ip.score=1/10',expirevar:'ip.score=60',setsid:'%{TX.sid}',setvar:'session.flag=1',setuid:'alice',setvar:'user.copy=%{SESSION.flag}',setrsc:'/account',setvar:'resource.hit'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "persistent-effects.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var memory = persistent.InMemoryBackend.init(std.testing.allocator);
    defer memory.deinit();
    var clock: TestClock = .{ .unix_nanoseconds = 5 * std.time.ns_per_s, .awake_nanoseconds = 0 };
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    builder.setPersistentBackend(memory.backend());
    builder.setClockSource(.{ .context = &clock, .nowFn = TestClock.now });
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    try tx.setCollectionValue(.tx, "sid", "session-1", .{ .origin = .rule, .offset = 0, .length = 9 });

    const outcome = try tx.applyMatchedRule(@fromBackingInt(0), .{
        .name = "ARGS:value",
        .value = "value",
        .source = .{ .origin = .request_body, .offset = 0, .length = 5 },
    });
    try std.testing.expectEqual(@as(usize, 11), outcome.effects_applied);
    try std.testing.expectEqual(@as(usize, 0), outcome.pending_persistent_effects);
    try std.testing.expectEqualStrings("3", (try tx.collectionFirst(.ip, "score")).?.value);
    try std.testing.expectEqualStrings("1", (try tx.collectionFirst(.session, "flag")).?.value);
    try std.testing.expectEqualStrings("1", (try tx.collectionFirst(.user, "copy")).?.value);
    try std.testing.expectEqualStrings("1", (try tx.collectionFirst(.resource, "hit")).?.value);
    try std.testing.expectEqualStrings("session-1", (try tx.scalar(.session_id)).?.value);
    try std.testing.expectEqualStrings("alice", (try tx.scalar(.user_id)).?.value);
    try std.testing.expectEqualStrings("/account", (try tx.scalar(.resource)).?.value);
    try std.testing.expectEqual(@as(usize, 4), try tx.flushPersistentCollections());

    var ip_before_expiry = try memory.backend().load(std.testing.allocator, .ip, "192.0.2.20", 65 * std.time.ns_per_s - 1, .{});
    defer ip_before_expiry.deinit();
    try std.testing.expectEqualStrings("3", ip_before_expiry.values.items[0].value);
    try std.testing.expectEqual(@as(i64, 5 * std.time.ns_per_s), ip_before_expiry.values.items[0].updated_at_ns.?);
    var ip_at_expiry = try memory.backend().load(std.testing.allocator, .ip, "192.0.2.20", 65 * std.time.ns_per_s, .{});
    defer ip_at_expiry.deinit();
    try std.testing.expectEqual(@as(usize, 0), ip_at_expiry.values.items.len);
}

test "matched decisions commit owned intervention and flow evidence atomically" {
    const input =
        \\SecRule ARGS @rx "id:10,setvar:'tx.path=blocked',redirect:'https://example.test/%{TX.path}',status:418"
        \\SecRule ARGS @rx "id:11,allow:request,skip:2"
        \\SecRule ARGS @rx "id:12,setvar:'tx.second=1',drop"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "runtime-decisions.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    const context: MatchContext = .{
        .name = "ARGS:value",
        .value = "value",
        .source = .{ .origin = .request_body, .offset = 0, .length = 5 },
    };

    var redirect_tx = waf.newTransaction();
    defer redirect_tx.deinit();
    try redirect_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try redirect_tx.processUri("/", "GET", "HTTP/1.1");
    try redirect_tx.processRequestHeaders();
    const redirect_outcome = try redirect_tx.applyMatchedRule(@fromBackingInt(0), context);
    try std.testing.expectEqual(compiled_plan.DisruptiveKind.redirect, redirect_outcome.disruptive);
    try std.testing.expectEqual(@as(u16, 302), redirect_outcome.disruptive_status);
    const intervention = (try redirect_tx.intervention()).?;
    try std.testing.expectEqual(Intervention.Action.redirect, intervention.action);
    try std.testing.expectEqualStrings("https://example.test/blocked", intervention.destination.?);
    try std.testing.expect(intervention.enforced);
    try std.testing.expect(redirect_tx.isPhaseInterrupted());
    const intent = redirect_tx.matchIntent(redirect_outcome.intent).?;
    try std.testing.expectEqualStrings(intervention.destination.?, intent.disruptive_destination.?);
    try std.testing.expectError(error.InterventionAlreadyRecorded, redirect_tx.applyMatchedRule(@fromBackingInt(2), context));
    try std.testing.expect((try redirect_tx.collectionFirst(.tx, "second")) == null);
    try std.testing.expectEqual(@as(usize, 1), redirect_tx.matchIntentCount());

    var allow_tx = waf.newTransaction();
    defer allow_tx.deinit();
    try allow_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try allow_tx.processUri("/", "GET", "HTTP/1.1");
    try allow_tx.processRequestHeaders();
    _ = try allow_tx.applyMatchedRule(@fromBackingInt(1), context);
    try std.testing.expectEqual(action_config.AllowScope.request, allow_tx.flowState().allow_scope.?);
    try std.testing.expectEqual(@as(u32, 2), allow_tx.flowState().skip);
    try std.testing.expect(allow_tx.isPhaseInterrupted());

    var detection_builder = Builder.init(std.testing.allocator);
    detection_builder.setRetainedPlan(plan);
    detection_builder.setMode(.detection_only);
    const detection_waf = try detection_builder.build();
    defer detection_waf.deinit() catch unreachable;
    var detection_tx = detection_waf.newTransaction();
    defer detection_tx.deinit();
    try detection_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try detection_tx.processUri("/", "GET", "HTTP/1.1");
    try detection_tx.processRequestHeaders();
    _ = try detection_tx.applyMatchedRule(@fromBackingInt(0), context);
    _ = try detection_tx.applyMatchedRule(@fromBackingInt(2), context);
    try std.testing.expect(!(try detection_tx.intervention()).?.enforced);
    try std.testing.expect(!detection_tx.isPhaseInterrupted());
    try std.testing.expect(!detection_tx.isTerminated());
    try std.testing.expectEqual(@as(usize, 2), detection_tx.matchIntentCount());
    try std.testing.expectEqualStrings("1", (try detection_tx.collectionFirst(.tx, "second")).?.value);
}

test "proxy decisions require an explicitly advertised connector capability" {
    const input =
        \\SecRule ARGS @rx "id:20,setvar:'tx.proxy=1',proxy:'https://upstream.test/%{REQUEST_URI}'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "proxy-capability.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    const context: MatchContext = .{
        .name = "ARGS:value",
        .value = "value",
        .source = .{ .origin = .request_body, .offset = 0, .length = 5 },
    };

    var disabled_builder = Builder.init(std.testing.allocator);
    disabled_builder.setRetainedPlan(plan);
    const disabled_waf = try disabled_builder.build();
    defer disabled_waf.deinit() catch unreachable;
    var disabled_tx = disabled_waf.newTransaction();
    defer disabled_tx.deinit();
    try disabled_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try disabled_tx.processUri("/proxy", "GET", "HTTP/1.1");
    try disabled_tx.processRequestHeaders();
    try std.testing.expectError(error.UnsupportedIntervention, disabled_tx.applyMatchedRule(@fromBackingInt(0), context));
    try std.testing.expect((try disabled_tx.collectionFirst(.tx, "proxy")) == null);
    try std.testing.expectEqual(@as(usize, 0), disabled_tx.matchIntentCount());

    var enabled_builder = Builder.init(std.testing.allocator);
    enabled_builder.setRetainedPlan(plan);
    enabled_builder.setInterventionCapabilities(.{ .proxy = true });
    const enabled_waf = try enabled_builder.build();
    defer enabled_waf.deinit() catch unreachable;
    var enabled_tx = enabled_waf.newTransaction();
    defer enabled_tx.deinit();
    try enabled_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try enabled_tx.processUri("/proxy", "GET", "HTTP/1.1");
    try enabled_tx.processRequestHeaders();
    _ = try enabled_tx.applyMatchedRule(@fromBackingInt(0), context);
    const intervention = (try enabled_tx.intervention()).?;
    try std.testing.expectEqual(Intervention.Action.proxy, intervention.action);
    try std.testing.expectEqualStrings("https://upstream.test//proxy", intervention.destination.?);
    try std.testing.expectEqualStrings("1", (try enabled_tx.collectionFirst(.tx, "proxy")).?.value);
}

test "phase cursor applies skip and phase-scoped allow without allocation" {
    const input =
        \\SecRule ARGS @rx "id:1,phase:2,skip:2"
        \\SecRule ARGS @rx "id:2,phase:2"
        \\SecRule ARGS @rx "id:3,phase:2"
        \\SecRule ARGS @rx "id:4,phase:2"
        \\SecRule ARGS @rx "id:5,phase:3,allow:phase"
        \\SecRule ARGS @rx "id:6,phase:3"
        \\SecRule ARGS @rx "id:7,phase:4"
        \\SecRule ARGS @rx "id:8,phase:5"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "phase-cursor.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    try tx.processRequestBody();
    const context: MatchContext = .{
        .name = "ARGS:value",
        .value = "value",
        .source = .{ .origin = .request_body, .offset = 0, .length = 5 },
    };

    var request_cursor = try PhaseCursor.init(&tx, .request_body);
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(0)), (try request_cursor.next()).?);
    _ = try tx.applyMatchedRule(@fromBackingInt(0), context);
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(3)), (try request_cursor.next()).?);
    try std.testing.expect((try request_cursor.next()) == null);

    try tx.processResponseHeaders(200, "HTTP/1.1");
    var response_headers_cursor = try PhaseCursor.init(&tx, .response_headers);
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(4)), (try response_headers_cursor.next()).?);
    _ = try tx.applyMatchedRule(@fromBackingInt(4), context);
    try std.testing.expect((try response_headers_cursor.next()) == null);

    try tx.processResponseBody();
    var response_body_cursor = try PhaseCursor.init(&tx, .response_body);
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(6)), (try response_body_cursor.next()).?);
    try tx.processLogging();
    var logging_cursor = try PhaseCursor.init(&tx, .logging);
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(7)), (try logging_cursor.next()).?);
}

test "dynamic skipAfter resolves staged macros and resumes after marker" {
    const input =
        \\SecRule ARGS @rx "id:1,phase:2,setvar:'tx.marker=DYNAMIC',skipAfter:'%{TX.marker}'"
        \\SecRule ARGS @rx "id:2,phase:2"
        \\SecMarker DYNAMIC
        \\SecRule ARGS @rx "id:3,phase:2"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "dynamic-skip-after.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    try tx.processRequestBody();
    var cursor = try PhaseCursor.init(&tx, .request_body);
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(0)), (try cursor.next()).?);
    const outcome = try tx.applyMatchedRule(@fromBackingInt(0), .{
        .name = "ARGS:value",
        .value = "value",
        .source = .{ .origin = .request_body, .offset = 0, .length = 5 },
    });
    try std.testing.expect(outcome.skip_after_active);
    try std.testing.expectEqual(@as(?compiled_plan.RuleId, @fromBackingInt(2)), outcome.skip_after_resume);
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(2)), (try cursor.next()).?);
    try std.testing.expect((try cursor.next()) == null);
}

test "runtime engine and request-body controls commit with match decisions" {
    const input =
        \\SecRule ARGS @rx "id:1,phase:1,setvar:'tx.mode=DetectionOnly',ctl:ruleEngine=%{TX.mode},ctl:requestBodyAccess=Off,ctl:requestBodyLimit=4,ctl:requestBodyProcessor=JSON,ctl:auditEngine=On,ctl:auditLogParts=ABCFHZ,deny"
        \\SecRule ARGS @rx "id:2,phase:1,ctl:ruleEngine=Off"
        \\SecRule ARGS @rx "id:3,phase:1"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "runtime-controls.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "POST", "HTTP/1.1");
    try tx.processRequestHeaders();
    const context: MatchContext = .{
        .name = "ARGS:value",
        .value = "value",
        .source = .{ .origin = .request_header, .offset = 0, .length = 5 },
    };
    var cursor = try PhaseCursor.init(&tx, .request_headers);
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(0)), (try cursor.next()).?);
    const outcome = try tx.applyMatchedRule(@fromBackingInt(0), context);
    try std.testing.expectEqual(@as(usize, 6), outcome.controls_applied);
    try std.testing.expect(!outcome.decision_enforced);
    try std.testing.expect(!(try tx.intervention()).?.enforced);
    try std.testing.expect(!tx.isPhaseInterrupted());
    const state = tx.controlState();
    try std.testing.expectEqual(action_config.EngineMode.detection_only, state.rule_engine);
    try std.testing.expectEqual(action_config.AuditEngine.on, state.audit_engine);
    try std.testing.expect(state.audit_parts.has('H'));
    try std.testing.expect(!state.request_body_access);
    try std.testing.expectEqual(@as(usize, 4), state.request_body_limit);
    try std.testing.expectEqual(action_config.BodyProcessor.json, state.request_body_processor.?);
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(1)), (try cursor.next()).?);
    _ = try tx.applyMatchedRule(@fromBackingInt(1), context);
    try std.testing.expectEqual(action_config.EngineMode.off, tx.controlState().rule_engine);
    try std.testing.expect((try cursor.next()) == null);
    try std.testing.expectError(error.RequestBodyLimitExceeded, tx.writeRequestBody("12345"));
}

test "invalid or late runtime controls roll back the entire match" {
    const input =
        \\SecRule ARGS @rx "id:1,phase:1,setvar:'tx.flag=1',ctl:requestBodyAccess=%{TX.missing}"
        \\SecRule ARGS @rx "id:2,phase:2,setvar:'tx.late=1',ctl:requestBodyAccess=On"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "control-rollback.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "POST", "HTTP/1.1");
    try tx.processRequestHeaders();
    const context: MatchContext = .{
        .name = "ARGS:value",
        .value = "value",
        .source = .{ .origin = .request_header, .offset = 0, .length = 5 },
    };
    try std.testing.expectError(error.InvalidActionValue, tx.applyMatchedRule(@fromBackingInt(0), context));
    try std.testing.expect((try tx.collectionFirst(.tx, "flag")) == null);
    try std.testing.expectEqual(@as(usize, 0), tx.matchIntentCount());
    try tx.processRequestBody();
    try std.testing.expectError(error.ControlTooLate, tx.applyMatchedRule(@fromBackingInt(1), context));
    try std.testing.expect((try tx.collectionFirst(.tx, "late")) == null);
    try std.testing.expectEqual(@as(usize, 0), tx.matchIntentCount());
}

test "runtime rule id and tag exclusions affect only subsequent cursor entries" {
    const input =
        \\SecRule ARGS @rx "id:1,phase:1,ctl:ruleRemoveById=2,ctl:ruleRemoveByTag=skip-me,ctl:ruleRemoveTargetById=4;ARGS:secret,ctl:ruleRemoveTargetByTag=group;REQUEST_HEADERS:authorization"
        \\SecRule ARGS @rx "id:2,phase:1"
        \\SecRule ARGS @rx "id:3,phase:1,tag:'skip-me'"
        \\SecRule ARGS @rx "id:4,phase:1,tag:'group'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "rule-exclusions.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    var cursor = try PhaseCursor.init(&tx, .request_headers);
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(0)), (try cursor.next()).?);
    const outcome = try tx.applyMatchedRule(@fromBackingInt(0), .{
        .name = "ARGS:value",
        .value = "value",
        .source = .{ .origin = .request_header, .offset = 0, .length = 5 },
    });
    try std.testing.expectEqual(@as(usize, 4), outcome.controls_applied);
    try std.testing.expect(tx.ruleExcluded(@fromBackingInt(1)));
    try std.testing.expect(tx.ruleExcluded(@fromBackingInt(2)));
    try std.testing.expect(!tx.ruleExcluded(@fromBackingInt(3)));
    try std.testing.expect(tx.targetExcluded(@fromBackingInt(3), "ARGS:secret"));
    try std.testing.expect(tx.targetExcluded(@fromBackingInt(3), "request_headers:Authorization"));
    try std.testing.expect(!tx.targetExcluded(@fromBackingInt(3), "ARGS:public"));
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(3)), (try cursor.next()).?);
    try std.testing.expect((try cursor.next()) == null);
}

test "failed combined effect preflight rolls back persistent session state" {
    const input =
        \\SecRule ARGS @rx "id:9,initcol:'ip=%{REMOTE_ADDR}',setvar:'ip.score=1',setvar:'tx.maximum=+1'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "persistent-rollback.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var memory = persistent.InMemoryBackend.init(std.testing.allocator);
    defer memory.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    builder.setPersistentBackend(memory.backend());
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    const source: collections.Source = .{ .origin = .rule, .offset = 0, .length = 1 };
    try tx.setCollectionValue(.tx, "maximum", "9223372036854775807", source);
    try std.testing.expectError(error.CapacityExceeded, tx.applyMatchedRule(@fromBackingInt(0), .{
        .name = "ARGS:value",
        .value = "value",
        .source = source,
    }));
    try std.testing.expect((try tx.collectionFirst(.ip, "score")) == null);
    try std.testing.expectEqualStrings("9223372036854775807", (try tx.collectionFirst(.tx, "maximum")).?.value);
    try std.testing.expectEqual(@as(usize, 0), try tx.flushPersistentCollections());
    try std.testing.expectEqual(@as(usize, 0), memory.records.items.len);
}

test "match intent count and byte limits fail before transaction publication" {
    const input =
        \\SecRule ARGS @rx "id:10,msg:'bounded',setvar:'tx.flag=1'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "intent-limits.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();

    var count_builder = Builder.init(std.testing.allocator);
    count_builder.setRetainedPlan(plan);
    count_builder.setLimits(.{ .max_match_intents = 1 });
    const count_waf = try count_builder.build();
    defer count_waf.deinit() catch unreachable;
    var count_tx = count_waf.newTransaction();
    defer count_tx.deinit();
    try count_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try count_tx.processUri("/", "GET", "HTTP/1.1");
    try count_tx.processRequestHeaders();
    const context: MatchContext = .{
        .name = "ARGS:value",
        .value = "value",
        .source = .{ .origin = .request_body, .offset = 0, .length = 5 },
    };
    _ = try count_tx.applyLocalMatchedRule(@fromBackingInt(0), context);
    try std.testing.expectError(error.TooManyMatchIntents, count_tx.applyLocalMatchedRule(@fromBackingInt(0), context));
    try std.testing.expectEqual(@as(usize, 1), count_tx.matchIntentCount());

    var bytes_builder = Builder.init(std.testing.allocator);
    bytes_builder.setRetainedPlan(plan);
    bytes_builder.setLimits(.{ .max_match_intent_bytes = 1 });
    const bytes_waf = try bytes_builder.build();
    defer bytes_waf.deinit() catch unreachable;
    var bytes_tx = bytes_waf.newTransaction();
    defer bytes_tx.deinit();
    try bytes_tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try bytes_tx.processUri("/", "GET", "HTTP/1.1");
    try bytes_tx.processRequestHeaders();
    try std.testing.expectError(error.MatchIntentStorageLimitExceeded, bytes_tx.applyLocalMatchedRule(@fromBackingInt(0), context));
    try std.testing.expectEqual(@as(usize, 0), bytes_tx.matchIntentCount());
    try std.testing.expect((try bytes_tx.collectionFirst(.tx, "flag")) == null);
}

test "complete chains apply member effects in order and publish one head intent" {
    const input =
        \\SecRule ARGS @rx "id:42,chain,msg:'chain %{TX.order}',logdata:'final=%{TX.order}',nolog,setvar:'tx.order=head'"
        \\SecRule TX @rx "chain,setvar:'tx.order=%{TX.order}-middle'"
        \\SecRule REQUEST_URI @rx "capture,auditlog,setvar:'tx.order=%{TX.order}-tail'"
        \\SecRule ARGS @rx "id:43,chain,setvar:'tx.should_not_commit=1'"
        \\SecRule TX @rx "setvar:'tx.maximum=+1'"
    ;
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "chain-effects.conf", input, .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer plan.deinit();
    var builder = Builder.init(std.testing.allocator);
    builder.setRetainedPlan(plan);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.20", 1234, "192.0.2.1", 443);
    try tx.processUri("/chain", "GET", "HTTP/1.1");
    try tx.processRequestHeaders();
    const capture_ranges = [_]?CaptureRange{.{ .start = 0, .end = 4 }};
    const matches = [_]MatchedRule{
        .{ .rule = @fromBackingInt(0), .context = .{
            .name = "ARGS:first",
            .value = "head",
            .source = .{ .origin = .request_body, .offset = 0, .length = 4 },
        } },
        .{ .rule = @fromBackingInt(1), .context = .{
            .name = "TX:order",
            .value = "head",
            .source = .{ .origin = .rule, .offset = 0, .length = 4 },
        } },
        .{ .rule = @fromBackingInt(2), .context = .{
            .name = "REQUEST_URI",
            .value = "tail",
            .source = .{ .origin = .request_target, .offset = 1, .length = 4 },
            .captures = &capture_ranges,
        } },
    };

    try std.testing.expectError(error.InvalidRuleChain, tx.applyMatchedRule(@fromBackingInt(0), matches[0].context));
    try std.testing.expectError(error.InvalidRuleChain, tx.applyMatchedChain(matches[0..2]));
    const reversed = [_]MatchedRule{ matches[0], matches[2], matches[1] };
    try std.testing.expectError(error.InvalidRuleChain, tx.applyMatchedChain(&reversed));
    try std.testing.expectEqual(@as(usize, 0), tx.matchIntentCount());
    try std.testing.expect((try tx.collectionFirst(.tx, "order")) == null);

    const outcome = try tx.applyMatchedChain(&matches);
    try std.testing.expectEqual(@as(usize, 6), outcome.effects_applied);
    try std.testing.expect(!outcome.log);
    try std.testing.expect(outcome.audit_log);
    try std.testing.expectEqualStrings("head-middle-tail", (try tx.collectionFirst(.tx, "order")).?.value);
    try std.testing.expectEqualStrings("tail", (try tx.collectionFirst(.tx, "0")).?.value);
    try std.testing.expectEqual(@as(usize, 1), tx.matchIntentCount());
    const intent = tx.matchIntent(outcome.intent).?;
    try std.testing.expectEqual(@as(compiled_plan.RuleId, @fromBackingInt(0)), intent.rule);
    try std.testing.expectEqualStrings("chain head-middle-tail", intent.message.?);
    try std.testing.expectEqualStrings("final=head-middle-tail", intent.log_data.?);
    try std.testing.expectEqualStrings("REQUEST_URI", intent.matched_name);
    try std.testing.expectEqualStrings("tail", intent.matched_value);

    try tx.setCollectionValue(.tx, "maximum", "9223372036854775807", .{ .origin = .rule, .offset = 0, .length = 1 });
    const failing = [_]MatchedRule{
        .{ .rule = @fromBackingInt(3), .context = matches[0].context },
        .{ .rule = @fromBackingInt(4), .context = matches[1].context },
    };
    try std.testing.expectError(error.CapacityExceeded, tx.applyMatchedChain(&failing));
    try std.testing.expect((try tx.collectionFirst(.tx, "should_not_commit")) == null);
    try std.testing.expectEqual(@as(usize, 1), tx.matchIntentCount());
}

test "compiled feature discovery is explicit" {
    var builder = Builder.init(std.testing.allocator);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    const compiled = waf.features();
    try std.testing.expect(compiled.has(.transaction_lifecycle));
    try std.testing.expect(compiled.has(.scalar_variables));
    try std.testing.expect(compiled.has(.atomic_hot_reload));
    try std.testing.expect(compiled.has(.compiled_execution_plan));
}

test "builder retains or transfers compiled plans explicitly" {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "builder.conf", "SecRule ARGS @rx id:1", .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};

    const retained_plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    var retained_builder = Builder.init(std.testing.allocator);
    retained_builder.setRetainedPlan(retained_plan);
    const retained_waf = try retained_builder.build();
    try std.testing.expectEqual(@as(usize, 2), retained_plan.sharedReferenceCount());
    retained_plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), retained_waf.compiledPlan().?.sharedReferenceCount());
    try std.testing.expectEqual(@as(usize, 1), retained_waf.compiledPlan().?.rules.len);
    try std.testing.expect(retained_waf.directiveConfiguration() != null);
    try retained_waf.deinit();

    const transferred_plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    var transfer_builder = Builder.init(std.testing.allocator);
    const transferred_waf = try transfer_builder.buildTransferringPlan(transferred_plan);
    try std.testing.expectEqual(transferred_plan, transferred_waf.compiledPlan().?);
    try transferred_waf.deinit();
}

test "builder validates directive schemas and reduced build capabilities before publication" {
    var unknown_parsed = try seclang.parser.parseBytes(std.testing.allocator, "unknown.conf", "SecMystery enabled", .{}, .{});
    defer unknown_parsed.deinit();
    var unknown_documents = [_]seclang.parser.Document{unknown_parsed.document};
    const unknown_plan = try compiled_plan.compile(std.testing.allocator, &unknown_parsed.registry, &unknown_documents, .{});
    defer unknown_plan.deinit();
    var unknown_builder = Builder.init(std.testing.allocator);
    unknown_builder.setRetainedPlan(unknown_plan);
    try std.testing.expectEqual(directives.DiagnosticCode.unknown_directive, unknown_builder.validateCompiledPlan(unknown_plan).diagnostic.code);
    try std.testing.expectError(error.InvalidDirectiveConfiguration, unknown_builder.build());
    try std.testing.expectEqual(@as(usize, 1), unknown_plan.sharedReferenceCount());

    var audit_parsed = try seclang.parser.parseBytes(std.testing.allocator, "reduced.conf", "SecAuditEngine On", .{}, .{});
    defer audit_parsed.deinit();
    var audit_documents = [_]seclang.parser.Document{audit_parsed.document};
    const audit_plan = try compiled_plan.compile(std.testing.allocator, &audit_parsed.registry, &audit_documents, .{});
    defer audit_plan.deinit();
    var reduced_builder = Builder.init(std.testing.allocator);
    reduced_builder.setDirectiveCapabilities(.coreOnly());
    try std.testing.expectError(error.InvalidDirectiveConfiguration, reduced_builder.buildTransferringPlan(audit_plan));
    try std.testing.expectEqual(@as(usize, 1), audit_plan.sharedReferenceCount());
}

test "failed directive generation leaves the active runtime usable" {
    var initial_builder = Builder.init(std.testing.allocator);
    const runtime = try initial_builder.buildRuntime();
    defer runtime.deinit() catch unreachable;

    var parsed = try seclang.parser.parseBytes(
        std.testing.allocator,
        "conflict.conf",
        "SecRequestBodyLimit 100\nSecRequestBodyNoFilesLimit 101",
        .{},
        .{},
    );
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const conflicting_plan = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer conflicting_plan.deinit();
    var replacement_builder = Builder.init(std.testing.allocator);
    try std.testing.expectError(error.InvalidDirectiveConfiguration, replacement_builder.buildTransferringPlan(conflicting_plan));

    var transaction = try runtime.newTransaction();
    try std.testing.expectEqual(@as(usize, 1), try runtime.activeTransactionCount());
    transaction.deinit();
}

test "failed builds preserve caller plan ownership" {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, "failed-build.conf", "SecAction pass", .{}, .{});
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const value = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer value.deinit();

    var builder = Builder.init(std.testing.allocator);
    builder.setLimits(.{ .max_header_count = 0 });
    builder.setRetainedPlan(value);
    try std.testing.expectError(error.InvalidLimit, builder.build());
    try std.testing.expectEqual(@as(usize, 1), value.sharedReferenceCount());
    try std.testing.expectError(error.InvalidLimit, builder.buildTransferringPlan(value));
    try std.testing.expectEqual(@as(usize, 1), value.sharedReferenceCount());
}

test "builder rejects unresolved static skipAfter after final source assembly" {
    var parsed = try seclang.parser.parseBytes(
        std.testing.allocator,
        "unresolved-marker.conf",
        "SecRule ARGS @rx \"id:1,skipAfter:EXTERNAL_MARKER\"",
        .{},
        .{},
    );
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const candidate = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer candidate.deinit();

    var builder = Builder.init(std.testing.allocator);
    switch (builder.validateExecutionPlan(candidate)) {
        .valid => return error.TestExpectedDiagnostic,
        .diagnostic => |diagnostic| {
            try std.testing.expectEqual(compiled_plan.DiagnosticCode.missing_static_marker, diagnostic.code);
            try std.testing.expectEqualStrings("WAF-PLAN-0114", diagnostic.code.id());
        },
    }
    try std.testing.expectError(error.InvalidExecutionPlan, builder.buildTransferringPlan(candidate));
    try std.testing.expectEqual(@as(usize, 1), candidate.sharedReferenceCount());
    const target = candidate.firstUnresolvedStaticMarker().?;
    try std.testing.expectEqualStrings("skipAfter", candidate.string(candidate.actions[target.action_index].name).?);
}

test "missing rule references are strict by default and explicit in compatibility mode" {
    var parsed = try seclang.parser.parseBytes(
        std.testing.allocator,
        "missing-rule.conf",
        "SecRuleRemoveById 99",
        .{},
        .{},
    );
    defer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};

    const strict_candidate = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    defer strict_candidate.deinit();
    var strict_builder = Builder.init(std.testing.allocator);
    try std.testing.expectError(error.MissingRuleReference, strict_builder.buildTransferringPlan(strict_candidate));
    try std.testing.expectEqual(@as(usize, 1), strict_candidate.sharedReferenceCount());

    const compatible_candidate = try compiled_plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    var compatible_builder = Builder.init(std.testing.allocator);
    compatible_builder.setMissingRulePolicy(.compatibility);
    const compatible = try compatible_builder.buildTransferringPlan(compatible_candidate);
    defer compatible.deinit() catch unreachable;
    try std.testing.expectEqual(@as(usize, 1), compatible.compiledPlan().?.missing_rule_references.len);
    try std.testing.expectEqual(compiled_plan.MissingRuleReferenceKind.remove_by_id, compatible.compiledPlan().?.missing_rule_references[0].kind);
}

test "transactions remain pinned to their compiled plan across reload" {
    var first_parsed = try seclang.parser.parseBytes(std.testing.allocator, "first.conf", "SecRule ARGS \"@contains first\" id:1", .{}, .{});
    defer first_parsed.deinit();
    var second_parsed = try seclang.parser.parseBytes(std.testing.allocator, "second.conf", "SecRule ARGS \"@contains second\" id:2", .{}, .{});
    defer second_parsed.deinit();
    var first_documents = [_]seclang.parser.Document{first_parsed.document};
    var second_documents = [_]seclang.parser.Document{second_parsed.document};
    const first_plan = try compiled_plan.compile(std.testing.allocator, &first_parsed.registry, &first_documents, .{});
    const second_plan = try compiled_plan.compile(std.testing.allocator, &second_parsed.registry, &second_documents, .{});

    var builder = Builder.init(std.testing.allocator);
    const runtime = try Runtime.init(std.testing.allocator, try builder.buildTransferringPlan(first_plan));
    var old_transaction = try runtime.newTransaction();
    const old_fingerprint = old_transaction.compiledPlan().?.fingerprint;
    const replacement = try builder.buildTransferringPlan(second_plan);
    var retired = try runtime.reload(replacement);
    var new_transaction = try runtime.newTransaction();
    try std.testing.expectEqualSlices(u8, &old_fingerprint, &old_transaction.compiledPlan().?.fingerprint);
    try std.testing.expect(!std.mem.eql(u8, &old_transaction.compiledPlan().?.fingerprint, &new_transaction.compiledPlan().?.fingerprint));
    try std.testing.expectError(error.TransactionsActive, retired.tryReclaim());
    old_transaction.deinit();
    try retired.tryReclaim();
    new_transaction.deinit();
    try runtime.deinit();
}

test "hot reload pins requests to retired generations until drain" {
    var initial_builder = Builder.init(std.testing.allocator);
    const runtime = try initial_builder.buildRuntime();

    var old_tx = try runtime.newTransaction();
    try old_tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try old_tx.processUri("/", "GET", "HTTP/1.1");
    try old_tx.processRequestHeaders();
    try old_tx.recordIntervention(.deny, 403, 1);
    try std.testing.expect((try old_tx.intervention()).?.enforced);

    var replacement_builder = Builder.init(std.testing.allocator);
    replacement_builder.setMode(.detection_only);
    const replacement = try replacement_builder.build();
    var retired = try runtime.reload(replacement);
    try std.testing.expectEqual(@as(usize, 1), retired.activeTransactionCount());
    try std.testing.expectError(error.TransactionsActive, retired.tryReclaim());

    var new_tx = try runtime.newTransaction();
    try new_tx.processConnection("127.0.0.1", 12345, "127.0.0.1", 443);
    try new_tx.processUri("/", "GET", "HTTP/1.1");
    try new_tx.processRequestHeaders();
    try new_tx.recordIntervention(.deny, 403, 2);
    try std.testing.expect(!(try new_tx.intervention()).?.enforced);
    old_tx.deinit();
    try retired.tryReclaim();
    try std.testing.expect(retired.isReclaimed());

    try std.testing.expectError(error.TransactionsActive, runtime.deinit());
    new_tx.deinit();
    try runtime.deinit();
}

test "runtime rejects ambiguous generation ownership" {
    var builder = Builder.init(std.testing.allocator);
    const initial = try builder.build();
    const runtime = try Runtime.init(std.testing.allocator, initial);
    defer runtime.deinit() catch unreachable;

    try std.testing.expectError(error.SameGeneration, runtime.reload(initial));

    const in_use = try builder.build();
    var tx = in_use.newTransaction();
    try std.testing.expectError(error.GenerationInUse, runtime.reload(in_use));
    tx.deinit();
    try in_use.deinit();
}

test "concurrent request pinning is safe across reload" {
    var builder = Builder.init(std.testing.allocator);
    const runtime = try builder.buildRuntime();
    const replacement = try builder.build();

    var pinned = std.atomic.Value(usize).init(0);
    var release = std.atomic.Value(bool).init(false);
    var failures = std.atomic.Value(usize).init(0);
    var workers: [4]ReloadWorker = undefined;
    var threads: [workers.len]std.Thread = undefined;
    for (&workers, &threads) |*worker, *thread| {
        worker.* = .{
            .runtime = runtime,
            .pinned = &pinned,
            .release = &release,
            .failures = &failures,
        };
        thread.* = try std.Thread.spawn(.{}, ReloadWorker.run, .{worker});
    }

    while (pinned.load(.acquire) != workers.len) std.atomic.spinLoopHint();
    var retired = try runtime.reload(replacement);
    try std.testing.expectEqual(workers.len, retired.activeTransactionCount());
    release.store(true, .release);
    for (&threads) |*thread| thread.join();

    try std.testing.expectEqual(@as(usize, 0), failures.load(.acquire));
    try retired.tryReclaim();
    try runtime.deinit();
}
