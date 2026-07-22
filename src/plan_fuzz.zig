//! Reusable deterministic and coverage-guided structural-plan fuzz oracle.

const std = @import("std");
const directives = @import("directives.zig");
const plan = @import("plan.zig");
const seclang = @import("seclang/root.zig");

pub fn fuzzOne(allocator: std.mem.Allocator, input: []const u8) !void {
    var parsed = seclang.parser.parseBytesOutcome(allocator, "plan-fuzz.conf", input, .{}, .{}) catch |failure| switch (failure) {
        error.InvalidUtf8 => return,
        else => |other| return other,
    };
    defer parsed.deinit();
    switch (parsed.outcome) {
        .diagnostic => |value| try parsed.registry.validateSpan(value.primary),
        .document => |document| {
            var documents = [_]seclang.parser.Document{document};
            var outcome = try plan.compileOutcome(allocator, &parsed.registry, &documents, .{});
            defer outcome.deinit();
            switch (outcome) {
                .diagnostic => |value| {
                    try parsed.registry.validateSpan(value.primary);
                    if (value.secondary) |secondary| try parsed.registry.validateSpan(secondary);
                    if (value.code.id().len == 0 or value.message.len == 0) return error.InvalidPlanFuzzDiagnostic;
                },
                .plan => |compiled| {
                    try validate(compiled, document.directives.items.len);
                    switch (directives.Configuration.init(compiled, .full())) {
                        .configuration => |configuration| {
                            if (std.mem.allEqual(u8, &configuration.fingerprint, 0))
                                return error.InvalidDirectiveFuzzFingerprint;
                            for (directives.registry) |entry| {
                                var occurrences = configuration.occurrences(entry.id);
                                while (occurrences.next()) |occurrence| {
                                    var values = occurrence.values();
                                    while (values.next()) |value| try parsed.registry.validateSpan(value.source);
                                }
                            }
                        },
                        .diagnostic => |value| {
                            try parsed.registry.validateSpan(value.primary);
                            if (value.secondary) |secondary| try parsed.registry.validateSpan(secondary);
                            if (value.code.id().len == 0 or value.message.len == 0)
                                return error.InvalidDirectiveFuzzDiagnostic;
                        },
                    }
                },
            }
        },
    }
}

fn validate(compiled: *const plan.Plan, directive_count: usize) !void {
    if (compiled.compiler_abi != plan.compiler_abi_version or
        std.mem.allEqual(u8, &compiled.fingerprint, 0) or
        compiled.directives.len != directive_count)
    {
        return error.InvalidPlanFuzzInvariant;
    }
    var indexed_rules: usize = 0;
    for (1..6) |phase| {
        var previous: ?u32 = null;
        for (compiled.phaseRules(@intCast(phase))) |rule_id| {
            const index: usize = @backingInt(rule_id);
            if (index >= compiled.rules.len) return error.InvalidPlanFuzzRuleId;
            const rule = compiled.rules[index];
            if (rule.phase != phase or rule.chain_position != 0 or rule.chain_head != rule_id)
                return error.InvalidPlanFuzzPhaseIndex;
            if (rule.removed_by != null) return error.InvalidPlanFuzzRemovedRule;
            if (previous) |prior| if (prior >= index) return error.InvalidPlanFuzzOrdering;
            previous = @intCast(index);
            indexed_rules += 1;
        }
    }
    for (compiled.rules, 0..) |rule, index| {
        _ = try compiled.sourceSlice(rule.source);
        if (@backingInt(rule.directive) >= compiled.directives.len or
            @backingInt(rule.chain_head) > index or
            rule.targets_start + rule.targets_count > compiled.targets.len or
            rule.actions_start + rule.actions_count > compiled.actions.len or
            rule.transformations_start + rule.transformations_count > compiled.transformations.len or
            rule.metadata.tags_start + rule.metadata.tags_count > compiled.metadata_tags.len or
            rule.effects_start + rule.effects_count > compiled.nondisruptive_effects.len)
        {
            return error.InvalidPlanFuzzRange;
        }
        try validateMetadataText(compiled, rule.metadata.revision);
        try validateMetadataText(compiled, rule.metadata.message);
        try validateMetadataText(compiled, rule.metadata.log_data);
        try validateMetadataText(compiled, rule.metadata.version);
        for (compiled.metadata_tags[rule.metadata.tags_start..][0..rule.metadata.tags_count]) |tag|
            try validateMetadataText(compiled, tag);
        for (compiled.nondisruptive_effects[rule.effects_start..][0..rule.effects_count]) |effect| {
            if (effect.action_index >= compiled.actions.len) return error.InvalidPlanFuzzEffect;
            try validateEffectText(compiled, effect.name);
            try validateEffectText(compiled, effect.value);
            try validateEffectText(compiled, effect.auxiliary);
        }
        if (rule.chain_position == 0 and rule.chain_head != @as(plan.RuleId, @fromBackingInt(@intCast(index))))
            return error.InvalidPlanFuzzChain;
        if (rule.operator.negated and rule.operator.prefilter != null) return error.InvalidPlanFuzzPrefilter;
        if (rule.operator.prefilter) |prefilter| {
            if (prefilter.literals_count == 0 or
                prefilter.literals_start + prefilter.literals_count > compiled.prefilter_literals.len)
            {
                return error.InvalidPlanFuzzPrefilter;
            }
        }
    }
    for (compiled.macro_programs) |program| {
        const source = compiled.string(program.source) orelse return error.InvalidPlanFuzzMacro;
        if (program.tokens_count == 0 or program.tokens_start + program.tokens_count > compiled.macro_tokens.len)
            return error.InvalidPlanFuzzMacro;
        for (compiled.macro_tokens[program.tokens_start..][0..program.tokens_count]) |token| {
            if (token.source_start + token.source_length > source.len) return error.InvalidPlanFuzzMacro;
            if (token.kind == .literal and (token.name != null or token.key != null)) return error.InvalidPlanFuzzMacro;
            if (token.kind != .literal and (token.name == null or compiled.string(token.name.?) == null))
                return error.InvalidPlanFuzzMacro;
            if (token.key) |key| _ = compiled.string(key) orelse return error.InvalidPlanFuzzMacro;
        }
    }
    var nonindexed_rules: usize = 0;
    for (compiled.rules) |rule| {
        nonindexed_rules += @intFromBool(rule.chain_position != 0 or rule.removed_by != null);
    }
    if (indexed_rules + nonindexed_rules != compiled.rules.len) return error.InvalidPlanFuzzPhaseIndex;
    for (compiled.rule_removals) |removal| {
        if (@backingInt(removal.directive) >= compiled.directives.len or @backingInt(removal.chain_head) >= compiled.rules.len)
            return error.InvalidPlanFuzzRemoval;
        if (compiled.rules[@backingInt(removal.chain_head)].removed_by != removal.directive)
            return error.InvalidPlanFuzzRemoval;
    }
    for (compiled.skip_after_targets) |target| {
        if (@backingInt(target.rule) >= compiled.rules.len or target.action_index >= compiled.actions.len)
            return error.InvalidPlanFuzzMarker;
        if (!target.dynamic) {
            if (target.marker) |marker| {
                if (@backingInt(marker) >= compiled.markers.len) return error.InvalidPlanFuzzMarker;
            }
        }
        if (target.resume_rule) |resume_rule| if (@backingInt(resume_rule) >= compiled.rules.len)
            return error.InvalidPlanFuzzMarker;
    }
    for (compiled.missing_rule_references) |reference| {
        if (@backingInt(reference.directive) >= compiled.directives.len or reference.interval.first > reference.interval.last)
            return error.InvalidPlanFuzzMissingReference;
    }
}

fn validateMetadataText(compiled: *const plan.Plan, maybe_text: ?plan.MetadataText) !void {
    const metadata = maybe_text orelse return;
    _ = compiled.string(metadata.value) orelse return error.InvalidPlanFuzzMetadata;
    if (metadata.macro) |program| if (@backingInt(program) >= compiled.macro_programs.len)
        return error.InvalidPlanFuzzMetadata;
}

fn validateEffectText(compiled: *const plan.Plan, maybe_text: ?plan.EffectText) !void {
    const effect = maybe_text orelse return;
    _ = compiled.string(effect.value) orelse return error.InvalidPlanFuzzEffect;
    if (effect.macro) |program| if (@backingInt(program) >= compiled.macro_programs.len)
        return error.InvalidPlanFuzzEffect;
}

test "plan fuzz oracle accepts valid malformed and arbitrary bytes" {
    const cases = [_][]const u8{
        "SecAction pass",
        "SecRule ARGS @rx id:1",
        "SecRule ARGS @rx chain",
        "SecRule ARGS @rx id:1\nSecRule TX @rx id:1",
        "SecDefaultAction \"phase:2,t:lowercase,pass\"\nSecRule ARGS \"@pm one two\" \"id:2,deny\"",
        "SecRule ARGS @rx id:1\nSecRule ARGS @rx id:2\nSecRuleRemoveById 2",
        "SecRule ARGS @rx \"id:1,tag:'group',msg:'hello',deny,t:lowercase\"\nSecRuleUpdateTargetById 1 \"!ARGS:secret|TX\"\nSecRuleUpdateTargetByTag group FILES\nSecRuleUpdateActionById 1 \"pass,t:none,t:trim\"",
        "SecRule ARGS @rx \"id:1,skipAfter:END\"\nSecRule TX @rx id:2\nSecMarker END\nSecRule ARGS @rx id:3",
        "SecRuleRemoveById \"99 100-110\"\nSecRuleUpdateActionById 200 pass",
        "SecRemoteRulesFailAction Warn\nSecRemoteRules key https://rules.example.test/bundle",
        "\x00\xff\x80",
    };
    for (cases) |input| try fuzzOne(std.testing.allocator, input);
}
