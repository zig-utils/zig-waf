//! Reusable deterministic and coverage-guided structural-plan fuzz oracle.

const std = @import("std");
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
                .plan => |compiled| try validate(compiled, document.directives.items.len),
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
            rule.transformations_start + rule.transformations_count > compiled.transformations.len)
        {
            return error.InvalidPlanFuzzRange;
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
    var chain_members: usize = 0;
    for (compiled.rules) |rule| chain_members += @intFromBool(rule.chain_position != 0);
    if (indexed_rules + chain_members != compiled.rules.len) return error.InvalidPlanFuzzPhaseIndex;
}

test "plan fuzz oracle accepts valid malformed and arbitrary bytes" {
    const cases = [_][]const u8{
        "SecAction pass",
        "SecRule ARGS @rx id:1",
        "SecRule ARGS @rx chain",
        "SecRule ARGS @rx id:1\nSecRule TX @rx id:1",
        "SecDefaultAction \"phase:2,t:lowercase,pass\"\nSecRule ARGS \"@pm one two\" \"id:2,deny\"",
        "\x00\xff\x80",
    };
    for (cases) |input| try fuzzOne(std.testing.allocator, input);
}
