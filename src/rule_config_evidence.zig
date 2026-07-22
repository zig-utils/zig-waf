const std = @import("std");
const plan = @import("plan.zig");
const rule_config = @import("rule_config.zig");
const seclang = @import("seclang/root.zig");

pub const json = @embedFile("compatibility/evidence/rule-configuration.json");

const default_actions = @embedFile("compatibility/fixtures/rule-configuration/default-actions.conf");
const overlays = @embedFile("compatibility/fixtures/rule-configuration/overlays.conf");
const markers = @embedFile("compatibility/fixtures/rule-configuration/markers.conf");
const missing_references = @embedFile("compatibility/fixtures/rule-configuration/missing-references.conf");

fn compileFixture(name: []const u8, input: []const u8) !struct {
    parsed: seclang.parser.OwnedDocument,
    compiled: *plan.Plan,
} {
    var parsed = try seclang.parser.parseBytes(std.testing.allocator, name, input, .{}, .{});
    errdefer parsed.deinit();
    var documents = [_]seclang.parser.Document{parsed.document};
    const compiled = try plan.compile(std.testing.allocator, &parsed.registry, &documents, .{});
    return .{ .parsed = parsed, .compiled = compiled };
}

fn countActions(compiled: *const plan.Plan, rule: plan.Rule, name: []const u8) usize {
    var count: usize = 0;
    for (compiled.actions[rule.actions_start..][0..rule.actions_count]) |action| {
        if (std.ascii.eqlIgnoreCase(compiled.string(action.name).?, name)) count += 1;
    }
    return count;
}

test "rule configuration evidence pins upstream revisions and compiler ABI" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings("WAF-13", object.get("issue").?.string);
    try std.testing.expectEqual(@as(i64, plan.compiler_abi_version), object.get("compilerAbi").?.integer);
    try std.testing.expectEqualStrings("7ea9fefbe0ba409d8733b4d682c8c4c059cd028d", object.get("baselines").?.object.get("modsecurity").?.object.get("commit").?.string);
    try std.testing.expectEqualStrings("27069d06c896be74b77b9a6c0b539a0cbfaca360", object.get("baselines").?.object.get("coraza").?.object.get("commit").?.string);
    try std.testing.expectEqualStrings("55b09f5acfd16413e7b31041100711ceb7adc89c", object.get("baselines").?.object.get("crs").?.object.get("commit").?.string);
    try std.testing.expectEqual(@as(i64, 0), object.get("qualification").?.object.get("unexplainedMismatches").?.integer);
}

test "pinned default-action differential fixture" {
    var fixture = try compileFixture("default-actions.conf", default_actions);
    defer fixture.parsed.deinit();
    defer fixture.compiled.deinit();
    try std.testing.expectEqual(@as(usize, 2), fixture.compiled.defaults.len);
    try std.testing.expectEqual(@as(u8, 1), fixture.compiled.rules[0].phase);
    try std.testing.expectEqual(@as(u8, 2), fixture.compiled.rules[1].phase);
    try std.testing.expectEqual(@as(?plan.DefaultId, null), fixture.compiled.rules[2].default);
    try std.testing.expectEqualStrings("lowercase", fixture.compiled.string(fixture.compiled.transformations[fixture.compiled.rules[0].transformations_start].name).?);
    try std.testing.expectEqualStrings("trim", fixture.compiled.string(fixture.compiled.transformations[fixture.compiled.rules[1].transformations_start].name).?);
}

test "pinned removal target and action differential fixture" {
    var fixture = try compileFixture("overlays.conf", overlays);
    defer fixture.parsed.deinit();
    defer fixture.compiled.deinit();
    try std.testing.expectEqual(@as(usize, 1), fixture.compiled.rule_removals.len);
    try std.testing.expectEqual(@as(usize, 2), fixture.compiled.phaseRules(2).len);
    try std.testing.expectEqual(@as(u32, 6), fixture.compiled.rules[0].targets_count);
    try std.testing.expectEqual(@as(usize, 0), countActions(fixture.compiled, fixture.compiled.rules[0], "deny"));
    try std.testing.expectEqual(@as(usize, 1), countActions(fixture.compiled, fixture.compiled.rules[0], "pass"));
    try std.testing.expectEqual(@as(usize, 2), countActions(fixture.compiled, fixture.compiled.rules[0], "tag"));
    try std.testing.expectEqual(@as(usize, 1), fixture.compiled.rules[0].transformations_count);
    try std.testing.expectEqualStrings("trim", fixture.compiled.string(fixture.compiled.transformations[fixture.compiled.rules[0].transformations_start].name).?);
}

test "pinned skip-after marker differential fixture" {
    var fixture = try compileFixture("markers.conf", markers);
    defer fixture.parsed.deinit();
    defer fixture.compiled.deinit();
    try std.testing.expectEqual(@as(usize, 3), fixture.compiled.markers.len);
    try std.testing.expectEqual(@as(usize, 1), fixture.compiled.skip_after_targets.len);
    const target = fixture.compiled.skip_after_targets[0];
    try std.testing.expectEqual(@as(?plan.MarkerId, @fromBackingInt(1)), target.marker);
    try std.testing.expectEqual(@as(?plan.RuleId, @fromBackingInt(2)), target.resume_rule);
}

test "pinned missing-reference differential fixture retains exact intervals" {
    var fixture = try compileFixture("missing-references.conf", missing_references);
    defer fixture.parsed.deinit();
    defer fixture.compiled.deinit();
    try std.testing.expectEqual(@as(usize, 4), fixture.compiled.missing_rule_references.len);
    try std.testing.expectEqual(rule_config.IdInterval{ .first = 2, .last = 2 }, fixture.compiled.missing_rule_references[0].interval);
    try std.testing.expectEqual(rule_config.IdInterval{ .first = 10, .last = 20 }, fixture.compiled.missing_rule_references[1].interval);
    try std.testing.expectEqual(plan.MissingRuleReferenceKind.update_target_by_id, fixture.compiled.missing_rule_references[2].kind);
    try std.testing.expectEqual(plan.MissingRuleReferenceKind.update_action_by_id, fixture.compiled.missing_rule_references[3].kind);
}
