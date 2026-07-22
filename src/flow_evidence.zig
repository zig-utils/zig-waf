const std = @import("std");
const action_config = @import("action_config.zig");
const plan = @import("plan.zig");
const seclang = @import("seclang/root.zig");

pub const json = @embedFile("compatibility/evidence/disruptive-flow-controls.json");

const decisions = @embedFile("compatibility/fixtures/disruptive-flow-controls/decisions.conf");
const controls = @embedFile("compatibility/fixtures/disruptive-flow-controls/controls.conf");

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

test "disruptive flow evidence pins upstream revisions and plan ABI" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings("WAF-15", object.get("issue").?.string);
    try std.testing.expectEqual(@as(i64, plan.compiler_abi_version), object.get("compilerAbi").?.integer);
    try std.testing.expectEqualStrings("7ea9fefbe0ba409d8733b4d682c8c4c059cd028d", object.get("baselines").?.object.get("modsecurity").?.object.get("commit").?.string);
    try std.testing.expectEqualStrings("27069d06c896be74b77b9a6c0b539a0cbfaca360", object.get("baselines").?.object.get("coraza").?.object.get("commit").?.string);
    try std.testing.expectEqualStrings("55b09f5acfd16413e7b31041100711ceb7adc89c", object.get("baselines").?.object.get("crs").?.object.get("commit").?.string);
    try std.testing.expectEqual(@as(i64, 0), object.get("qualification").?.object.get("unexplainedMismatches").?.integer);
}

test "pinned decision fixture compiles block flow redirect allow drop and pass" {
    var fixture = try compileFixture("decisions.conf", decisions);
    defer fixture.parsed.deinit();
    defer fixture.compiled.deinit();
    try std.testing.expectEqual(@as(usize, 6), fixture.compiled.rules.len);
    try std.testing.expect(fixture.compiled.rules[0].disruptive.declared_block);
    try std.testing.expectEqual(plan.DisruptiveKind.deny, fixture.compiled.rules[0].disruptive.kind);
    try std.testing.expect(fixture.compiled.rules[0].flow.skip_after_target != null);
    try std.testing.expectEqual(plan.DisruptiveKind.redirect, fixture.compiled.rules[2].disruptive.kind);
    try std.testing.expectEqual(action_config.AllowScope.phase, fixture.compiled.rules[3].disruptive.allow_scope);
    try std.testing.expectEqual(plan.DisruptiveKind.drop, fixture.compiled.rules[4].disruptive.kind);
    try std.testing.expectEqual(plan.DisruptiveKind.pass, fixture.compiled.rules[5].disruptive.kind);
}

test "pinned control fixture compiles the stable typed control families" {
    var fixture = try compileFixture("controls.conf", controls);
    defer fixture.parsed.deinit();
    defer fixture.compiled.deinit();
    const rule = fixture.compiled.rules[0];
    const compiled_controls = fixture.compiled.runtime_controls[rule.controls_start..][0..rule.controls_count];
    try std.testing.expectEqual(@as(usize, 11), compiled_controls.len);
    try std.testing.expectEqual(action_config.ControlKind.rule_engine, compiled_controls[0].kind);
    try std.testing.expectEqual(action_config.ControlKind.rule_remove_target_by_tag, compiled_controls[9].kind);
    try std.testing.expectEqual(action_config.ControlKind.rule_remove_target_by_id, compiled_controls[10].kind);
}
