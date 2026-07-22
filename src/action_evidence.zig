const std = @import("std");
const engine = @import("engine.zig");
const persistent = @import("persistent.zig");
const plan = @import("plan.zig");
const seclang = @import("seclang/root.zig");

pub const json = @embedFile("compatibility/evidence/non-disruptive-actions.json");

const metadata_local = @embedFile("compatibility/fixtures/non-disruptive-actions/metadata-local.conf");
const persistent_chain = @embedFile("compatibility/fixtures/non-disruptive-actions/persistent-chain.conf");

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

test "non-disruptive evidence pins revisions and runtime ABI" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings("WAF-14", object.get("issue").?.string);
    try std.testing.expectEqual(@as(i64, plan.compiler_abi_version), object.get("compilerAbi").?.integer);
    try std.testing.expectEqual(@as(i64, persistent.backend_abi_version), object.get("persistentBackendAbi").?.integer);
    try std.testing.expectEqualStrings("7ea9fefbe0ba409d8733b4d682c8c4c059cd028d", object.get("baselines").?.object.get("modsecurity").?.object.get("commit").?.string);
    try std.testing.expectEqualStrings("27069d06c896be74b77b9a6c0b539a0cbfaca360", object.get("baselines").?.object.get("coraza").?.object.get("commit").?.string);
    try std.testing.expectEqualStrings("55b09f5acfd16413e7b31041100711ceb7adc89c", object.get("baselines").?.object.get("crs").?.object.get("commit").?.string);
    try std.testing.expectEqual(@as(i64, 0), object.get("qualification").?.object.get("unexplainedMismatches").?.integer);
}

test "pinned local metadata fixture executes post-action expansion" {
    var fixture = try compileFixture("metadata-local.conf", metadata_local);
    defer fixture.parsed.deinit();
    defer fixture.compiled.deinit();
    try std.testing.expectEqual(@as(usize, 1), fixture.compiled.rules.len);
    try std.testing.expectEqual(@as(u32, 8), fixture.compiled.rules[0].effects_count);
    var builder = engine.Builder.init(std.testing.allocator);
    builder.setRetainedPlan(fixture.compiled);
    const waf = try builder.build();
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/", "POST", "HTTP/1.1");
    try tx.processRequestHeaders();
    const captures = [_]?engine.CaptureRange{.{ .start = 0, .end = 5 }};
    const outcome = try tx.applyLocalMatchedRule(@fromBackingInt(0), .{
        .name = "ARGS:value",
        .value = "value",
        .source = .{ .origin = .request_body, .offset = 0, .length = 5 },
        .captures = &captures,
    });
    try std.testing.expectEqualStrings("6", (try tx.collectionFirst(.tx, "score")).?.value);
    try std.testing.expect(!outcome.log);
    try std.testing.expect(outcome.audit_log);
    const intent = tx.matchIntent(outcome.intent).?;
    try std.testing.expectEqualStrings("score=6", intent.message.?);
    try std.testing.expectEqualStrings("copy=6", intent.log_data.?);
    try std.testing.expectEqualStrings("score-6", intent.tags[1]);
}

test "pinned persistent chain fixture compiles every effect family in order" {
    var fixture = try compileFixture("persistent-chain.conf", persistent_chain);
    defer fixture.parsed.deinit();
    defer fixture.compiled.deinit();
    try std.testing.expectEqual(@as(usize, 3), fixture.compiled.rules.len);
    var effects: usize = 0;
    for (fixture.compiled.rules) |rule| effects += rule.effects_count;
    try std.testing.expectEqual(@as(usize, 11), effects);
    const head = fixture.compiled.rules[0];
    const head_effects = fixture.compiled.nondisruptive_effects[head.effects_start..][0..head.effects_count];
    try std.testing.expectEqual(plan.EffectKind.initcol, head_effects[0].kind);
    try std.testing.expectEqual(plan.EffectKind.setvar, head_effects[1].kind);
    try std.testing.expectEqual(plan.EffectKind.setvar, head_effects[2].kind);
    try std.testing.expectEqual(plan.EffectKind.deprecatevar, head_effects[3].kind);
    try std.testing.expectEqual(plan.EffectKind.expirevar, head_effects[4].kind);
    try std.testing.expectEqual(plan.EffectKind.setsid, head_effects[5].kind);
}
