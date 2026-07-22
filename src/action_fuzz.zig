//! Reusable deterministic and coverage-guided SecLang action runtime oracle.

const std = @import("std");
const engine = @import("engine.zig");
const plan = @import("plan.zig");
const seclang = @import("seclang/root.zig");

pub fn fuzzOne(allocator: std.mem.Allocator, input: []const u8) !void {
    var parsed = seclang.parser.parseBytesOutcome(allocator, "action-fuzz.conf", input, .{}, .{}) catch |failure| switch (failure) {
        error.InvalidUtf8 => return,
        else => |other| return other,
    };
    defer parsed.deinit();
    const document = switch (parsed.outcome) {
        .diagnostic => return,
        .document => |document| document,
    };
    var documents = [_]seclang.parser.Document{document};
    var compile_outcome = try plan.compileOutcome(allocator, &parsed.registry, &documents, .{});
    defer compile_outcome.deinit();
    const compiled = switch (compile_outcome) {
        .diagnostic => return,
        .plan => |compiled| compiled,
    };

    var builder = engine.Builder.init(allocator);
    builder.setRetainedPlan(compiled);
    builder.setInterventionCapabilities(.{ .proxy = true });
    const waf = builder.build() catch return;
    defer waf.deinit() catch unreachable;
    var tx = waf.newTransaction();
    defer tx.deinit();
    try tx.processConnection("192.0.2.1", 1234, "198.51.100.1", 443);
    try tx.processUri("/fuzz", "POST", "HTTP/1.1");
    try tx.processRequestHeaders();

    const matched_value = input[0..@min(input.len, waf.config.limits.max_match_value_bytes)];
    for (1..6) |phase| {
        for (compiled.phaseRules(@intCast(phase))) |head_id| {
            var matches: std.ArrayList(engine.MatchedRule) = .empty;
            defer matches.deinit(allocator);
            var current: ?plan.RuleId = head_id;
            while (current) |rule_id| {
                const index: usize = @backingInt(rule_id);
                if (index >= compiled.rules.len) return error.InvalidActionFuzzChain;
                try matches.append(allocator, .{
                    .rule = rule_id,
                    .context = .{
                        .name = "ARGS:fuzz",
                        .value = matched_value,
                        .source = .{ .origin = .request_body, .offset = 0, .length = matched_value.len },
                    },
                });
                current = compiled.rules[index].chain_next;
                if (matches.items.len > compiled.rules.len) return error.InvalidActionFuzzChain;
            }
            const before = tx.matchIntentCount();
            const outcome = tx.applyLocalMatchedChain(matches.items) catch {
                if (tx.matchIntentCount() != before) return error.PartialActionFuzzIntent;
                continue;
            };
            const intent = tx.matchIntent(outcome.intent) orelse return error.MissingActionFuzzIntent;
            if (intent.rule != head_id or intent.chain_head != head_id or
                !std.mem.eql(u8, intent.matched_name, "ARGS:fuzz") or
                !std.mem.eql(u8, intent.matched_value, matched_value) or
                intent.disruptive_status < 100 or intent.disruptive_status > 599 or
                ((intent.disruptive == .redirect or intent.disruptive == .proxy) and
                    intent.disruptive_destination == null))
            {
                return error.InvalidActionFuzzIntent;
            }
        }
    }
}
