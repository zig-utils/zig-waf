//! Host-provided extensions (#23).
//!
//! Some operators cannot live inside the WAF. `@geoLookup` needs a MaxMind
//! database, `@rbl` needs a DNS query, `@inspectFile` runs an external scanner,
//! `@fuzzyHash` needs a corpus of hashes — every one of them is a file, a socket,
//! or a process, and the request path must not block on any of those. Nor can the
//! WAF decide where such data lives or how long it may take: those are deployment
//! questions.
//!
//! So the WAF does not implement them; it lets a host register one. A plugin is a
//! name plus a callback, and the WAF calls it exactly where the operator appears.
//!
//! Two rules make this safe to build a security control on:
//!
//!   * A rule naming an operator that no plugin provides **fails to compile**. It
//!     would otherwise be a rule that never matches, which looks like coverage and
//!     is not — see `plan.isImplementedOperator`.
//!   * A plugin that cannot answer says `unavailable`, and that is not the same as
//!     "no match". The engine counts it, so a GeoIP database that failed to load is
//!     visible as an unanswered question rather than as a stream of clean requests.

const std = @import("std");

/// What a plugin operator decided.
pub const Outcome = union(enum) {
    /// The operator ran and reached a verdict.
    matched: bool,
    /// The operator could not run — the data source is missing, unreachable, or
    /// timed out. The rule does not match, but the engine records that the question
    /// went unanswered rather than treating silence as safety.
    unavailable,
};

/// One host-provided operator.
///
/// `evaluateFn` is called on the request path, so it must not block: a plugin that
/// needs a network round trip is expected to answer from a cache it maintains
/// elsewhere and report `unavailable` on a miss. Neither `parameter` nor `input` is
/// retained after the call returns.
pub const Operator = struct {
    /// The operator name, without the leading `@`, matched case-insensitively.
    name: []const u8,
    context: *anyopaque,
    evaluateFn: *const fn (context: *anyopaque, parameter: []const u8, input: []const u8) Outcome,

    pub fn evaluate(self: Operator, parameter: []const u8, input: []const u8) Outcome {
        return self.evaluateFn(self.context, parameter, input);
    }
};

/// The set of extensions a host provides. Borrowed by the WAF for its lifetime, so
/// the host owns the storage and must outlive it — the same ownership rule as the
/// persistent-collection backend.
pub const Registry = struct {
    operators: []const Operator = &.{},

    /// The plugin answering to `name` (with or without a leading `@`), or null.
    pub fn findOperator(self: *const Registry, name: []const u8) ?*const Operator {
        const wanted = if (name.len != 0 and name[0] == '@') name[1..] else name;
        for (self.operators) |*operator| {
            if (std.ascii.eqlIgnoreCase(operator.name, wanted)) return operator;
        }
        return null;
    }

    /// Whether `name` is provided, for the compile-time check that refuses a rule
    /// whose operator nothing can evaluate.
    pub fn providesOperator(self: *const Registry, name: []const u8) bool {
        return self.findOperator(name) != null;
    }

    /// The registered operator names, for passing to plan compilation.
    pub fn operatorNames(self: *const Registry, out: [][]const u8) [][]const u8 {
        const count = @min(out.len, self.operators.len);
        for (self.operators[0..count], out[0..count]) |operator, *slot| slot.* = operator.name;
        return out[0..count];
    }

    /// A registry is only usable if its names are distinct and non-empty: two
    /// plugins answering to one name would make which of them runs depend on
    /// registration order.
    pub fn validate(self: *const Registry) error{ EmptyPluginName, DuplicatePluginName }!void {
        for (self.operators, 0..) |operator, index| {
            if (operator.name.len == 0) return error.EmptyPluginName;
            for (self.operators[0..index]) |previous| {
                if (std.ascii.eqlIgnoreCase(previous.name, operator.name)) return error.DuplicatePluginName;
            }
        }
    }
};

// ---- tests --------------------------------------------------------------

const testing = std.testing;

/// A stand-in for a host's GeoIP lookup: it answers from a table instead of a
/// MaxMind database, and reports `unavailable` when its data is not loaded.
const CountryLookup = struct {
    loaded: bool = true,
    country: []const u8 = "SE",

    fn evaluate(context: *anyopaque, parameter: []const u8, input: []const u8) Outcome {
        const self: *CountryLookup = @ptrCast(@alignCast(context));
        if (!self.loaded) return .unavailable;
        _ = input;
        return .{ .matched = std.mem.eql(u8, parameter, self.country) };
    }

    fn operator(self: *CountryLookup) Operator {
        return .{ .name = "geoLookup", .context = self, .evaluateFn = evaluate };
    }
};

test "a registry resolves operators by name, with or without the sigil" {
    var lookup = CountryLookup{};
    const operators = [_]Operator{lookup.operator()};
    const registry = Registry{ .operators = &operators };
    try registry.validate();

    try testing.expect(registry.providesOperator("geoLookup"));
    try testing.expect(registry.providesOperator("@geoLookup"));
    // SecLang operator names are case-insensitive, so plugin names are too.
    try testing.expect(registry.providesOperator("GEOLOOKUP"));
    try testing.expect(!registry.providesOperator("rbl"));
    try testing.expect(registry.findOperator("nope") == null);

    var names: [4][]const u8 = undefined;
    const listed = registry.operatorNames(&names);
    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqualStrings("geoLookup", listed[0]);
}

test "a plugin distinguishes no-match from unable-to-answer" {
    var lookup = CountryLookup{};
    const operators = [_]Operator{lookup.operator()};
    const registry = Registry{ .operators = &operators };

    const plugin = registry.findOperator("geoLookup").?;
    try testing.expectEqual(Outcome{ .matched = true }, plugin.evaluate("SE", "203.0.113.7"));
    try testing.expectEqual(Outcome{ .matched = false }, plugin.evaluate("NO", "203.0.113.7"));

    // A database that failed to load is not a country that failed to match: the
    // difference is the whole point, because the second reads as a clean request.
    lookup.loaded = false;
    try testing.expectEqual(Outcome.unavailable, plugin.evaluate("SE", "203.0.113.7"));
}

test "a registry rejects names that would make dispatch ambiguous" {
    var first = CountryLookup{};
    var second = CountryLookup{};

    const duplicate = [_]Operator{ first.operator(), second.operator() };
    try testing.expectError(error.DuplicatePluginName, (Registry{ .operators = &duplicate }).validate());

    const unnamed = [_]Operator{.{ .name = "", .context = &first, .evaluateFn = CountryLookup.evaluate }};
    try testing.expectError(error.EmptyPluginName, (Registry{ .operators = &unnamed }).validate());

    // Case-insensitive matching means these two collide as well, and a registry
    // that accepted them would make which one runs depend on registration order.
    const cased = [_]Operator{
        .{ .name = "geoLookup", .context = &first, .evaluateFn = CountryLookup.evaluate },
        .{ .name = "GeoLookup", .context = &second, .evaluateFn = CountryLookup.evaluate },
    };
    try testing.expectError(error.DuplicatePluginName, (Registry{ .operators = &cased }).validate());
}
