//! High-performance, embeddable web application firewall engine.

pub const version = "0.0.0-dev";
pub const compatibility = @import("compatibility.zig");
pub const collections = @import("collections.zig");
pub const directives = @import("directives.zig");
pub const engine = @import("engine.zig");
pub const macros = @import("macros.zig");
pub const operators = @import("operators.zig");
pub const plan = @import("plan.zig");
pub const plan_fuzz = @import("plan_fuzz.zig");
pub const rule_config = @import("rule_config.zig");
pub const persistent = @import("persistent.zig");
pub const persistent_lmdb = @import("persistent_lmdb.zig");
pub const selectors = @import("selectors.zig");
pub const seclang = @import("seclang/root.zig");
pub const variables = @import("variables.zig");

pub const Waf = engine.Waf;
pub const Runtime = engine.Runtime;
pub const RetiredGeneration = engine.RetiredGeneration;
pub const Transaction = engine.Transaction;
pub const Intervention = engine.Intervention;
pub const Phase = engine.Phase;
pub const Feature = engine.Feature;
pub const FeatureSet = engine.FeatureSet;
pub const ClockSample = engine.ClockSample;
pub const ClockSource = engine.ClockSource;

test {
    _ = version;
    _ = compatibility;
    _ = collections;
    _ = directives;
    _ = engine;
    _ = macros;
    _ = operators;
    _ = plan;
    _ = plan_fuzz;
    _ = rule_config;
    _ = persistent;
    _ = persistent_lmdb;
    _ = selectors;
    _ = seclang;
    _ = variables;
}
