//! High-performance, embeddable web application firewall engine.

pub const version = "0.0.0-dev";
pub const engine = @import("engine.zig");
pub const operators = @import("operators.zig");

pub const Waf = engine.Waf;
pub const Transaction = engine.Transaction;
pub const Intervention = engine.Intervention;
pub const Phase = engine.Phase;

test {
    _ = version;
    _ = engine;
    _ = operators;
}
