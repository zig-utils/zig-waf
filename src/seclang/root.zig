//! Bounded, source-preserving SecLang frontend.

pub const source = @import("source.zig");
pub const diagnostic = @import("diagnostic.zig");
pub const evidence = @import("evidence.zig");
pub const fuzz = @import("fuzz.zig");
pub const include = @import("include.zig");
pub const lexer = @import("lexer.zig");
pub const parser = @import("parser.zig");
pub const assembly = @import("assembly.zig");
pub const syntax = @import("syntax.zig");

test {
    _ = source;
    _ = diagnostic;
    _ = evidence;
    _ = fuzz;
    _ = include;
    _ = lexer;
    _ = parser;
    _ = assembly;
    _ = syntax;
}
