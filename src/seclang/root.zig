//! Bounded, source-preserving SecLang frontend.

pub const source = @import("source.zig");
pub const diagnostic = @import("diagnostic.zig");
pub const fuzz = @import("fuzz.zig");
pub const include = @import("include.zig");
pub const lexer = @import("lexer.zig");
pub const parser = @import("parser.zig");
pub const syntax = @import("syntax.zig");

test {
    _ = source;
    _ = diagnostic;
    _ = fuzz;
    _ = include;
    _ = lexer;
    _ = parser;
    _ = syntax;
}
