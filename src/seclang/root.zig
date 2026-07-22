//! Bounded, source-preserving SecLang frontend.

pub const source = @import("source.zig");
pub const lexer = @import("lexer.zig");
pub const parser = @import("parser.zig");

test {
    _ = source;
    _ = lexer;
    _ = parser;
}
