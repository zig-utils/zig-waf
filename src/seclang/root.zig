//! Bounded, source-preserving SecLang frontend.

pub const source = @import("source.zig");
pub const lexer = @import("lexer.zig");

test {
    _ = source;
    _ = lexer;
}
