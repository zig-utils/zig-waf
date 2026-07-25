//! Bounded physical-to-logical SecLang line normalization.

const std = @import("std");
const source = @import("source.zig");

pub const Limits = struct {
    max_logical_line_bytes: usize = 1024 * 1024,
    max_segments_per_line: usize = 1024,
    max_tokens_per_line: usize = 4096,
    max_token_bytes: usize = 256 * 1024,

    pub fn validate(self: Limits) error{InvalidLexerLimit}!void {
        if (self.max_logical_line_bytes == 0 or
            self.max_segments_per_line == 0 or
            self.max_tokens_per_line == 0 or
            self.max_token_bytes == 0)
        {
            return error.InvalidLexerLimit;
        }
    }
};

pub const Segment = struct {
    logical_start: u32,
    physical: source.Span,
};

pub const LogicalLine = struct {
    allocator: std.mem.Allocator,
    text: []u8,
    segments: []Segment,
    physical: source.Span,

    pub fn deinit(self: *LogicalLine) void {
        self.allocator.free(self.text);
        self.allocator.free(self.segments);
        self.* = undefined;
    }

    pub fn physicalOffset(self: *const LogicalLine, logical_offset: u32) ?u32 {
        if (logical_offset > self.text.len) return null;
        var selected: ?Segment = null;
        for (self.segments) |segment| {
            if (segment.logical_start > logical_offset) break;
            selected = segment;
        }
        const segment = selected orelse return self.physical.start;
        const relative = logical_offset - segment.logical_start;
        return @min(segment.physical.end, segment.physical.start + relative);
    }
};

pub const LexerError = std.mem.Allocator.Error || error{
    InvalidLexerLimit,
    LogicalLineTooLarge,
    TooManyLineSegments,
    DanglingContinuation,
    /// A backtick block was opened and never closed.
    UnterminatedBlock,
    TooManyTokens,
    TokenTooLarge,
    UnterminatedQuote,
    DanglingEscape,
};

/// How a token was delimited. `backtick` is Coraza's multi-line block form, whose
/// value spans physical lines and keeps its newlines — the only token kind that
/// does. ModSecurity has no equivalent; a backtick there is an ordinary byte.
pub const Quote = enum { unquoted, single, double, backtick, mixed };

pub const Token = struct {
    raw: []const u8,
    quote: Quote,
    logical_start: u32,
    logical_end: u32,
    physical: source.Span,
};

pub const TokenLine = struct {
    allocator: std.mem.Allocator,
    tokens: []Token,
    comment: ?source.Span,

    pub fn deinit(self: *TokenLine) void {
        self.allocator.free(self.tokens);
        self.* = undefined;
    }
};

pub fn tokenize(line: *const LogicalLine, allocator: std.mem.Allocator, limits: Limits) LexerError!TokenLine {
    try limits.validate();
    // As in the line iterator: a backtick delimits a value only on a line that can
    // carry a block. Everywhere else — a regex character class, for instance — it is
    // an ordinary byte.
    const block_capable = std.ascii.startsWithIgnoreCase(std.mem.trimStart(u8, line.text, " \t"), "SecDataset");
    var tokens: std.ArrayList(Token) = .empty;
    defer tokens.deinit(allocator);
    var token_start: ?usize = null;
    var first_quote: ?Quote = null;
    var quote: ?Quote = null;
    var mixed = false;
    var escaped = false;
    var comment: ?source.Span = null;
    var index: usize = 0;
    while (index < line.text.len) : (index += 1) {
        const byte = line.text[index];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (byte == '\\') {
            if (token_start == null) token_start = index;
            escaped = true;
            continue;
        }
        if (quote) |active_quote| {
            const closes = switch (active_quote) {
                .single => byte == '\'',
                .double => byte == '"',
                .backtick => byte == '`',
                else => false,
            };
            if (closes) quote = null;
            continue;
        }
        if (byte == '\'' or byte == '"' or (block_capable and byte == '`')) {
            if (token_start == null) {
                token_start = index;
                first_quote = quoteOf(byte);
            } else if (index != token_start.?) {
                mixed = true;
            }
            quote = quoteOf(byte);
            continue;
        }
        if (isHorizontalSpace(byte)) {
            if (token_start) |start| {
                try appendToken(&tokens, allocator, line, limits, start, index, first_quote, mixed);
                token_start = null;
                first_quote = null;
                mixed = false;
            }
            continue;
        }
        if (byte == '#' and token_start == null) {
            const physical_start = line.physicalOffset(@intCast(index)) orelse line.physical.start;
            comment = .{ .source = line.physical.source, .start = physical_start, .end = line.physical.end };
            break;
        }
        if (token_start == null) token_start = index;
    }
    if (escaped) return error.DanglingEscape;
    if (quote != null) return error.UnterminatedQuote;
    if (token_start) |start| try appendToken(&tokens, allocator, line, limits, start, index, first_quote, mixed);
    return .{
        .allocator = allocator,
        .tokens = try tokens.toOwnedSlice(allocator),
        .comment = comment,
    };
}

fn appendToken(
    tokens: *std.ArrayList(Token),
    allocator: std.mem.Allocator,
    line: *const LogicalLine,
    limits: Limits,
    start: usize,
    end: usize,
    first_quote: ?Quote,
    mixed: bool,
) LexerError!void {
    if (tokens.items.len == limits.max_tokens_per_line) return error.TooManyTokens;
    if (end - start > limits.max_token_bytes) return error.TokenTooLarge;
    const physical_start = line.physicalOffset(@intCast(start)) orelse line.physical.start;
    const physical_end = line.physicalOffset(@intCast(end)) orelse line.physical.end;
    try tokens.append(allocator, .{
        .raw = line.text[start..end],
        .quote = if (mixed) .mixed else first_quote orelse .unquoted,
        .logical_start = @intCast(start),
        .logical_end = @intCast(end),
        .physical = .{ .source = line.physical.source, .start = physical_start, .end = physical_end },
    });
}

pub const LogicalLineIterator = struct {
    input: *const source.Source,
    limits: Limits,
    offset: usize = 0,

    pub fn init(input: *const source.Source, limits: Limits) error{InvalidLexerLimit}!LogicalLineIterator {
        try limits.validate();
        return .{ .input = input, .limits = limits };
    }

    pub fn next(self: *LogicalLineIterator, allocator: std.mem.Allocator) LexerError!?LogicalLine {
        if (self.offset == self.input.bytes.len) return null;
        const physical_start = self.offset;
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(allocator);
        var segments: std.ArrayList(Segment) = .empty;
        defer segments.deinit(allocator);
        var continuing = false;
        var active_quote: ?u8 = null;
        var quote_escape = false;
        // A backtick block spans physical lines without continuation markers, and
        // its newlines are part of the value — which is what makes it a block
        // rather than a long line.
        var in_block = false;

        while (self.offset < self.input.bytes.len) {
            const line_start = self.offset;
            const newline = std.mem.indexOfScalarPos(u8, self.input.bytes, line_start, '\n');
            const next_offset = if (newline) |index| index + 1 else self.input.bytes.len;
            var content_end = newline orelse self.input.bytes.len;
            if (content_end > line_start and self.input.bytes[content_end - 1] == '\r') content_end -= 1;
            var content_start = line_start;
            if (in_block) {
                // Inside a block the line is taken verbatim: leading whitespace and
                // the newline separating entries are data.
                if (segments.items.len == self.limits.max_segments_per_line) return error.TooManyLineSegments;
                const block_length = (content_end - line_start) + 1;
                if (block_length > self.limits.max_logical_line_bytes -| text.items.len) return error.LogicalLineTooLarge;
                try text.append(allocator, '\n');
                try segments.append(allocator, .{
                    .logical_start = @intCast(text.items.len),
                    .physical = .{
                        .source = self.input.id,
                        .start = @intCast(line_start),
                        .end = @intCast(content_end),
                    },
                });
                try text.appendSlice(allocator, self.input.bytes[line_start..content_end]);
                updateQuoteState(self.input.bytes[line_start..content_end], &active_quote, &quote_escape, &in_block);
                self.offset = next_offset;
                if (in_block) {
                    // An unterminated block would otherwise swallow the rest of the
                    // file and report a confusing error far from its cause.
                    if (newline == null) return error.UnterminatedBlock;
                    continue;
                }
                break;
            }
            if (continuing) {
                while (content_start < content_end and isHorizontalSpace(self.input.bytes[content_start])) content_start += 1;
            }

            var trimmed_end = content_end;
            while (trimmed_end > content_start and isHorizontalSpace(self.input.bytes[trimmed_end - 1])) trimmed_end -= 1;
            const has_continuation = trimmed_end > content_start and self.input.bytes[trimmed_end - 1] == '\\';
            var append_end = content_end;
            var separator_before_continuation = false;
            if (has_continuation) {
                append_end = trimmed_end - 1;
                const before_whitespace = append_end;
                while (append_end > content_start and isHorizontalSpace(self.input.bytes[append_end - 1])) append_end -= 1;
                separator_before_continuation = append_end != before_whitespace;
            }

            // Only `SecDataset` takes a block, so only such a line may open one. A
            // backtick anywhere else is an ordinary byte — OWASP CRS 4.28 has one
            // inside a regex character class (rule 932370), and treating that as a
            // block opener swallowed the rest of the rule.
            const block_capable = blk: {
                const prefix = "SecDataset";
                const scan_start = if (text.items.len != 0) text.items else self.input.bytes[content_start..content_end];
                var index: usize = 0;
                while (index < scan_start.len and isHorizontalSpace(scan_start[index])) index += 1;
                const rest_of_line = scan_start[index..];
                break :blk rest_of_line.len >= prefix.len and std.ascii.eqlIgnoreCase(rest_of_line[0..prefix.len], prefix);
            };

            if (append_end > content_start) {
                if (segments.items.len == self.limits.max_segments_per_line) return error.TooManyLineSegments;
                const length = append_end - content_start;
                if (length > self.limits.max_logical_line_bytes -| text.items.len) return error.LogicalLineTooLarge;
                try segments.append(allocator, .{
                    .logical_start = @intCast(text.items.len),
                    .physical = .{
                        .source = self.input.id,
                        .start = @intCast(content_start),
                        .end = @intCast(append_end),
                    },
                });
                try text.appendSlice(allocator, self.input.bytes[content_start..append_end]);
                updateQuoteState(self.input.bytes[content_start..append_end], &active_quote, &quote_escape, if (block_capable) &in_block else null);
            }
            if (has_continuation and separator_before_continuation and active_quote == null and text.items.len != 0) {
                if (text.items.len == self.limits.max_logical_line_bytes) return error.LogicalLineTooLarge;
                try text.append(allocator, ' ');
            }
            self.offset = next_offset;
            if (in_block) {
                if (newline == null) return error.UnterminatedBlock;
                continue;
            }
            if (!has_continuation) break;
            if (newline == null) return error.DanglingContinuation;
            continuing = true;
        }

        // Reaching the end of the file with a block still open: the input ends
        // mid-value, whether or not its last line had a newline.
        if (in_block) return error.UnterminatedBlock;

        const owned_text = try text.toOwnedSlice(allocator);
        errdefer allocator.free(owned_text);
        const owned_segments = try segments.toOwnedSlice(allocator);
        return .{
            .allocator = allocator,
            .text = owned_text,
            .segments = owned_segments,
            .physical = .{
                .source = self.input.id,
                .start = @intCast(physical_start),
                .end = @intCast(self.offset),
            },
        };
    }
};

fn quoteOf(byte: u8) Quote {
    return switch (byte) {
        '\'' => .single,
        '"' => .double,
        '`' => .backtick,
        else => unreachable,
    };
}

fn isHorizontalSpace(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

/// Track quoting across a line. `in_block` is null for a line that cannot contain a
/// block, in which case a backtick is an ordinary byte.
fn updateQuoteState(bytes: []const u8, active_quote: *?u8, escaped: *bool, in_block: ?*bool) void {
    for (bytes) |byte| {
        // Inside a block only a backtick means anything: a quote or a backslash in a
        // dataset entry is data, not syntax.
        if (in_block) |flag| if (flag.*) {
            if (byte == '`') flag.* = false;
            continue;
        };
        if (escaped.*) {
            escaped.* = false;
            continue;
        }
        if (byte == '\\') {
            escaped.* = true;
            continue;
        }
        if (active_quote.*) |quote| {
            if (byte == quote) active_quote.* = null;
        } else if (byte == '\'' or byte == '"') {
            active_quote.* = byte;
        } else if (byte == '`') {
            if (in_block) |flag| flag.* = true;
        }
    }
}

test "logical lines normalize CRLF and baseline continuation whitespace" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const id = try registry.add(
        "rules.conf",
        "SecRule ARGS \\\r\n    \"@rx attack\"   \\\n\t\"id:1,deny\"\r\nSecAction pass",
        null,
    );
    var iterator = try LogicalLineIterator.init(registry.get(id).?, .{});
    var first = (try iterator.next(std.testing.allocator)).?;
    defer first.deinit();
    try std.testing.expectEqualStrings("SecRule ARGS \"@rx attack\" \"id:1,deny\"", first.text);
    try std.testing.expectEqual(@as(usize, 3), first.segments.len);
    try std.testing.expectEqual(@as(u32, 0), first.physicalOffset(0).?);
    try std.testing.expectEqual(@as(u32, 12), first.physicalOffset(12).?);
    var second = (try iterator.next(std.testing.allocator)).?;
    defer second.deinit();
    try std.testing.expectEqualStrings("SecAction pass", second.text);
    try std.testing.expect((try iterator.next(std.testing.allocator)) == null);
}

test "logical line limits and dangling continuation are explicit" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const long = try registry.add("long.conf", "abcd", null);
    var limited = try LogicalLineIterator.init(registry.get(long).?, .{ .max_logical_line_bytes = 3 });
    try std.testing.expectError(error.LogicalLineTooLarge, limited.next(std.testing.allocator));
    const dangling = try registry.add("dangling.conf", "SecAction \\", null);
    var dangling_iterator = try LogicalLineIterator.init(registry.get(dangling).?, .{});
    try std.testing.expectError(error.DanglingContinuation, dangling_iterator.next(std.testing.allocator));
}

test "tokenizer preserves quotes escapes inline hashes and comments" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const id = try registry.add("rule.conf", "SecRule ARGS \"@rx ^#attack\\\"x\" 'id:1,msg:\\'quoted' # comment", null);
    var iterator = try LogicalLineIterator.init(registry.get(id).?, .{});
    var line = (try iterator.next(std.testing.allocator)).?;
    defer line.deinit();
    var token_line = try tokenize(&line, std.testing.allocator, .{});
    defer token_line.deinit();
    try std.testing.expectEqual(@as(usize, 4), token_line.tokens.len);
    try std.testing.expectEqualStrings("SecRule", token_line.tokens[0].raw);
    try std.testing.expectEqualStrings("\"@rx ^#attack\\\"x\"", token_line.tokens[2].raw);
    try std.testing.expectEqual(Quote.double, token_line.tokens[2].quote);
    try std.testing.expectEqual(Quote.single, token_line.tokens[3].quote);
    try std.testing.expect(token_line.comment != null);
}

test "tokenizer rejects unterminated state and enforces token limits" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const id = try registry.add("bad.conf", "SecAction \"pass", null);
    var iterator = try LogicalLineIterator.init(registry.get(id).?, .{});
    var line = (try iterator.next(std.testing.allocator)).?;
    defer line.deinit();
    try std.testing.expectError(error.UnterminatedQuote, tokenize(&line, std.testing.allocator, .{}));
    const limited_id = try registry.add("tokens.conf", "a b", null);
    var limited_iterator = try LogicalLineIterator.init(registry.get(limited_id).?, .{});
    var limited_line = (try limited_iterator.next(std.testing.allocator)).?;
    defer limited_line.deinit();
    try std.testing.expectError(error.TooManyTokens, tokenize(&limited_line, std.testing.allocator, .{ .max_tokens_per_line = 1 }));
}

test "a backtick block spans physical lines and keeps its newlines" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const id = try registry.add(
        "dataset.conf",
        "SecDataset denied `\n  first\nsecond\n`\nSecAction pass",
        null,
    );
    var iterator = try LogicalLineIterator.init(registry.get(id).?, .{});
    var block = (try iterator.next(std.testing.allocator)).?;
    defer block.deinit();
    // The block's newlines survive, because they separate its entries; leading
    // whitespace inside it is data rather than indentation to be stripped.
    try std.testing.expectEqualStrings("SecDataset denied `\n  first\nsecond\n`", block.text);

    var token_line = try tokenize(&block, std.testing.allocator, .{});
    defer token_line.deinit();
    try std.testing.expectEqual(@as(usize, 3), token_line.tokens.len);
    try std.testing.expectEqualStrings("SecDataset", token_line.tokens[0].raw);
    try std.testing.expectEqualStrings("denied", token_line.tokens[1].raw);
    // The whole block is one token, so the directive receives its entries as a
    // single value rather than as stray arguments.
    try std.testing.expectEqualStrings("`\n  first\nsecond\n`", token_line.tokens[2].raw);
    try std.testing.expectEqual(Quote.backtick, token_line.tokens[2].quote);

    // The directive after the block is still its own logical line.
    var following = (try iterator.next(std.testing.allocator)).?;
    defer following.deinit();
    try std.testing.expectEqualStrings("SecAction pass", following.text);
    try std.testing.expect((try iterator.next(std.testing.allocator)) == null);
}

test "a block treats quotes, hashes, and continuations as data" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    // Every one of these is syntax outside a block: an unbalanced quote, a comment
    // marker, and a trailing backslash. Inside one they are dataset entries.
    const id = try registry.add("odd.conf", "SecDataset odd `\nit's\n# not a comment\ntrailing \\\n`", null);
    var iterator = try LogicalLineIterator.init(registry.get(id).?, .{});
    var block = (try iterator.next(std.testing.allocator)).?;
    defer block.deinit();
    try std.testing.expectEqualStrings("SecDataset odd `\nit's\n# not a comment\ntrailing \\\n`", block.text);
    var token_line = try tokenize(&block, std.testing.allocator, .{});
    defer token_line.deinit();
    try std.testing.expectEqual(@as(usize, 3), token_line.tokens.len);
    try std.testing.expect(token_line.comment == null);
}

test "an unterminated block is reported rather than swallowing the file" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const id = try registry.add("open.conf", "SecDataset open `\nfirst\nsecond\n", null);
    var iterator = try LogicalLineIterator.init(registry.get(id).?, .{});
    try std.testing.expectError(error.UnterminatedBlock, iterator.next(std.testing.allocator));

    // A block is bounded like every other logical line.
    const long = try registry.add("long.conf", "SecDataset big `\naaaa\nbbbb\n`", null);
    var limited = try LogicalLineIterator.init(registry.get(long).?, .{ .max_logical_line_bytes = 20 });
    try std.testing.expectError(error.LogicalLineTooLarge, limited.next(std.testing.allocator));
}

test "a backtick outside a block still tokenizes as a delimiter" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    // A single-line backtick value is legal and stays on one line.
    const id = try registry.add("inline.conf", "SecDataset inline `one`", null);
    var iterator = try LogicalLineIterator.init(registry.get(id).?, .{});
    var line = (try iterator.next(std.testing.allocator)).?;
    defer line.deinit();
    try std.testing.expectEqualStrings("SecDataset inline `one`", line.text);
    var token_line = try tokenize(&line, std.testing.allocator, .{});
    defer token_line.deinit();
    try std.testing.expectEqual(@as(usize, 3), token_line.tokens.len);
    try std.testing.expectEqual(Quote.backtick, token_line.tokens[2].quote);
}

test "a backtick outside a dataset line is an ordinary byte" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    // OWASP CRS 4.28 rule 932370 carries a backtick inside a regex character class,
    // and its rule continues across several lines. Treating that backtick as a
    // block opener swallowed the continuation and broke the whole file.
    const id = try registry.add(
        "crs.conf",
        "SecRule ARGS \"@rx (?:[\\n\\r;`\\{]|\\|\\|?)\" \\\n    \"id:932370,phase:2,block\"\nSecAction pass",
        null,
    );
    var iterator = try LogicalLineIterator.init(registry.get(id).?, .{});
    var rule = (try iterator.next(std.testing.allocator)).?;
    defer rule.deinit();
    // The continuation joined, so the actions are part of the same directive.
    try std.testing.expect(std.mem.indexOf(u8, rule.text, "id:932370") != null);

    var token_line = try tokenize(&rule, std.testing.allocator, .{});
    defer token_line.deinit();
    try std.testing.expectEqual(@as(usize, 4), token_line.tokens.len);
    try std.testing.expectEqualStrings("SecRule", token_line.tokens[0].raw);
    // The operator stayed one double-quoted token, backtick and all.
    try std.testing.expectEqual(Quote.double, token_line.tokens[2].quote);
    try std.testing.expect(std.mem.indexOfScalar(u8, token_line.tokens[2].raw, '`') != null);

    // And the line after it is still its own directive rather than block content.
    var following = (try iterator.next(std.testing.allocator)).?;
    defer following.deinit();
    try std.testing.expectEqualStrings("SecAction pass", following.text);
}
