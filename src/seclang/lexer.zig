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
    TooManyTokens,
    TokenTooLarge,
    UnterminatedQuote,
    DanglingEscape,
};

pub const Quote = enum { unquoted, single, double, mixed };

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
            if ((active_quote == .single and byte == '\'') or (active_quote == .double and byte == '"')) quote = null;
            continue;
        }
        if (byte == '\'' or byte == '"') {
            if (token_start == null) {
                token_start = index;
                first_quote = if (byte == '\'') .single else .double;
            } else if (index != token_start.?) {
                mixed = true;
            }
            quote = if (byte == '\'') .single else .double;
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

        while (self.offset < self.input.bytes.len) {
            const line_start = self.offset;
            const newline = std.mem.indexOfScalarPos(u8, self.input.bytes, line_start, '\n');
            const next_offset = if (newline) |index| index + 1 else self.input.bytes.len;
            var content_end = newline orelse self.input.bytes.len;
            if (content_end > line_start and self.input.bytes[content_end - 1] == '\r') content_end -= 1;
            var content_start = line_start;
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
                updateQuoteState(self.input.bytes[content_start..append_end], &active_quote, &quote_escape);
            }
            if (has_continuation and separator_before_continuation and active_quote == null and text.items.len != 0) {
                if (text.items.len == self.limits.max_logical_line_bytes) return error.LogicalLineTooLarge;
                try text.append(allocator, ' ');
            }
            self.offset = next_offset;
            if (!has_continuation) break;
            if (newline == null) return error.DanglingContinuation;
            continuing = true;
        }

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

fn isHorizontalSpace(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

fn updateQuoteState(bytes: []const u8, active_quote: *?u8, escaped: *bool) void {
    for (bytes) |byte| {
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
