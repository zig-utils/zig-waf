//! Stable, bounded diagnostics for SecLang configuration failures.

const std = @import("std");
const source = @import("source.zig");

pub const Severity = enum { error_, warning, note };

pub const Code = enum {
    invalid_parser_limit,
    invalid_source,
    logical_line_too_large,
    too_many_line_segments,
    dangling_continuation,
    too_many_tokens,
    token_too_large,
    unterminated_quote,
    dangling_escape,
    too_many_directives,
    too_many_arguments,
    invalid_directive_name,
    missing_rule_targets,
    missing_rule_operator,
    too_many_rule_arguments,
    missing_action_list,
    too_many_action_arguments,
    missing_marker,
    too_many_marker_arguments,
    missing_include_path,
    too_many_include_arguments,
    too_many_targets,
    too_many_actions,
    empty_target,
    invalid_target_modifier,
    missing_target_collection,
    empty_operator,
    missing_operator_name,
    empty_action,
    missing_action_name,
    unterminated_nested_quote,
    dangling_nested_escape,
    syntax,

    pub fn id(self: Code) []const u8 {
        return switch (self) {
            .invalid_parser_limit => "WAF-SECLANG-0001",
            .invalid_source => "WAF-SECLANG-0002",
            .logical_line_too_large => "WAF-SECLANG-0101",
            .too_many_line_segments => "WAF-SECLANG-0102",
            .dangling_continuation => "WAF-SECLANG-0103",
            .too_many_tokens => "WAF-SECLANG-0104",
            .token_too_large => "WAF-SECLANG-0105",
            .unterminated_quote => "WAF-SECLANG-0106",
            .dangling_escape => "WAF-SECLANG-0107",
            .too_many_directives => "WAF-SECLANG-0201",
            .too_many_arguments => "WAF-SECLANG-0202",
            .invalid_directive_name => "WAF-SECLANG-0203",
            .missing_rule_targets => "WAF-SECLANG-0204",
            .missing_rule_operator => "WAF-SECLANG-0205",
            .too_many_rule_arguments => "WAF-SECLANG-0206",
            .missing_action_list => "WAF-SECLANG-0207",
            .too_many_action_arguments => "WAF-SECLANG-0208",
            .missing_marker => "WAF-SECLANG-0209",
            .too_many_marker_arguments => "WAF-SECLANG-0210",
            .missing_include_path => "WAF-SECLANG-0211",
            .too_many_include_arguments => "WAF-SECLANG-0212",
            .too_many_targets => "WAF-SECLANG-0301",
            .too_many_actions => "WAF-SECLANG-0302",
            .empty_target => "WAF-SECLANG-0303",
            .invalid_target_modifier => "WAF-SECLANG-0304",
            .missing_target_collection => "WAF-SECLANG-0305",
            .empty_operator => "WAF-SECLANG-0306",
            .missing_operator_name => "WAF-SECLANG-0307",
            .empty_action => "WAF-SECLANG-0308",
            .missing_action_name => "WAF-SECLANG-0309",
            .unterminated_nested_quote => "WAF-SECLANG-0310",
            .dangling_nested_escape => "WAF-SECLANG-0311",
            .syntax => "WAF-SECLANG-0399",
        };
    }
};

pub const Diagnostic = struct {
    code: Code,
    severity: Severity = .error_,
    primary: source.Span,
    secondary: ?source.Span = null,
    message: []const u8,

    pub fn fromError(failure: anyerror, primary: source.Span) Diagnostic {
        const code = codeFromError(failure);
        return .{ .code = code, .primary = primary, .message = messageForCode(code) };
    }
};

pub const RenderLimits = struct {
    max_bytes: usize = 16 * 1024,
    max_excerpt_bytes: usize = 512,
    max_include_depth: usize = 64,

    pub fn validate(self: RenderLimits) error{InvalidDiagnosticLimit}!void {
        if (self.max_bytes < 64 or self.max_excerpt_bytes == 0 or self.max_include_depth == 0)
            return error.InvalidDiagnosticLimit;
    }
};

pub const RenderError = std.mem.Allocator.Error || source.RegistryError || error{InvalidDiagnosticLimit};

pub fn renderHuman(
    allocator: std.mem.Allocator,
    registry: *const source.Registry,
    value: Diagnostic,
    limits: RenderLimits,
) RenderError![]u8 {
    try limits.validate();
    try registry.validateSpan(value.primary);
    const primary_source = registry.get(value.primary.source).?;
    const location = try registry.location(value.primary.source, value.primary.start);
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    try appendFmt(&output, allocator, limits.max_bytes, "{s}:{d}:{d}: {s}[{s}]: {s}\n", .{
        primary_source.path,
        location.line,
        location.column,
        severityName(value.severity),
        value.code.id(),
        value.message,
    });
    try appendExcerpt(&output, allocator, registry, value.primary, limits);
    if (value.secondary) |secondary| {
        try registry.validateSpan(secondary);
        const secondary_source = registry.get(secondary.source).?;
        const secondary_location = try registry.location(secondary.source, secondary.start);
        try appendFmt(&output, allocator, limits.max_bytes, "note: related location {s}:{d}:{d}\n", .{
            secondary_source.path,
            secondary_location.line,
            secondary_location.column,
        });
    }

    var current = primary_source.included_from;
    var depth: usize = 0;
    while (current) |origin| : (depth += 1) {
        if (depth == limits.max_include_depth) {
            try appendBounded(&output, allocator, "note: include ancestry truncated\n", limits.max_bytes);
            break;
        }
        const parent_source = registry.get(origin.parent) orelse return error.InvalidIncludeOrigin;
        const parent_location = try registry.location(origin.parent, origin.directive.start);
        try appendFmt(&output, allocator, limits.max_bytes, "included from {s}:{d}:{d}\n", .{
            parent_source.path,
            parent_location.line,
            parent_location.column,
        });
        current = parent_source.included_from;
    }
    return output.toOwnedSlice(allocator);
}

fn appendExcerpt(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    registry: *const source.Registry,
    span: source.Span,
    limits: RenderLimits,
) RenderError!void {
    const input = registry.get(span.source).?;
    const location = try registry.location(span.source, span.start);
    const line_start = input.line_starts[location.line - 1];
    const newline = std.mem.indexOfScalarPos(u8, input.bytes, line_start, '\n');
    var line_end: usize = newline orelse input.bytes.len;
    if (line_end > line_start and input.bytes[line_end - 1] == '\r') line_end -= 1;
    const excerpt_end = @min(line_end, @as(usize, line_start) + limits.max_excerpt_bytes);
    const excerpt = input.bytes[line_start..excerpt_end];
    try appendBounded(output, allocator, excerpt, limits.max_bytes);
    if (excerpt_end < line_end) try appendBounded(output, allocator, "...", limits.max_bytes);
    try appendBounded(output, allocator, "\n", limits.max_bytes);

    const caret_column = @min(@as(usize, location.column - 1), excerpt.len);
    var index: usize = 0;
    while (index < caret_column) : (index += 1) {
        const marker: []const u8 = if (excerpt[index] == '\t') "\t" else " ";
        try appendBounded(output, allocator, marker, limits.max_bytes);
    }
    try appendBounded(output, allocator, "^\n", limits.max_bytes);
}

fn appendFmt(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    max_bytes: usize,
    comptime format: []const u8,
    arguments: anytype,
) std.mem.Allocator.Error!void {
    const formatted = try std.fmt.allocPrint(allocator, format, arguments);
    defer allocator.free(formatted);
    try appendBounded(output, allocator, formatted, max_bytes);
}

fn appendBounded(output: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8, max_bytes: usize) std.mem.Allocator.Error!void {
    if (output.items.len == max_bytes) return;
    const available = max_bytes - output.items.len;
    try output.appendSlice(allocator, bytes[0..@min(bytes.len, available)]);
}

fn severityName(severity: Severity) []const u8 {
    return switch (severity) {
        .error_ => "error",
        .warning => "warning",
        .note => "note",
    };
}

fn codeFromError(failure: anyerror) Code {
    if (failure == error.InvalidParserLimit or failure == error.InvalidLexerLimit or failure == error.InvalidSyntaxLimit) return .invalid_parser_limit;
    if (failure == error.InvalidSourceId) return .invalid_source;
    if (failure == error.LogicalLineTooLarge) return .logical_line_too_large;
    if (failure == error.TooManyLineSegments) return .too_many_line_segments;
    if (failure == error.DanglingContinuation) return .dangling_continuation;
    if (failure == error.TooManyTokens) return .too_many_tokens;
    if (failure == error.TokenTooLarge) return .token_too_large;
    if (failure == error.UnterminatedQuote) return .unterminated_quote;
    if (failure == error.DanglingEscape) return .dangling_escape;
    if (failure == error.TooManyDirectives) return .too_many_directives;
    if (failure == error.TooManyArguments) return .too_many_arguments;
    if (failure == error.InvalidDirectiveName) return .invalid_directive_name;
    if (failure == error.MissingRuleTargets) return .missing_rule_targets;
    if (failure == error.MissingRuleOperator) return .missing_rule_operator;
    if (failure == error.TooManyRuleArguments) return .too_many_rule_arguments;
    if (failure == error.MissingActionList) return .missing_action_list;
    if (failure == error.TooManyActionArguments) return .too_many_action_arguments;
    if (failure == error.MissingMarker) return .missing_marker;
    if (failure == error.TooManyMarkerArguments) return .too_many_marker_arguments;
    if (failure == error.MissingIncludePath) return .missing_include_path;
    if (failure == error.TooManyIncludeArguments) return .too_many_include_arguments;
    if (failure == error.TooManyTargets) return .too_many_targets;
    if (failure == error.TooManyActions) return .too_many_actions;
    if (failure == error.EmptyTarget) return .empty_target;
    if (failure == error.InvalidTargetModifier) return .invalid_target_modifier;
    if (failure == error.MissingTargetCollection) return .missing_target_collection;
    if (failure == error.EmptyOperator) return .empty_operator;
    if (failure == error.MissingOperatorName) return .missing_operator_name;
    if (failure == error.EmptyAction) return .empty_action;
    if (failure == error.MissingActionName) return .missing_action_name;
    if (failure == error.UnterminatedNestedQuote) return .unterminated_nested_quote;
    if (failure == error.DanglingNestedEscape) return .dangling_nested_escape;
    return .syntax;
}

fn messageForCode(code: Code) []const u8 {
    return switch (code) {
        .invalid_parser_limit => "invalid SecLang parser resource limit",
        .invalid_source => "invalid SecLang source identifier",
        .logical_line_too_large => "logical line exceeds its configured byte limit",
        .too_many_line_segments => "logical line has too many continuation segments",
        .dangling_continuation => "continuation marker has no following physical line",
        .too_many_tokens => "logical line has too many tokens",
        .token_too_large => "token exceeds its configured byte limit",
        .unterminated_quote => "quoted argument is not terminated",
        .dangling_escape => "escape marker has no following byte",
        .too_many_directives => "source has too many directives",
        .too_many_arguments => "source has too many directive arguments",
        .invalid_directive_name => "directive name is malformed or quoted",
        .missing_rule_targets => "SecRule is missing its target list",
        .missing_rule_operator => "SecRule is missing its operator",
        .too_many_rule_arguments => "SecRule has trailing arguments",
        .missing_action_list => "action directive is missing its action list",
        .too_many_action_arguments => "action directive has trailing arguments",
        .missing_marker => "SecMarker is missing its marker",
        .too_many_marker_arguments => "SecMarker has trailing arguments",
        .missing_include_path => "include directive is missing its path",
        .too_many_include_arguments => "include directive has trailing arguments",
        .too_many_targets => "SecRule has too many targets",
        .too_many_actions => "rule has too many actions",
        .empty_target => "SecRule target list contains an empty target",
        .invalid_target_modifier => "SecRule target has invalid stacked modifiers",
        .missing_target_collection => "SecRule target is missing its collection",
        .empty_operator => "SecRule operator is empty",
        .missing_operator_name => "SecRule operator is missing its name",
        .empty_action => "action list contains an empty action",
        .missing_action_name => "action is missing its name",
        .unterminated_nested_quote => "action value contains an unterminated quote",
        .dangling_nested_escape => "target or action ends with an escape marker",
        .syntax => "invalid SecLang syntax",
    };
}

test "human diagnostics include exact location excerpt and ancestry" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const root = try registry.add("root.conf", "Include child.conf\n", null);
    const child = try registry.add("child.conf", "SecAction pass\nSecRule ARGS\n", .{
        .parent = root,
        .directive = .{ .source = root, .start = 0, .end = 18 },
    });
    const value = Diagnostic.fromError(error.MissingRuleOperator, .{ .source = child, .start = 27, .end = 27 });
    const rendered = try renderHuman(std.testing.allocator, &registry, value, .{});
    defer std.testing.allocator.free(rendered);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "child.conf:2:13: error[WAF-SECLANG-0205]") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "SecRule ARGS\n            ^") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "included from root.conf:1:1") != null);
}

test "human diagnostic rendering obeys its hard byte bound" {
    var registry = try source.Registry.init(std.testing.allocator, .{});
    defer registry.deinit();
    const id = try registry.add("long.conf", "SecAction aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", null);
    const value = Diagnostic.fromError(error.TokenTooLarge, .{ .source = id, .start = 0, .end = 1 });
    const rendered = try renderHuman(std.testing.allocator, &registry, value, .{ .max_bytes = 64, .max_excerpt_bytes = 8 });
    defer std.testing.allocator.free(rendered);
    try std.testing.expectEqual(@as(usize, 64), rendered.len);
}
