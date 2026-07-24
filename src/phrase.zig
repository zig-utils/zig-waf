//! ASCII case-insensitive Aho-Corasick multi-pattern matcher backing the `@pm`
//! family of operators. The compiled automaton is immutable and shareable; it
//! reports whether any pattern occurs in an input and iterates leftmost-longest
//! non-overlapping matches for capture extraction.

const std = @import("std");

pub const BuildError = std.mem.Allocator.Error || error{
    TooManyPatterns,
    TooManyStates,
    PatternTooLong,
};

pub const Limits = struct {
    max_patterns: usize = 1 << 20,
    max_pattern_bytes: usize = 64 * 1024,
    max_states: usize = 1 << 24,
};

pub const Match = struct {
    /// Byte offset of the match start in the searched input.
    start: usize,
    /// Byte offset just past the match end in the searched input.
    end: usize,
};

const root: u32 = 0;

const Edge = struct { byte: u8, target: u32 };

const Node = struct {
    edges_start: u32,
    edges_len: u32,
    fail: u32,
    /// Length of the longest pattern ending exactly at this state (0 = none).
    output_len: u32,
    /// True when this state, or any state reachable through the failure chain,
    /// is terminal — the O(1) membership test for the boolean `contains`.
    terminal: bool,
};

pub const AhoCorasick = struct {
    allocator: std.mem.Allocator,
    nodes: []Node,
    edges: []Edge,
    /// An empty pattern matches at every position, so the automaton always hits.
    always_match: bool,

    pub fn deinit(self: *AhoCorasick) void {
        self.allocator.free(self.nodes);
        self.allocator.free(self.edges);
        self.* = undefined;
    }

    /// Lowercased leftmost transition for `byte` from `state`, following the
    /// failure chain when no explicit edge exists.
    fn step(self: *const AhoCorasick, state: u32, byte: u8) u32 {
        const c = std.ascii.toLower(byte);
        var current = state;
        while (true) {
            if (self.edge(current, c)) |target| return target;
            if (current == root) return root;
            current = self.nodes[current].fail;
        }
    }

    fn edge(self: *const AhoCorasick, state: u32, c: u8) ?u32 {
        const node = self.nodes[state];
        const slice = self.edges[node.edges_start .. node.edges_start + node.edges_len];
        var low: usize = 0;
        var high: usize = slice.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (slice[mid].byte == c) return slice[mid].target;
            if (slice[mid].byte < c) low = mid + 1 else high = mid;
        }
        return null;
    }

    /// True when any compiled pattern occurs in `input` (case-insensitively).
    pub fn contains(self: *const AhoCorasick, input: []const u8) bool {
        if (self.always_match) return true;
        var state: u32 = root;
        for (input) |byte| {
            state = self.step(state, byte);
            if (self.nodes[state].terminal) return true;
        }
        return false;
    }

    /// A non-overlapping match iterator for capture extraction. It reports, at
    /// each successive position where a pattern ends, the longest pattern ending
    /// there, then resumes scanning after that match. The `@pm` boolean result
    /// uses `contains`; capture position semantics are not corpus-pinned.
    pub const Iterator = struct {
        automaton: *const AhoCorasick,
        input: []const u8,
        pos: usize = 0,
        state: u32 = root,

        pub fn next(self: *Iterator) ?Match {
            if (self.automaton.always_match) {
                if (self.pos > self.input.len) return null;
                const at = self.pos;
                self.pos += 1;
                return .{ .start = at, .end = at };
            }
            while (self.pos < self.input.len) : (self.pos += 1) {
                self.state = self.automaton.step(self.state, self.input[self.pos]);
                const output_len = self.longestOutput(self.state);
                if (output_len != 0) {
                    const end = self.pos + 1;
                    const start = end - output_len;
                    self.pos = end;
                    self.state = root;
                    return .{ .start = start, .end = end };
                }
            }
            return null;
        }

        /// The longest pattern ending at `state`, scanning the failure chain.
        fn longestOutput(self: *Iterator, state: u32) u32 {
            var current = state;
            var best: u32 = 0;
            while (current != root) {
                if (self.automaton.nodes[current].output_len > best)
                    best = self.automaton.nodes[current].output_len;
                current = self.automaton.nodes[current].fail;
            }
            return best;
        }
    };

    pub fn iterator(self: *const AhoCorasick, input: []const u8) Iterator {
        return .{ .automaton = self, .input = input };
    }
};

const BuildNode = struct {
    edges: std.AutoHashMapUnmanaged(u8, u32) = .empty,
    fail: u32 = root,
    output_len: u32 = 0,
    terminal: bool = false,
};

/// Compile the space- or list-separated `patterns` into an immutable automaton.
/// Patterns are lowercased for ASCII case-insensitive matching; empty patterns
/// make the automaton always match, mirroring the pinned engines.
pub fn build(allocator: std.mem.Allocator, patterns: []const []const u8, limits: Limits) BuildError!AhoCorasick {
    if (patterns.len > limits.max_patterns) return error.TooManyPatterns;

    var nodes: std.ArrayList(BuildNode) = .empty;
    defer {
        for (nodes.items) |*node| node.edges.deinit(allocator);
        nodes.deinit(allocator);
    }
    try nodes.append(allocator, .{}); // root

    var always_match = false;
    for (patterns) |pattern| {
        if (pattern.len == 0) {
            always_match = true;
            continue;
        }
        if (pattern.len > limits.max_pattern_bytes) return error.PatternTooLong;
        var state: u32 = root;
        for (pattern) |byte| {
            const c = std.ascii.toLower(byte);
            const gop = try nodes.items[state].edges.getOrPut(allocator, c);
            if (!gop.found_existing) {
                if (nodes.items.len >= limits.max_states) return error.TooManyStates;
                const next_index: u32 = @intCast(nodes.items.len);
                gop.value_ptr.* = next_index;
                try nodes.append(allocator, .{});
            }
            state = gop.value_ptr.*;
        }
        const len: u32 = @intCast(pattern.len);
        if (len > nodes.items[state].output_len) nodes.items[state].output_len = len;
        nodes.items[state].terminal = true;
    }

    try computeFailureLinks(allocator, nodes.items);
    return try freeze(allocator, nodes.items, always_match);
}

/// Breadth-first failure-link construction. A state's `terminal` flag is folded
/// down the failure chain so `contains` is a single O(1) check per input byte.
fn computeFailureLinks(allocator: std.mem.Allocator, nodes: []BuildNode) BuildError!void {
    var queue: std.ArrayList(u32) = .empty;
    defer queue.deinit(allocator);

    var it = nodes[root].edges.iterator();
    while (it.next()) |entry| {
        nodes[entry.value_ptr.*].fail = root;
        try queue.append(allocator, entry.value_ptr.*);
    }

    var head: usize = 0;
    while (head < queue.items.len) : (head += 1) {
        const state = queue.items[head];
        // Snapshot child edges: the map is stable during this pass.
        var child_it = nodes[state].edges.iterator();
        while (child_it.next()) |entry| {
            const byte = entry.key_ptr.*;
            const child = entry.value_ptr.*;
            var fail = nodes[state].fail;
            while (fail != root and nodes[fail].edges.get(byte) == null) fail = nodes[fail].fail;
            const target = nodes[fail].edges.get(byte) orelse root;
            nodes[child].fail = if (target == child) root else target;
            if (nodes[nodes[child].fail].terminal) nodes[child].terminal = true;
            try queue.append(allocator, child);
        }
    }
}

fn freeze(allocator: std.mem.Allocator, nodes: []BuildNode, always_match: bool) BuildError!AhoCorasick {
    var total_edges: usize = 0;
    for (nodes) |node| total_edges += node.edges.count();

    const frozen_nodes = try allocator.alloc(Node, nodes.len);
    errdefer allocator.free(frozen_nodes);
    const frozen_edges = try allocator.alloc(Edge, total_edges);
    errdefer allocator.free(frozen_edges);

    var edge_cursor: u32 = 0;
    for (nodes, 0..) |node, index| {
        const start = edge_cursor;
        var it = node.edges.iterator();
        while (it.next()) |entry| {
            frozen_edges[edge_cursor] = .{ .byte = entry.key_ptr.*, .target = entry.value_ptr.* };
            edge_cursor += 1;
        }
        // Sort this node's edges by byte so lookups can binary-search.
        std.mem.sort(Edge, frozen_edges[start..edge_cursor], {}, lessThanByte);
        frozen_nodes[index] = .{
            .edges_start = start,
            .edges_len = @intCast(node.edges.count()),
            .fail = node.fail,
            .output_len = node.output_len,
            .terminal = node.terminal,
        };
    }

    return .{
        .allocator = allocator,
        .nodes = frozen_nodes,
        .edges = frozen_edges,
        .always_match = always_match,
    };
}

fn lessThanByte(_: void, a: Edge, b: Edge) bool {
    return a.byte < b.byte;
}

test "aho-corasick reports case-insensitive substring membership" {
    const patterns = [_][]const u8{ "abc", "def", "ghi" };
    var automaton = try build(std.testing.allocator, &patterns, .{});
    defer automaton.deinit();

    try std.testing.expect(automaton.contains("abcdefghi"));
    try std.testing.expect(automaton.contains("XXDEFXX"));
    try std.testing.expect(!automaton.contains(""));
    try std.testing.expect(!automaton.contains("nothing here"));
}

test "aho-corasick empty pattern always matches" {
    const patterns = [_][]const u8{ "", "abc" };
    var automaton = try build(std.testing.allocator, &patterns, .{});
    defer automaton.deinit();
    try std.testing.expect(automaton.contains(""));
    try std.testing.expect(automaton.contains("anything"));
}

test "aho-corasick iterates the longest pattern ending at each terminal position" {
    const patterns = [_][]const u8{ "he", "hers", "his", "she" };
    var automaton = try build(std.testing.allocator, &patterns, .{});
    defer automaton.deinit();

    // "ushers": the first terminal ends at index 4 with the longest pattern
    // ending there ("she", 1..4); the remainder "rs" holds no further pattern.
    var it = automaton.iterator("ushers");
    const first = it.next().?;
    try std.testing.expectEqualStrings("she", "ushers"[first.start..first.end]);
    try std.testing.expect(it.next() == null);
}

test "aho-corasick reports successive non-overlapping matches" {
    const patterns = [_][]const u8{ "she", "he" };
    var automaton = try build(std.testing.allocator, &patterns, .{});
    defer automaton.deinit();

    const input = "she said he ran";
    var it = automaton.iterator(input);
    const first = it.next().?;
    try std.testing.expectEqualStrings("she", input[first.start..first.end]);
    const second = it.next().?;
    try std.testing.expectEqualStrings("he", input[second.start..second.end]);
    try std.testing.expect(it.next() == null);
}

test "aho-corasick bounds pattern and state counts" {
    const patterns = [_][]const u8{"toolong"};
    try std.testing.expectError(error.PatternTooLong, build(std.testing.allocator, &patterns, .{ .max_pattern_bytes = 3 }));
    try std.testing.expectError(error.TooManyPatterns, build(std.testing.allocator, &patterns, .{ .max_patterns = 0 }));
}
