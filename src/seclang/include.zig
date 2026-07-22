//! Root-confined, deterministic local SecLang include resolution.

const std = @import("std");
const builtin = @import("builtin");
const parser = @import("parser.zig");
const source = @import("source.zig");

pub const Limits = struct {
    max_depth: usize = 64,
    max_glob_matches: usize = 4096,
    max_pattern_bytes: usize = 4096,

    pub fn validate(self: Limits) error{InvalidIncludeLimit}!void {
        if (self.max_depth == 0 or self.max_glob_matches == 0 or self.max_pattern_bytes == 0)
            return error.InvalidIncludeLimit;
    }
};

pub const Policy = struct {
    allow_absolute_includes: bool = false,
};

pub const Options = struct {
    source_limits: source.Limits = .{},
    parser_limits: parser.Limits = .{},
    include_limits: Limits = .{},
    policy: Policy = .{},
};

pub const IncludeError = error{
    InvalidIncludeLimit,
    AbsoluteIncludeForbidden,
    IncludeRootEscape,
    IncludeNotFound,
    IncludeCycle,
    IncludeDepthExceeded,
    TooManyGlobMatches,
    IncludePatternTooLarge,
    InvalidIncludePattern,
    NonRegularInclude,
};

pub const Tree = struct {
    allocator: std.mem.Allocator,
    registry: source.Registry,
    documents: std.ArrayList(parser.Document) = .empty,
    remote_sources: std.ArrayList(RemoteSource) = .empty,
    remote_warnings: std.ArrayList(RemoteWarning) = .empty,

    pub fn deinit(self: *Tree) void {
        for (self.documents.items) |*document| document.deinit();
        self.documents.deinit(self.allocator);
        self.remote_sources.deinit(self.allocator);
        self.remote_warnings.deinit(self.allocator);
        self.registry.deinit();
        self.* = undefined;
    }
};

pub const RemoteSource = struct {
    source_id: source.SourceId,
    directive: source.Span,
    content_digest: [32]u8,
};

pub const RemoteWarning = struct {
    directive: source.Span,
    code: @import("../remote_rules.zig").WarningCode,
};

pub fn parseTree(
    allocator: std.mem.Allocator,
    io: std.Io,
    configuration_root: []const u8,
    entry_path: []const u8,
    options: Options,
) !Tree {
    try options.include_limits.validate();
    const root = try std.Io.Dir.cwd().realPathFileAlloc(io, configuration_root, allocator);
    defer allocator.free(root);

    var tree: Tree = .{
        .allocator = allocator,
        .registry = try source.Registry.init(allocator, options.source_limits),
    };
    errdefer tree.deinit();
    var context: Context = .{
        .allocator = allocator,
        .io = io,
        .root = root,
        .options = options,
        .tree = &tree,
    };
    defer context.deinit();

    const candidates = try context.expand(root, entry_path, false);
    defer freePaths(allocator, candidates);
    if (candidates.len != 1) return error.IncludeNotFound;
    try context.loadFile(candidates[0], null, 1);
    return tree;
}

pub fn parseFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    options: Options,
) !Tree {
    const canonical = try std.Io.Dir.cwd().realPathFileAlloc(io, path, allocator);
    defer allocator.free(canonical);
    const parent = std.fs.path.dirname(canonical) orelse return error.IncludeNotFound;
    return parseTree(allocator, io, parent, std.fs.path.basename(canonical), options);
}

const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    options: Options,
    tree: *Tree,
    loaded: std.StringHashMapUnmanaged(source.SourceId) = .empty,
    active: std.StringHashMapUnmanaged(void) = .empty,

    fn deinit(self: *Context) void {
        self.loaded.deinit(self.allocator);
        self.active.deinit(self.allocator);
    }

    fn loadFile(self: *Context, canonical_path: []const u8, included_from: ?source.IncludeOrigin, depth: usize) !void {
        if (depth > self.options.include_limits.max_depth) return error.IncludeDepthExceeded;
        if (self.active.contains(canonical_path)) return error.IncludeCycle;
        if (self.loaded.contains(canonical_path)) return;
        if (!withinRoot(self.root, canonical_path)) return error.IncludeRootEscape;
        const stat = try std.Io.Dir.cwd().statFile(self.io, canonical_path, .{});
        if (stat.kind != .file) return error.NonRegularInclude;

        const read_limit = std.math.add(usize, self.options.source_limits.max_source_bytes, 1) catch
            self.options.source_limits.max_source_bytes;
        const bytes = std.Io.Dir.cwd().readFileAlloc(
            self.io,
            canonical_path,
            self.allocator,
            .limited(read_limit),
        ) catch |failure| switch (failure) {
            error.StreamTooLong => return error.SourceTooLarge,
            else => |other| return other,
        };
        defer self.allocator.free(bytes);
        const source_id = try self.tree.registry.add(canonical_path, bytes, included_from);
        const owned_path = self.tree.registry.get(source_id).?.path;
        try self.loaded.put(self.allocator, owned_path, source_id);
        try self.active.put(self.allocator, owned_path, {});
        defer _ = self.active.remove(owned_path);

        var document = try parser.parseSource(self.allocator, &self.tree.registry, source_id, self.options.parser_limits);
        const document_index = self.tree.documents.items.len;
        self.tree.documents.append(self.allocator, document) catch |failure| {
            document.deinit();
            return failure;
        };

        const directives = self.tree.documents.items[document_index].directives.items;
        const parent_directory = std.fs.path.dirname(owned_path) orelse self.root;
        for (directives) |directive| {
            if (directive.kind != .include and directive.kind != .include_optional) continue;
            const optional = directive.kind == .include_optional;
            const requested = directive.arguments[0].content();
            const candidates = try self.expand(parent_directory, requested, optional);
            defer freePaths(self.allocator, candidates);
            for (candidates) |candidate| {
                try self.loadFile(candidate, .{ .parent = source_id, .directive = directive.physical }, depth + 1);
            }
        }
    }

    fn expand(self: *Context, parent_directory: []const u8, requested: []const u8, optional: bool) ![][]u8 {
        if (requested.len == 0) return error.IncludeNotFound;
        if (requested.len > self.options.include_limits.max_pattern_bytes) return error.IncludePatternTooLarge;
        try validateGlob(requested);
        if (std.fs.path.isAbsolute(requested) and !self.options.policy.allow_absolute_includes)
            return error.AbsoluteIncludeForbidden;

        const resolved = if (std.fs.path.isAbsolute(requested))
            try std.fs.path.resolve(self.allocator, &.{requested})
        else
            try std.fs.path.resolve(self.allocator, &.{ parent_directory, requested });
        defer self.allocator.free(resolved);
        if (!withinRoot(self.root, resolved)) return error.IncludeRootEscape;

        if (!hasGlob(requested)) {
            const canonical = canonicalPathAlloc(self.allocator, self.io, resolved) catch |failure| switch (failure) {
                error.FileNotFound => {
                    if (optional) return self.allocator.alloc([]u8, 0);
                    return error.IncludeNotFound;
                },
                else => |other| return other,
            };
            if (!withinRoot(self.root, canonical)) {
                self.allocator.free(canonical);
                return error.IncludeRootEscape;
            }
            const result = self.allocator.alloc([]u8, 1) catch |failure| {
                self.allocator.free(canonical);
                return failure;
            };
            result[0] = canonical;
            return result;
        }

        var directory = try std.Io.Dir.openDirAbsolute(self.io, self.root, .{ .iterate = true });
        defer directory.close(self.io);
        var walker = try directory.walk(self.allocator);
        defer walker.deinit();
        var matches: std.ArrayList([]u8) = .empty;
        errdefer freePathList(self.allocator, &matches);
        while (try walker.next(self.io)) |entry| {
            if (entry.kind == .directory) continue;
            const candidate = try std.fs.path.join(self.allocator, &.{ self.root, entry.path });
            defer self.allocator.free(candidate);
            if (!globMatches(resolved, candidate)) continue;
            const canonical = try canonicalPathAlloc(self.allocator, self.io, candidate);
            if (!withinRoot(self.root, canonical)) {
                self.allocator.free(canonical);
                return error.IncludeRootEscape;
            }
            if (!containsPath(matches.items, canonical)) {
                if (matches.items.len == self.options.include_limits.max_glob_matches) {
                    self.allocator.free(canonical);
                    return error.TooManyGlobMatches;
                }
                matches.append(self.allocator, canonical) catch |failure| {
                    self.allocator.free(canonical);
                    return failure;
                };
            } else {
                self.allocator.free(canonical);
            }
        }
        if (matches.items.len == 0 and !optional) return error.IncludeNotFound;
        std.mem.sort([]u8, matches.items, {}, pathLessThan);
        return matches.toOwnedSlice(self.allocator);
    }
};

fn withinRoot(root: []const u8, candidate: []const u8) bool {
    if (pathEqual(root, candidate)) return true;
    if (candidate.len <= root.len or !pathStartsWith(candidate, root)) return false;
    return std.fs.path.isSep(candidate[root.len]);
}

fn pathEqual(left: []const u8, right: []const u8) bool {
    return if (builtin.os.tag == .windows)
        std.ascii.eqlIgnoreCase(left, right)
    else
        std.mem.eql(u8, left, right);
}

fn pathStartsWith(candidate: []const u8, root: []const u8) bool {
    if (root.len > candidate.len) return false;
    return if (builtin.os.tag == .windows)
        std.ascii.eqlIgnoreCase(candidate[0..root.len], root)
    else
        std.mem.eql(u8, candidate[0..root.len], root);
}

fn hasGlob(path: []const u8) bool {
    return std.mem.indexOfAny(u8, path, "*?[") != null;
}

fn validateGlob(pattern: []const u8) error{InvalidIncludePattern}!void {
    var index: usize = 0;
    while (index < pattern.len) : (index += 1) {
        if (pattern[index] != '[') continue;
        const closing = std.mem.indexOfScalarPos(u8, pattern, index + 1, ']') orelse
            return error.InvalidIncludePattern;
        if (closing == index + 1) return error.InvalidIncludePattern;
        index = closing;
    }
}

fn containsPath(paths: []const []u8, wanted: []const u8) bool {
    for (paths) |path| if (pathEqual(path, wanted)) return true;
    return false;
}

fn pathLessThan(_: void, left: []u8, right: []u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn canonicalPathAlloc(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const sentinel_path = try std.Io.Dir.cwd().realPathFileAlloc(io, path, allocator);
    defer allocator.free(sentinel_path);
    return allocator.dupe(u8, sentinel_path);
}

fn freePathList(allocator: std.mem.Allocator, paths: *std.ArrayList([]u8)) void {
    for (paths.items) |path| allocator.free(path);
    paths.deinit(allocator);
}

fn freePaths(allocator: std.mem.Allocator, paths: [][]u8) void {
    for (paths) |path| allocator.free(path);
    allocator.free(paths);
}

fn globMatches(pattern: []const u8, text: []const u8) bool {
    var pattern_index: usize = 0;
    var text_index: usize = 0;
    var star_pattern: ?usize = null;
    var star_text: usize = 0;
    while (text_index < text.len) {
        if (pattern_index < pattern.len and pattern[pattern_index] == '*') {
            while (pattern_index < pattern.len and pattern[pattern_index] == '*') pattern_index += 1;
            star_pattern = pattern_index;
            star_text = text_index;
            continue;
        }
        if (pattern_index < pattern.len and tokenMatches(pattern, &pattern_index, text[text_index])) {
            text_index += 1;
            continue;
        }
        if (star_pattern) |after_star| {
            if (star_text == text.len or std.fs.path.isSep(text[star_text])) return false;
            star_text += 1;
            text_index = star_text;
            pattern_index = after_star;
            continue;
        }
        return false;
    }
    while (pattern_index < pattern.len and pattern[pattern_index] == '*') pattern_index += 1;
    return pattern_index == pattern.len;
}

fn tokenMatches(pattern: []const u8, pattern_index: *usize, byte: u8) bool {
    const current = pattern[pattern_index.*];
    if (std.fs.path.isSep(current)) {
        if (!std.fs.path.isSep(byte)) return false;
        pattern_index.* += 1;
        return true;
    }
    if (std.fs.path.isSep(byte)) return false;
    if (current == '?') {
        pattern_index.* += 1;
        return true;
    }
    if (current == '[') {
        const closing = std.mem.indexOfScalarPos(u8, pattern, pattern_index.* + 1, ']') orelse return false;
        const matched = classMatches(pattern[pattern_index.* + 1 .. closing], byte);
        pattern_index.* = closing + 1;
        return matched;
    }
    if (current != byte) return false;
    pattern_index.* += 1;
    return true;
}

fn classMatches(class: []const u8, byte: u8) bool {
    if (class.len == 0) return false;
    var index: usize = 0;
    const negated = class[0] == '!' or class[0] == '^';
    if (negated) index = 1;
    var matched = false;
    while (index < class.len) {
        if (index + 2 < class.len and class[index + 1] == '-') {
            matched = matched or (byte >= class[index] and byte <= class[index + 2]);
            index += 3;
        } else {
            matched = matched or byte == class[index];
            index += 1;
        }
    }
    return if (negated) !matched else matched;
}

test "include tree expands sorted globs and deduplicates canonical sources" {
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.createDirPath(std.testing.io, "rules");
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "main.conf", .data = "Include rules/*.conf\nInclude rules/a.conf" });
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "rules/b.conf", .data = "SecAction \"id:2,pass\"" });
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "rules/a.conf", .data = "SecAction \"id:1,pass\"" });
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &root_buffer);
    var tree = try parseTree(std.testing.allocator, std.testing.io, root_buffer[0..root_length], "main.conf", .{});
    defer tree.deinit();
    try std.testing.expectEqual(@as(usize, 3), tree.documents.items.len);
    try std.testing.expectEqualStrings("a.conf", std.fs.path.basename(tree.registry.get(tree.documents.items[1].source_id).?.path));
    try std.testing.expectEqualStrings("b.conf", std.fs.path.basename(tree.registry.get(tree.documents.items[2].source_id).?.path));
}

test "optional includes may be absent and required cycles fail" {
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "optional.conf", .data = "IncludeOptional absent/*.conf\nSecAction pass" });
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "a.conf", .data = "Include b.conf" });
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "b.conf", .data = "Include a.conf" });
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &root_buffer);
    var optional = try parseTree(std.testing.allocator, std.testing.io, root_buffer[0..root_length], "optional.conf", .{});
    defer optional.deinit();
    try std.testing.expectEqual(@as(usize, 1), optional.documents.items.len);
    try std.testing.expectError(error.IncludeCycle, parseTree(std.testing.allocator, std.testing.io, root_buffer[0..root_length], "a.conf", .{}));
}

test "include root rejects traversal absolute paths and symlink escapes" {
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.createDirPath(std.testing.io, "root");
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "outside.conf", .data = "SecAction pass" });
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "root/traversal.conf", .data = "Include ../outside.conf" });
    try temporary.dir.symLink(std.testing.io, "../outside.conf", "root/escape.conf", .{});
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "root/symlink.conf", .data = "Include escape.conf" });
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPathFile(std.testing.io, "root", &root_buffer);
    const root = root_buffer[0..root_length];
    try std.testing.expectError(error.IncludeRootEscape, parseTree(std.testing.allocator, std.testing.io, root, "traversal.conf", .{}));
    try std.testing.expectError(error.IncludeRootEscape, parseTree(std.testing.allocator, std.testing.io, root, "symlink.conf", .{}));
    const absolute = try std.fs.path.join(std.testing.allocator, &.{ root, "traversal.conf" });
    defer std.testing.allocator.free(absolute);
    try std.testing.expectError(error.AbsoluteIncludeForbidden, parseTree(std.testing.allocator, std.testing.io, root, absolute, .{}));
}

test "include graph enforces depth and glob match limits" {
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "main.conf", .data = "Include *.child" });
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "a.child", .data = "SecAction pass" });
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "b.child", .data = "SecAction pass" });
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "depth.conf", .data = "Include a.child" });
    var root_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &root_buffer);
    const root = root_buffer[0..root_length];
    try std.testing.expectError(error.TooManyGlobMatches, parseTree(std.testing.allocator, std.testing.io, root, "main.conf", .{ .include_limits = .{ .max_glob_matches = 1 } }));
    try std.testing.expectError(error.IncludeDepthExceeded, parseTree(std.testing.allocator, std.testing.io, root, "depth.conf", .{ .include_limits = .{ .max_depth = 1 } }));
}

test "glob matcher handles bounded wildcards classes and separators" {
    try std.testing.expect(globMatches("/root/rules/*.conf", "/root/rules/a.conf"));
    try std.testing.expect(globMatches("/root/rules/rule-9[0-9]?.conf", "/root/rules/rule-942.conf"));
    try std.testing.expect(!globMatches("/root/rules/*.conf", "/root/rules/nested/a.conf"));
    try std.testing.expectError(error.InvalidIncludePattern, validateGlob("rules/[abc.conf"));
}

test "file convenience API resolves includes relative to the entry" {
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.createDirPath(std.testing.io, "config/nested");
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "config/main.conf", .data = "Include nested/rule.conf" });
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "config/nested/rule.conf", .data = "SecAction pass" });
    var entry_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const entry_length = try temporary.dir.realPathFile(std.testing.io, "config/main.conf", &entry_buffer);
    var tree = try parseFile(std.testing.allocator, std.testing.io, entry_buffer[0..entry_length], .{});
    defer tree.deinit();
    try std.testing.expectEqual(@as(usize, 2), tree.documents.items.len);
}
