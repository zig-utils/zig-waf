//! Ordered local/remote SecLang source-tree assembly.

const std = @import("std");
const include = @import("include.zig");
const parser = @import("parser.zig");
const remote_rules = @import("../remote_rules.zig");
const source = @import("source.zig");

pub const Options = struct {
    remote_limits: remote_rules.Limits = .{},
    parser_limits: parser.Limits = .{},
    max_remote_depth: usize = 16,
    max_warnings: usize = 4096,

    pub fn validate(self: Options) error{InvalidAssemblyLimit}!void {
        self.remote_limits.validate() catch return error.InvalidAssemblyLimit;
        if (self.max_remote_depth == 0 or self.max_warnings == 0) return error.InvalidAssemblyLimit;
    }
};

pub const AssemblyError = error{
    InvalidAssemblyLimit,
    RemoteDepthExceeded,
    RemoteCycle,
    RemoteLocalIncludeForbidden,
    TooManyRemoteWarnings,
    MissingAssemblyRoot,
};

pub fn assembleFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    include_options: include.Options,
    fetcher: remote_rules.Fetcher,
    destination_policy: remote_rules.DestinationPolicy,
    options: Options,
) !include.Tree {
    var tree = try include.parseFile(allocator, io, path, include_options);
    errdefer tree.deinit();
    try resolveRemoteRules(&tree, fetcher, destination_policy, options);
    return tree;
}

pub fn resolveRemoteRules(
    tree: *include.Tree,
    fetcher: remote_rules.Fetcher,
    destination_policy: remote_rules.DestinationPolicy,
    options: Options,
) !void {
    try options.validate();
    var context: Context = .{
        .tree = tree,
        .fetcher = fetcher,
        .destination_policy = destination_policy,
        .options = options,
    };
    defer context.deinit();
    var found_root = false;
    var index: usize = 0;
    while (index < tree.documents.items.len) : (index += 1) {
        const document = tree.documents.items[index];
        const record = tree.registry.get(document.source_id) orelse continue;
        if (record.included_from != null) continue;
        found_root = true;
        try context.processDocument(index, false, 0);
    }
    if (!found_root) return error.MissingAssemblyRoot;
}

const Context = struct {
    tree: *include.Tree,
    fetcher: remote_rules.Fetcher,
    destination_policy: remote_rules.DestinationPolicy,
    options: Options,
    fail_action: remote_rules.FailAction = .abort,
    visited: std.AutoHashMapUnmanaged(source.SourceId, void) = .empty,
    active_urls: std.StringHashMapUnmanaged(void) = .empty,

    fn deinit(self: *Context) void {
        self.visited.deinit(self.tree.allocator);
        self.active_urls.deinit(self.tree.allocator);
    }

    fn processDocument(self: *Context, document_index: usize, is_remote: bool, remote_depth: usize) !void {
        const document = self.tree.documents.items[document_index];
        if (self.visited.contains(document.source_id)) return;
        try self.visited.put(self.tree.allocator, document.source_id, {});
        const directives = document.directives.items;
        for (directives) |directive| {
            if (is_remote and (directive.kind == .include or directive.kind == .include_optional))
                return error.RemoteLocalIncludeForbidden;
            if (std.ascii.eqlIgnoreCase(directive.name, "SecRemoteRulesFailAction") and directive.arguments.len == 1) {
                const value = directive.arguments[0].content();
                if (std.ascii.eqlIgnoreCase(value, "Abort")) self.fail_action = .abort;
                if (std.ascii.eqlIgnoreCase(value, "Warn")) self.fail_action = .warn;
            }
            if (std.ascii.eqlIgnoreCase(directive.name, "SecRemoteRules") and directive.arguments.len == 2)
                try self.fetchRemote(document.source_id, directive, remote_depth + 1);
            var child_index: usize = 0;
            while (child_index < self.tree.documents.items.len) : (child_index += 1) {
                const child = self.tree.documents.items[child_index];
                const record = self.tree.registry.get(child.source_id) orelse continue;
                const origin = record.included_from orelse continue;
                if (origin.parent != document.source_id or !std.meta.eql(origin.directive, directive.physical)) continue;
                const child_remote = std.mem.startsWith(u8, record.path, "https://");
                try self.processDocument(child_index, child_remote, if (child_remote) remote_depth + 1 else remote_depth);
            }
        }
    }

    fn fetchRemote(self: *Context, parent: source.SourceId, directive: parser.Directive, depth: usize) !void {
        if (depth > self.options.max_remote_depth) return error.RemoteDepthExceeded;
        const key = directive.arguments[0].content();
        const url = directive.arguments[1].content();
        if (self.active_urls.contains(url)) return error.RemoteCycle;
        try self.active_urls.put(self.tree.allocator, url, {});
        defer _ = self.active_urls.remove(url);
        var outcome = try remote_rules.load(
            self.tree.allocator,
            self.fetcher,
            self.destination_policy,
            key,
            url,
            self.fail_action,
            self.options.remote_limits,
        );
        defer outcome.deinit();
        switch (outcome) {
            .warning => |warning| {
                if (self.tree.remote_warnings.items.len == self.options.max_warnings) return error.TooManyRemoteWarnings;
                try self.tree.remote_warnings.append(self.tree.allocator, .{
                    .directive = directive.physical,
                    .code = warning.code,
                });
            },
            .source => |*remote_source| {
                const source_id = try self.tree.registry.add(
                    remote_source.finalUrl(),
                    remote_source.bytes(),
                    .{ .parent = parent, .directive = directive.physical },
                );
                var document = try parser.parseSource(self.tree.allocator, &self.tree.registry, source_id, self.options.parser_limits);
                self.tree.documents.append(self.tree.allocator, document) catch |cause| {
                    document.deinit();
                    return cause;
                };
                try self.tree.remote_sources.append(self.tree.allocator, .{
                    .source_id = source_id,
                    .directive = directive.physical,
                    .content_digest = remote_source.content_digest,
                });
            },
        }
    }
};

const TestPolicy = struct {
    fn authorize(_: *anyopaque, _: []const u8, _: ?[]const u8) bool {
        return true;
    }
};

const TestFetcher = struct {
    body: []const u8,
    fail: bool = false,

    fn fetch(context: *anyopaque, allocator: std.mem.Allocator, request: remote_rules.Request) remote_rules.FetchError!remote_rules.Response {
        const self: *TestFetcher = @ptrCast(@alignCast(context));
        if (self.fail) return error.TransportFailure;
        if (!request.destination_policy.authorize(request.url, "203.0.113.20")) return error.PolicyRejected;
        const addresses = try allocator.alloc([]u8, 1);
        errdefer allocator.free(addresses);
        addresses[0] = try allocator.dupe(u8, "203.0.113.20");
        errdefer allocator.free(addresses[0]);
        const final_url = try allocator.dupe(u8, request.url);
        errdefer allocator.free(final_url);
        const body = try allocator.dupe(u8, self.body);
        return .{
            .allocator = allocator,
            .status = 200,
            .final_url = final_url,
            .body = body,
            .redirects = 0,
            .connected_addresses = addresses,
        };
    }
};

test "remote sources join the source tree with digest and directive provenance" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{
        .sub_path = "main.conf",
        .data = "SecRemoteRules key https://rules.example.test/bundle\nSecAction pass",
    });
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_length = try temporary.dir.realPathFile(std.testing.io, "main.conf", &path_buffer);
    var tree = try include.parseFile(std.testing.allocator, std.testing.io, path_buffer[0..path_length], .{});
    defer tree.deinit();
    var fetcher: TestFetcher = .{ .body = "SecRule ARGS @rx id:77" };
    var policy_byte: u8 = 0;
    try resolveRemoteRules(
        &tree,
        .{ .context = &fetcher, .fetchFn = TestFetcher.fetch },
        .{ .context = &policy_byte, .authorizeFn = TestPolicy.authorize },
        .{},
    );
    try std.testing.expectEqual(@as(usize, 2), tree.documents.items.len);
    try std.testing.expectEqual(@as(usize, 1), tree.remote_sources.items.len);
    try std.testing.expectEqual(@as(usize, 0), tree.remote_warnings.items.len);
    const record = tree.registry.get(tree.remote_sources.items[0].source_id).?;
    try std.testing.expectEqualStrings("https://rules.example.test/bundle", record.path);
    try std.testing.expectEqual(tree.documents.items[0].source_id, record.included_from.?.parent);
}

test "remote warn records no synthetic source and nested local includes fail" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{
        .sub_path = "warn.conf",
        .data = "SecRemoteRulesFailAction Warn\nSecRemoteRules key https://rules.example.test/unavailable",
    });
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_length = try temporary.dir.realPathFile(std.testing.io, "warn.conf", &path_buffer);
    var tree = try include.parseFile(std.testing.allocator, std.testing.io, path_buffer[0..path_length], .{});
    defer tree.deinit();
    var fetcher: TestFetcher = .{ .body = "", .fail = true };
    var policy_byte: u8 = 0;
    try resolveRemoteRules(
        &tree,
        .{ .context = &fetcher, .fetchFn = TestFetcher.fetch },
        .{ .context = &policy_byte, .authorizeFn = TestPolicy.authorize },
        .{},
    );
    try std.testing.expectEqual(@as(usize, 1), tree.documents.items.len);
    try std.testing.expectEqual(@as(usize, 1), tree.remote_warnings.items.len);
    try std.testing.expectEqual(remote_rules.WarningCode.transport_failure, tree.remote_warnings.items[0].code);
}
