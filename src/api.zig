//! The versioned control-plane API surface (#49): its routes, the authorization each
//! one requires, and the matching that turns a request into an operation.
//!
//! This is the contract, not a server. Binding a socket, reading a request, and
//! writing a response belong to whatever hosts the control plane; what has to be
//! fixed — and testable without a network — is *which* operations exist, what each is
//! called, and who may invoke it. Those are the parts a client depends on and the
//! parts a mistake in is a security hole rather than a bug.
//!
//! `docs/api-v1.json` is the OpenAPI document for the same surface, and a test here
//! holds the two together: an operation in one and not the other fails the build.
//! A published contract that disagrees with the code is worse than none, because
//! clients are written against it.

const std = @import("std");
const auth = @import("authz.zig");

/// The API version, in the path prefix. A breaking change to any operation below
/// takes a new prefix rather than mutating one clients already call.
pub const version_prefix = "/api/v1";

pub const Method = enum { get, post, put, delete };

/// One operation: how it is addressed, what it is called, and the least privilege
/// that may invoke it.
///
/// Authorization lives here rather than in a handler because it is the property most
/// easily forgotten in one: a handler added without a check is a hole, while a route
/// added without a `requires` does not compile.
pub const Route = struct {
    method: Method,
    /// The path after `version_prefix`, with `{name}` marking a parameter.
    path: []const u8,
    /// Stable identifier, matching the OpenAPI document's `operationId`.
    operation: []const u8,
    /// The action a caller must be permitted to perform.
    requires: ?auth.Action,
};

/// Every operation the control plane exposes. Ordered by resource, and exhaustive:
/// a request that matches nothing here is a 404, never a fall-through to something
/// that happens to be close.
pub const routes = [_]Route{
    // Health is the one unauthenticated operation: a load balancer has no
    // credentials, and refusing it would make the control plane look down.
    .{ .method = .get, .path = "/health", .operation = "getHealth", .requires = null },

    // Auth
    .{ .method = .post, .path = "/auth/session", .operation = "createSession", .requires = null },
    .{ .method = .delete, .path = "/auth/session", .operation = "endSession", .requires = .view_fleet },
    .{ .method = .get, .path = "/auth/whoami", .operation = "getCurrentIdentity", .requires = .view_fleet },
    .{ .method = .post, .path = "/auth/tokens", .operation = "issueToken", .requires = .manage_tokens },
    .{ .method = .delete, .path = "/auth/tokens/{name}", .operation = "revokeToken", .requires = .manage_tokens },

    // Nodes
    .{ .method = .get, .path = "/nodes", .operation = "listNodes", .requires = .view_fleet },
    .{ .method = .post, .path = "/nodes", .operation = "enrollNode", .requires = .manage_settings },
    .{ .method = .get, .path = "/nodes/{node_id}", .operation = "getNode", .requires = .view_fleet },
    .{ .method = .post, .path = "/nodes/{node_id}/heartbeat", .operation = "recordHeartbeat", .requires = .view_fleet },
    .{ .method = .put, .path = "/nodes/{node_id}/labels/{key}", .operation = "setNodeLabel", .requires = .manage_settings },

    // Policies (rule-set bundles) and the rules inside them
    .{ .method = .get, .path = "/policies", .operation = "listPolicies", .requires = .view_fleet },
    .{ .method = .post, .path = "/policies", .operation = "publishPolicy", .requires = .manage_rulesets },
    .{ .method = .get, .path = "/policies/{name}/versions/{version}", .operation = "getPolicyVersion", .requires = .view_fleet },
    .{ .method = .get, .path = "/policies/{name}/versions/{version}/rules", .operation = "listPolicyRules", .requires = .view_fleet },
    .{ .method = .post, .path = "/policies/{name}/versions/{version}/verify", .operation = "verifyPolicySignature", .requires = .view_fleet },

    // Exclusions
    .{ .method = .get, .path = "/policies/{name}/exclusions", .operation = "listExclusions", .requires = .view_fleet },
    .{ .method = .post, .path = "/policies/{name}/exclusions", .operation = "createExclusion", .requires = .manage_rulesets },

    // Rollouts
    .{ .method = .get, .path = "/rollouts/{name}", .operation = "getRolloutState", .requires = .view_fleet },
    .{ .method = .post, .path = "/rollouts/{name}/assign", .operation = "assignRollout", .requires = .drive_rollout },
    .{ .method = .post, .path = "/rollouts/{name}/advance", .operation = "advanceRollout", .requires = .drive_rollout },
    .{ .method = .get, .path = "/rollouts/{name}/drift", .operation = "listRolloutDrift", .requires = .view_fleet },

    // Events and audits
    .{ .method = .get, .path = "/events", .operation = "searchEvents", .requires = .view_events },
    .{ .method = .post, .path = "/events", .operation = "ingestEvents", .requires = .view_fleet },
    .{ .method = .get, .path = "/events/export", .operation = "exportEvents", .requires = .export_events },
    .{ .method = .get, .path = "/audits/searches", .operation = "listSavedSearches", .requires = .view_events },
    .{ .method = .put, .path = "/audits/searches/{name}", .operation = "saveSearch", .requires = .view_events },

    // Alerts
    .{ .method = .get, .path = "/alerts", .operation = "listAlerts", .requires = .view_fleet },
    .{ .method = .post, .path = "/alerts", .operation = "createAlert", .requires = .manage_alerts },
    .{ .method = .post, .path = "/alerts/{name}/silence", .operation = "silenceAlert", .requires = .manage_alerts },
    .{ .method = .get, .path = "/alerts/failing", .operation = "listFailingAlertChannels", .requires = .view_fleet },

    // Metrics and settings
    .{ .method = .get, .path = "/metrics", .operation = "getMetrics", .requires = .view_fleet },
    .{ .method = .get, .path = "/settings", .operation = "listSettings", .requires = .manage_settings },
    .{ .method = .put, .path = "/settings/{key}", .operation = "setSetting", .requires = .manage_settings },
};

/// What a matched request resolved to.
pub const Match = struct {
    route: *const Route,
    /// Path parameter values, in the order they appear in the pattern. Borrowed from
    /// the request path.
    parameters: [max_parameters][]const u8,
    parameter_count: usize,

    pub fn parameter(self: Match, index: usize) ?[]const u8 {
        if (index >= self.parameter_count) return null;
        return self.parameters[index];
    }
};

/// No route uses more than this; a pattern needing more would not compile against it.
pub const max_parameters = 4;

/// Resolve a method and path to an operation, or null when nothing matches.
///
/// A path segment matches a `{name}` placeholder only if it is non-empty: a request
/// for `/nodes//heartbeat` names no node, and treating an empty segment as an
/// identifier is how a request reaches a handler with nothing to act on.
pub fn match(method: Method, path: []const u8) ?Match {
    if (!std.mem.startsWith(u8, path, version_prefix)) return null;
    const relative = path[version_prefix.len..];
    // Query strings are the caller's to strip, but tolerating one here means a route
    // cannot be missed because of it.
    const without_query = if (std.mem.indexOfScalar(u8, relative, '?')) |index| relative[0..index] else relative;
    if (without_query.len == 0) return null;

    for (&routes) |*route| {
        if (route.method != method) continue;
        var result = Match{ .route = route, .parameters = undefined, .parameter_count = 0 };
        if (matchPath(route.path, without_query, &result)) return result;
    }
    return null;
}

fn matchPath(pattern: []const u8, path: []const u8, result: *Match) bool {
    var pattern_parts = std.mem.splitScalar(u8, pattern, '/');
    var path_parts = std.mem.splitScalar(u8, path, '/');
    result.parameter_count = 0;
    while (true) {
        const expected = pattern_parts.next();
        const actual = path_parts.next();
        if (expected == null and actual == null) return true;
        if (expected == null or actual == null) return false;
        if (expected.?.len >= 2 and expected.?[0] == '{' and expected.?[expected.?.len - 1] == '}') {
            if (actual.?.len == 0) return false; // an empty segment names nothing
            if (result.parameter_count == max_parameters) return false;
            result.parameters[result.parameter_count] = actual.?;
            result.parameter_count += 1;
            continue;
        }
        if (!std.mem.eql(u8, expected.?, actual.?)) return false;
    }
}

/// Whether `role` may invoke `route`. A route with no requirement is open by
/// design — health and login — and every other route is refused for an
/// unauthenticated caller rather than defaulting to a role.
pub fn authorize(route: *const Route, role: ?auth.Role) bool {
    const action = route.requires orelse return true;
    const identity = role orelse return false;
    return identity.can(action);
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

test "routes resolve, with parameters, and only under the version prefix" {
    const health = match(.get, "/api/v1/health").?;
    try testing.expectEqualStrings("getHealth", health.route.operation);
    try testing.expectEqual(@as(usize, 0), health.parameter_count);

    const node = match(.get, "/api/v1/nodes/11111111-2222-3333-4444-555555555555").?;
    try testing.expectEqualStrings("getNode", node.route.operation);
    try testing.expectEqualStrings("11111111-2222-3333-4444-555555555555", node.parameter(0).?);

    const label = match(.put, "/api/v1/nodes/abc/labels/tier").?;
    try testing.expectEqualStrings("setNodeLabel", label.route.operation);
    try testing.expectEqualStrings("abc", label.parameter(0).?);
    try testing.expectEqualStrings("tier", label.parameter(1).?);

    // A query string does not hide a route.
    try testing.expectEqualStrings("searchEvents", match(.get, "/api/v1/events?node=abc&limit=10").?.route.operation);

    // A literal segment wins over nothing: an unknown path is unmatched rather than
    // falling through to a route that happens to be close.
    try testing.expect(match(.get, "/api/v1/nodes/abc/unknown") == null);
    try testing.expect(match(.get, "/api/v1/unknown") == null);
    try testing.expect(match(.post, "/api/v1/health") == null); // wrong method
    try testing.expect(match(.get, "/health") == null); // outside the version prefix
    try testing.expect(match(.get, "/api/v2/health") == null); // a version that does not exist

    // An empty segment names nothing, so it must not satisfy a parameter.
    try testing.expect(match(.post, "/api/v1/nodes//heartbeat") == null);
}

test "authorization is decided by the route, not by the handler" {
    // Health and login are open by design: a load balancer has no credentials, and
    // refusing the login is circular.
    try testing.expect(authorize(match(.get, "/api/v1/health").?.route, null));
    try testing.expect(authorize(match(.post, "/api/v1/auth/session").?.route, null));

    // Everything else refuses an unauthenticated caller rather than defaulting to a
    // role.
    const rollout = match(.post, "/api/v1/rollouts/crs/advance").?.route;
    try testing.expect(!authorize(rollout, null));
    try testing.expect(!authorize(rollout, .viewer));
    try testing.expect(authorize(rollout, .operator));
    try testing.expect(authorize(rollout, .admin));

    // A viewer reads events but cannot publish a policy or touch identity.
    try testing.expect(authorize(match(.get, "/api/v1/events").?.route, .viewer));
    try testing.expect(!authorize(match(.post, "/api/v1/policies").?.route, .viewer));
    try testing.expect(!authorize(match(.post, "/api/v1/auth/tokens").?.route, .operator));
    try testing.expect(authorize(match(.post, "/api/v1/auth/tokens").?.route, .admin));
}

test "every route is uniquely addressed and carries an operation id" {
    for (&routes, 0..) |route, index| {
        try testing.expect(route.operation.len != 0);
        try testing.expect(std.mem.startsWith(u8, route.path, "/"));
        for (routes[0..index]) |previous| {
            // Two routes with the same method and path would make which one runs
            // depend on declaration order.
            if (previous.method == route.method and std.mem.eql(u8, previous.path, route.path))
                return error.DuplicateRoute;
            if (std.mem.eql(u8, previous.operation, route.operation))
                return error.DuplicateOperationId;
        }
    }
}

test "the OpenAPI document and the route table describe the same API" {
    // A published contract that disagrees with the code is worse than none, because
    // clients are written against it. This holds the two together in the only way
    // that survives edits: every operation in one must exist in the other.
    const document = @embedFile("api-v1.json");
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, document, .{});
    defer parsed.deinit();

    var documented: std.StringHashMapUnmanaged(void) = .empty;
    defer documented.deinit(testing.allocator);

    const paths = parsed.value.object.get("paths").?.object;
    var path_entries = paths.iterator();
    while (path_entries.next()) |path_entry| {
        var method_entries = path_entry.value_ptr.object.iterator();
        while (method_entries.next()) |method_entry| {
            const operation = method_entry.value_ptr.object.get("operationId").?.string;
            try documented.put(testing.allocator, operation, {});

            // The documented path must resolve in the table, under the same method.
            const method: Method = if (std.mem.eql(u8, method_entry.key_ptr.*, "get"))
                .get
            else if (std.mem.eql(u8, method_entry.key_ptr.*, "post"))
                .post
            else if (std.mem.eql(u8, method_entry.key_ptr.*, "put"))
                .put
            else
                .delete;
            const full = try std.fmt.allocPrint(testing.allocator, "{s}{s}", .{ version_prefix, path_entry.key_ptr.* });
            defer testing.allocator.free(full);
            const resolved = match(method, full) orelse {
                std.debug.print("documented but unroutable: {s} {s}\n", .{ method_entry.key_ptr.*, path_entry.key_ptr.* });
                return error.DocumentedRouteMissing;
            };
            try testing.expectEqualStrings(operation, resolved.route.operation);
        }
    }

    for (&routes) |route| {
        if (!documented.contains(route.operation)) {
            std.debug.print("routable but undocumented: {s}\n", .{route.operation});
            return error.RouteUndocumented;
        }
    }
    try testing.expectEqual(routes.len, documented.count());
}

test "every path parameter is declared, and declares nothing the path does not have" {
    // A parameter present in the template but absent from the document is invisible
    // to a generated client, which then cannot address the resource at all; one
    // declared but not in the template is a value the server will never receive.
    // Both read as working documentation, so neither is caught by review.
    const document = @embedFile("api-v1.json");
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, document, .{});
    defer parsed.deinit();

    const paths = parsed.value.object.get("paths").?.object;
    var path_entries = paths.iterator();
    while (path_entries.next()) |path_entry| {
        const template = path_entry.key_ptr.*;
        var method_entries = path_entry.value_ptr.object.iterator();
        while (method_entries.next()) |method_entry| {
            const operation = method_entry.value_ptr.object;
            const all = if (operation.get("parameters")) |value| value.array.items else &.{};

            // Path parameters are checked against the template; query parameters are
            // checked for shape only, since the template says nothing about them.
            var declared: std.ArrayList(std.json.Value) = .empty;
            defer declared.deinit(testing.allocator);
            for (all) |parameter| {
                const location = parameter.object.get("in").?.string;
                if (std.mem.eql(u8, location, "path")) {
                    try declared.append(testing.allocator, parameter);
                    continue;
                }
                try testing.expectEqualStrings("query", location);
                // Optionality must be stated rather than left to a generator's
                // default, which would silently turn a mandatory filter — the node a
                // search is scoped to — into one a caller may omit.
                const required = parameter.object.get("required") orelse return error.QueryParameterOptionalityUnstated;
                try testing.expect(required == .bool);
                try testing.expect(parameter.object.get("schema") != null);
            }

            // Every `{name}` in the template is declared, in order, as a required
            // path parameter.
            var index: usize = 0;
            var rest = template;
            while (std.mem.indexOfScalar(u8, rest, '{')) |open| {
                const close = std.mem.indexOfScalarPos(u8, rest, open, '}').?;
                const name = rest[open + 1 .. close];
                rest = rest[close + 1 ..];

                if (index >= declared.items.len) {
                    std.debug.print("undeclared path parameter: {s} in {s}\n", .{ name, template });
                    return error.PathParameterUndeclared;
                }
                const parameter = declared.items[index].object;
                try testing.expectEqualStrings(name, parameter.get("name").?.string);
                try testing.expectEqualStrings("path", parameter.get("in").?.string);
                // OpenAPI requires `required: true` on a path parameter; a client
                // generator is entitled to reject the document without it.
                try testing.expect(parameter.get("required").?.bool);
                try testing.expect(parameter.get("schema") != null);
                index += 1;
            }
            if (index != declared.items.len) {
                std.debug.print("declared parameter not in path: {s}\n", .{template});
                return error.ParameterNotInPath;
            }
        }
    }
}

test "every failure is the one documented error shape, and every reference resolves" {
    // A client writes one error path. That only holds if every operation's failures
    // point at the same schema, so this checks the pointers rather than trusting
    // that each of the thirty-four operations was written the same way.
    const document = @embedFile("api-v1.json");
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, document, .{});
    defer parsed.deinit();
    const root = parsed.value.object;

    const paths = root.get("paths").?.object;
    var path_entries = paths.iterator();
    while (path_entries.next()) |path_entry| {
        var method_entries = path_entry.value_ptr.object.iterator();
        while (method_entries.next()) |method_entry| {
            const responses = method_entry.value_ptr.object.get("responses").?.object;
            var status_entries = responses.iterator();
            var failures: usize = 0;
            while (status_entries.next()) |status_entry| {
                const status = status_entry.key_ptr.*;
                if (status[0] != '4' and status[0] != '5') continue;
                failures += 1;
                const reference = status_entry.value_ptr.object.get("$ref") orelse {
                    std.debug.print(
                        "inline failure body: {s} {s}\n",
                        .{ status, method_entry.value_ptr.object.get("operationId").?.string },
                    );
                    return error.FailureBodyNotShared;
                };
                try testing.expect(resolves(root, reference.string));
            }
            // An operation that documents no failure at all claims it cannot fail.
            try testing.expect(failures != 0);
        }
    }

    // Each shared response carries the error schema itself, so the indirection ends
    // somewhere real.
    var shared = root.get("components").?.object.get("responses").?.object.iterator();
    while (shared.next()) |entry| {
        const schema = entry.value_ptr.object.get("content").?.object
            .get("application/json").?.object.get("schema").?.object;
        try testing.expectEqualStrings("#/components/schemas/Error", schema.get("$ref").?.string);
    }
    try testing.expect(resolves(root, "#/components/schemas/Error"));
}

test "every operation describes what it returns and what it accepts" {
    // An operation documented as returning 200 with no body shape tells a client
    // nothing it can be written against, which is the state this document was in:
    // thirty-four operations, none of them describing a payload.
    const document = @embedFile("api-v1.json");
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, document, .{});
    defer parsed.deinit();
    const root = parsed.value.object;

    var referenced: std.StringHashMapUnmanaged(void) = .empty;
    defer referenced.deinit(testing.allocator);

    const paths = root.get("paths").?.object;
    var path_entries = paths.iterator();
    while (path_entries.next()) |path_entry| {
        var method_entries = path_entry.value_ptr.object.iterator();
        while (method_entries.next()) |method_entry| {
            const operation = method_entry.value_ptr.object;
            const name = operation.get("operationId").?.string;

            if (operation.get("requestBody")) |body| {
                // A request body that is not required is one the server must handle
                // both with and without, doubling the cases every handler gets right.
                try testing.expect(body.object.get("required").?.bool);
                const schema = try onlyContentSchema(body.object.get("content").?.object);
                try collectReferences(testing.allocator, &referenced, root, schema);
            }

            var success_seen = false;
            var status_entries = operation.get("responses").?.object.iterator();
            while (status_entries.next()) |status_entry| {
                const status = status_entry.key_ptr.*;
                if (status[0] != '2') continue;
                success_seen = true;
                const body = status_entry.value_ptr.object;
                if (std.mem.eql(u8, status, "204")) {
                    // 204 means no body; declaring content for one is a contradiction
                    // a client resolves by guessing.
                    try testing.expect(body.get("content") == null);
                    continue;
                }
                const content = body.get("content") orelse {
                    std.debug.print("no response body shape: {s}\n", .{name});
                    return error.ResponseBodyUndescribed;
                };
                const schema = try onlyContentSchema(content.object);
                try collectReferences(testing.allocator, &referenced, root, schema);
            }
            try testing.expect(success_seen);
        }
    }

    // Follow references through the schemas themselves: a resource is usually
    // reachable only via the collection that lists it, so stopping at the operations
    // would report most of the document as unused.
    const schemas = root.get("components").?.object.get("schemas").?.object;
    var grew = true;
    while (grew) {
        grew = false;
        var reachable = referenced.keyIterator();
        var pending: std.ArrayList([]const u8) = .empty;
        defer pending.deinit(testing.allocator);
        while (reachable.next()) |name| try pending.append(testing.allocator, name.*);
        for (pending.items) |name| {
            const before = referenced.count();
            try collectReferences(testing.allocator, &referenced, root, schemas.get(name).?);
            if (referenced.count() != before) grew = true;
        }
    }

    // A schema nothing points at is dead weight that still reads as part of the
    // contract, so it either gets used or gets deleted.
    var declared = schemas.iterator();
    while (declared.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, "Error")) continue; // reached via components.responses
        if (!referenced.contains(entry.key_ptr.*)) {
            std.debug.print("schema declared but never used: {s}\n", .{entry.key_ptr.*});
            return error.SchemaUnreferenced;
        }
    }
}

/// The schema of a content map that must describe exactly one media type. More than
/// one would mean the operation returns different shapes depending on what the caller
/// asked for, which every reference in this document treats as a mistake rather than
/// a feature.
fn onlyContentSchema(content: std.json.ObjectMap) !std.json.Value {
    if (content.count() != 1) return error.AmbiguousMediaType;
    var entries = content.iterator();
    return entries.next().?.value_ptr.object.get("schema") orelse error.MediaTypeHasNoSchema;
}

/// Record every schema reference in a JSON subtree, checking that each resolves.
/// Walks the whole subtree rather than known keys, so a reference in a shape this
/// document does not use yet is still followed rather than quietly missed.
fn collectReferences(
    allocator: std.mem.Allocator,
    into: *std.StringHashMapUnmanaged(void),
    root: std.json.ObjectMap,
    value: std.json.Value,
) !void {
    switch (value) {
        .object => |fields| {
            if (fields.get("$ref")) |reference| {
                if (reference != .string or !resolves(root, reference.string))
                    return error.UnresolvableReference;
                const prefix = "#/components/schemas/";
                if (std.mem.startsWith(u8, reference.string, prefix))
                    try into.put(allocator, reference.string[prefix.len..], {});
            }
            var entries = fields.iterator();
            while (entries.next()) |entry|
                try collectReferences(allocator, into, root, entry.value_ptr.*);
        },
        .array => |items| {
            for (items.items) |item| try collectReferences(allocator, into, root, item);
        },
        else => {},
    }
}

/// Whether a local JSON pointer of the form `#/a/b/c` names something in `root`.
/// Only local references are supported: the document is self-contained by design, so
/// a reference that leaves it is a defect rather than a case to handle.
fn resolves(root: std.json.ObjectMap, reference: []const u8) bool {
    if (!std.mem.startsWith(u8, reference, "#/")) return false;
    var current = std.json.Value{ .object = root };
    var segments = std.mem.tokenizeScalar(u8, reference[2..], '/');
    while (segments.next()) |segment| {
        if (current != .object) return false;
        current = current.object.get(segment) orelse return false;
    }
    return true;
}
