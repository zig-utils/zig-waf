//! Authenticated, bounded remote ruleset loading for candidate construction.
//!
//! The request path never imports or calls this module. Concrete HTTP/TLS
//! transports must enforce the supplied destination policy before every
//! connection and redirect, then return address evidence for verification.

const std = @import("std");

pub const FailAction = enum { abort, warn };

pub const Limits = struct {
    timeout_ns: u64 = 10 * std.time.ns_per_s,
    max_response_bytes: usize = 16 * 1024 * 1024,
    max_url_bytes: usize = 8192,
    max_key_bytes: usize = 4096,
    max_redirects: u16 = 3,
    max_connected_addresses: usize = 16,

    pub fn validate(self: Limits) error{InvalidRemoteRuleLimit}!void {
        if (self.timeout_ns == 0 or self.max_response_bytes == 0 or self.max_url_bytes == 0 or
            self.max_key_bytes == 0 or self.max_connected_addresses == 0)
        {
            return error.InvalidRemoteRuleLimit;
        }
    }
};

pub const DestinationPolicy = struct {
    context: *anyopaque,
    authorizeFn: *const fn (context: *anyopaque, url: []const u8, address: ?[]const u8) bool,

    pub fn authorize(self: DestinationPolicy, url: []const u8, address: ?[]const u8) bool {
        return self.authorizeFn(self.context, url, address);
    }
};

pub const Request = struct {
    url: []const u8,
    authorization_key: []const u8,
    timeout_ns: u64,
    max_response_bytes: usize,
    max_redirects: u16,
    destination_policy: DestinationPolicy,
};

pub const Response = struct {
    allocator: std.mem.Allocator,
    status: u16,
    final_url: []u8,
    body: []u8,
    redirects: u16,
    connected_addresses: [][]u8,

    pub fn deinit(self: *Response) void {
        for (self.connected_addresses) |address| self.allocator.free(address);
        self.allocator.free(self.connected_addresses);
        self.allocator.free(self.final_url);
        self.allocator.free(self.body);
        self.* = undefined;
    }
};

pub const FetchError = std.mem.Allocator.Error || error{ TransportFailure, Timeout, PolicyRejected };

pub const Fetcher = struct {
    context: *anyopaque,
    fetchFn: *const fn (context: *anyopaque, allocator: std.mem.Allocator, request: Request) FetchError!Response,

    pub fn fetch(self: Fetcher, allocator: std.mem.Allocator, request: Request) FetchError!Response {
        return self.fetchFn(self.context, allocator, request);
    }
};

pub const WarningCode = enum {
    invalid_url,
    destination_denied,
    transport_failure,
    timeout,
    unexpected_status,
    redirect_limit,
    response_limit,
    empty_response,
    missing_address_evidence,
};

/// Deliberately contains neither the authentication key nor response bytes.
pub const Warning = struct {
    code: WarningCode,
};

pub const Source = struct {
    response: Response,
    content_digest: [32]u8,

    pub fn bytes(self: *const Source) []const u8 {
        return self.response.body;
    }

    pub fn finalUrl(self: *const Source) []const u8 {
        return self.response.final_url;
    }

    pub fn deinit(self: *Source) void {
        self.response.deinit();
        self.* = undefined;
    }
};

pub const Outcome = union(enum) {
    source: Source,
    warning: Warning,

    pub fn deinit(self: *Outcome) void {
        switch (self.*) {
            .source => |*source| source.deinit(),
            .warning => {},
        }
        self.* = undefined;
    }
};

pub const LoadError = std.mem.Allocator.Error || error{ InvalidRemoteRuleLimit, RemoteRulesAborted };

pub fn load(
    allocator: std.mem.Allocator,
    fetcher: Fetcher,
    destination_policy: DestinationPolicy,
    key: []const u8,
    url: []const u8,
    fail_action: FailAction,
    limits: Limits,
) LoadError!Outcome {
    try limits.validate();
    if (key.len == 0 or key.len > limits.max_key_bytes or url.len > limits.max_url_bytes or !safeHttpsUrl(url))
        return failure(fail_action, .invalid_url);
    if (!destination_policy.authorize(url, null)) return failure(fail_action, .destination_denied);
    var response = fetcher.fetch(allocator, .{
        .url = url,
        .authorization_key = key,
        .timeout_ns = limits.timeout_ns,
        .max_response_bytes = limits.max_response_bytes,
        .max_redirects = limits.max_redirects,
        .destination_policy = destination_policy,
    }) catch |cause| switch (cause) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Timeout => return failure(fail_action, .timeout),
        error.PolicyRejected => return failure(fail_action, .destination_denied),
        error.TransportFailure => return failure(fail_action, .transport_failure),
    };
    var transferred = false;
    defer if (!transferred) response.deinit();
    if (response.final_url.len > limits.max_url_bytes or !safeHttpsUrl(response.final_url))
        return failure(fail_action, .invalid_url);
    if (!destination_policy.authorize(response.final_url, null)) return failure(fail_action, .destination_denied);
    if (response.redirects > limits.max_redirects) return failure(fail_action, .redirect_limit);
    if (response.status != 200) return failure(fail_action, .unexpected_status);
    if (response.body.len == 0) return failure(fail_action, .empty_response);
    if (response.body.len > limits.max_response_bytes) return failure(fail_action, .response_limit);
    if (response.connected_addresses.len == 0 or response.connected_addresses.len > limits.max_connected_addresses)
        return failure(fail_action, .missing_address_evidence);
    for (response.connected_addresses) |address| {
        if (!destination_policy.authorize(response.final_url, address))
            return failure(fail_action, .destination_denied);
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(response.body, &digest, .{});
    transferred = true;
    return .{ .source = .{ .response = response, .content_digest = digest } };
}

fn failure(action: FailAction, code: WarningCode) error{RemoteRulesAborted}!Outcome {
    return switch (action) {
        .abort => error.RemoteRulesAborted,
        .warn => .{ .warning = .{ .code = code } },
    };
}

fn safeHttpsUrl(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    const parsed = std.Uri.parse(value) catch return false;
    if (!std.ascii.eqlIgnoreCase(parsed.scheme, "https")) return false;
    if (parsed.user != null or parsed.password != null or parsed.host == null) return false;
    return !parsed.host.?.isEmpty();
}

const TestPolicy = struct {
    calls: usize = 0,
    deny_address: ?[]const u8 = null,

    fn authorize(context: *anyopaque, _: []const u8, address: ?[]const u8) bool {
        const self: *TestPolicy = @ptrCast(@alignCast(context));
        self.calls += 1;
        if (self.deny_address) |denied| if (address) |candidate|
            return !std.mem.eql(u8, denied, candidate);
        return true;
    }

    fn policy(self: *TestPolicy) DestinationPolicy {
        return .{ .context = self, .authorizeFn = authorize };
    }
};

const TestFetcher = struct {
    status: u16 = 200,
    body: []const u8 = "SecAction pass",
    final_url: []const u8 = "https://rules.example.test/bundle",
    address: []const u8 = "203.0.113.10",
    redirects: u16 = 0,
    expected_key: []const u8 = "secret",

    fn fetch(context: *anyopaque, allocator: std.mem.Allocator, request: Request) FetchError!Response {
        const self: *TestFetcher = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, request.authorization_key, self.expected_key)) return error.TransportFailure;
        if (!request.destination_policy.authorize(request.url, self.address)) return error.PolicyRejected;
        const addresses = try allocator.alloc([]u8, 1);
        errdefer allocator.free(addresses);
        addresses[0] = try allocator.dupe(u8, self.address);
        errdefer allocator.free(addresses[0]);
        const final_url = try allocator.dupe(u8, self.final_url);
        errdefer allocator.free(final_url);
        const body = try allocator.dupe(u8, self.body);
        return .{
            .allocator = allocator,
            .status = self.status,
            .final_url = final_url,
            .body = body,
            .redirects = self.redirects,
            .connected_addresses = addresses,
        };
    }

    fn interface(self: *TestFetcher) Fetcher {
        return .{ .context = self, .fetchFn = fetch };
    }
};

test "authenticated remote source returns digest and verified provenance" {
    var policy_state: TestPolicy = .{};
    var fetcher_state: TestFetcher = .{};
    var outcome = try load(
        std.testing.allocator,
        fetcher_state.interface(),
        policy_state.policy(),
        "secret",
        "https://rules.example.test/bundle",
        .abort,
        .{},
    );
    defer outcome.deinit();
    switch (outcome) {
        .warning => return error.TestExpectedSource,
        .source => |source| {
            try std.testing.expectEqualStrings("SecAction pass", source.bytes());
            var expected: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash("SecAction pass", &expected, .{});
            try std.testing.expectEqualSlices(u8, &expected, &source.content_digest);
        },
    }
    try std.testing.expectEqual(@as(usize, 4), policy_state.calls);
}

test "warn is redacted and abort remains fail closed" {
    var policy_state: TestPolicy = .{ .deny_address = "203.0.113.10" };
    var fetcher_state: TestFetcher = .{};
    var warned = try load(
        std.testing.allocator,
        fetcher_state.interface(),
        policy_state.policy(),
        "never-print-this-key",
        "https://rules.example.test/bundle",
        .warn,
        .{},
    );
    defer warned.deinit();
    try std.testing.expectEqual(WarningCode.transport_failure, warned.warning.code);

    var abort_policy: TestPolicy = .{};
    var bad_status: TestFetcher = .{ .status = 503 };
    try std.testing.expectError(error.RemoteRulesAborted, load(
        std.testing.allocator,
        bad_status.interface(),
        abort_policy.policy(),
        "secret",
        "https://rules.example.test/bundle",
        .abort,
        .{},
    ));
}

test "URL response redirect address and body policies are bounded" {
    var policy_state: TestPolicy = .{};
    var fetcher_state: TestFetcher = .{};
    try std.testing.expectError(error.RemoteRulesAborted, load(std.testing.allocator, fetcher_state.interface(), policy_state.policy(), "secret", "http://rules.example.test", .abort, .{}));
    try std.testing.expectError(error.RemoteRulesAborted, load(std.testing.allocator, fetcher_state.interface(), policy_state.policy(), "secret", "https://user@rules.example.test", .abort, .{}));

    var redirect_fetcher: TestFetcher = .{ .redirects = 2 };
    var redirected = try load(std.testing.allocator, redirect_fetcher.interface(), policy_state.policy(), "secret", "https://rules.example.test", .warn, .{ .max_redirects = 1 });
    defer redirected.deinit();
    try std.testing.expectEqual(WarningCode.redirect_limit, redirected.warning.code);

    var large_fetcher: TestFetcher = .{ .body = "too large" };
    var limited = try load(std.testing.allocator, large_fetcher.interface(), policy_state.policy(), "secret", "https://rules.example.test", .warn, .{ .max_response_bytes = 3 });
    defer limited.deinit();
    try std.testing.expectEqual(WarningCode.response_limit, limited.warning.code);
}

test "remote loader is allocation failure safe" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var policy_state: TestPolicy = .{};
            var fetcher_state: TestFetcher = .{};
            var outcome = try load(allocator, fetcher_state.interface(), policy_state.policy(), "secret", "https://rules.example.test", .abort, .{});
            defer outcome.deinit();
        }
    }.run, .{});
}
