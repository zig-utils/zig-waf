//! IPv4 and IPv6 CIDR membership backing the `@ipMatch` family of operators.
//! Parsing follows the pinned Go `net.ParseIP`/`net.ParseCIDR` behavior used by
//! Coraza: a bare IPv6 address is treated as `/128`, a bare IPv4 address as
//! `/32`, and an unparseable subnet is skipped rather than failing the ruleset.

const std = @import("std");

pub const Address = union(enum) {
    v4: u32,
    v6: u128,
};

pub const Cidr = union(enum) {
    v4: struct { network: u32, prefix: u6 },
    v6: struct { network: u128, prefix: u8 },
};

pub const BuildError = std.mem.Allocator.Error || error{TooManySubnets};

pub const Limits = struct {
    max_subnets: usize = 1 << 20,
};

/// Parse a single dotted-quad IPv4 address into host-order bits.
pub fn parseIpv4(text: []const u8) ?u32 {
    var octets: [4]u8 = undefined;
    var index: usize = 0;
    var it = std.mem.splitScalar(u8, text, '.');
    while (it.next()) |part| {
        if (index == 4) return null;
        if (part.len == 0 or part.len > 3) return null;
        var value: u16 = 0;
        for (part) |digit| {
            if (digit < '0' or digit > '9') return null;
            value = value * 10 + (digit - '0');
        }
        if (value > 255) return null;
        octets[index] = @intCast(value);
        index += 1;
    }
    if (index != 4) return null;
    return (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) | @as(u32, octets[3]);
}

/// Parse an IPv6 address, including `::` zero-compression and a trailing
/// embedded IPv4 group, into 128 host-order bits.
pub fn parseIpv6(text: []const u8) ?u128 {
    if (text.len == 0) return null;
    const double = std.mem.indexOf(u8, text, "::");
    var head: [8]u16 = undefined;
    var head_len: usize = 0;
    var tail: [8]u16 = undefined;
    var tail_len: usize = 0;

    if (double) |pos| {
        // At most one "::" is allowed.
        if (std.mem.indexOf(u8, text[pos + 2 ..], "::") != null) return null;
        if (!parseGroups(text[0..pos], &head, &head_len)) return null;
        if (!parseGroups(text[pos + 2 ..], &tail, &tail_len)) return null;
        if (head_len + tail_len > 7) return null; // must leave >=1 zero group
    } else {
        if (!parseGroups(text, &head, &head_len)) return null;
        if (head_len != 8) return null;
    }

    var groups: [8]u16 = @splat(0);
    for (0..head_len) |i| groups[i] = head[i];
    for (0..tail_len) |i| groups[8 - tail_len + i] = tail[i];

    var result: u128 = 0;
    for (groups) |group| result = (result << 16) | group;
    return result;
}

/// Parse a colon-separated run of hex groups, expanding a trailing embedded
/// IPv4 literal (`::ffff:1.2.3.4`) into two groups. Returns false on any
/// malformed group. An empty segment (from a leading/trailing `::`) yields zero
/// groups.
fn parseGroups(text: []const u8, out: *[8]u16, out_len: *usize) bool {
    out_len.* = 0;
    if (text.len == 0) return true;
    var it = std.mem.splitScalar(u8, text, ':');
    while (it.next()) |group| {
        if (group.len == 0) return false;
        if (std.mem.indexOfScalar(u8, group, '.') != null) {
            const v4 = parseIpv4(group) orelse return false;
            if (out_len.* + 2 > out.len) return false;
            out[out_len.*] = @intCast(v4 >> 16);
            out[out_len.* + 1] = @truncate(v4);
            out_len.* += 2;
            continue;
        }
        if (group.len > 4) return false;
        var value: u16 = 0;
        for (group) |digit| {
            const nibble = hexNibble(digit) orelse return false;
            value = (value << 4) | nibble;
        }
        if (out_len.* == out.len) return false;
        out[out_len.*] = value;
        out_len.* += 1;
    }
    return true;
}

fn hexNibble(byte: u8) ?u16 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

/// Parse an address that is either IPv4 or IPv6. An IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`) is normalized to IPv4, matching Go `net.IP.To4`, so it
/// compares as IPv4 and never matches a genuine IPv6 subnet.
pub fn parseAddress(text: []const u8) ?Address {
    if (std.mem.indexOfScalar(u8, text, ':') != null) {
        const value = parseIpv6(text) orelse return null;
        if (value >> 32 == 0xffff) return .{ .v4 = @truncate(value) };
        return .{ .v6 = value };
    }
    return .{ .v4 = parseIpv4(text) orelse return null };
}

/// Parse one `@ipMatch` subnet token with the pinned bare-address defaults.
pub fn parseCidr(text_raw: []const u8) ?Cidr {
    const text = std.mem.trim(u8, text_raw, " \t\r\n");
    if (text.len == 0) return null;
    const is_v6 = std.mem.indexOfScalar(u8, text, ':') != null;
    const slash = std.mem.indexOfScalar(u8, text, '/');

    const address_text = if (slash) |pos| text[0..pos] else text;
    const default_prefix: u16 = if (is_v6) 128 else 32;
    const prefix: u16 = if (slash) |pos| blk: {
        const digits = text[pos + 1 ..];
        if (digits.len == 0 or digits.len > 3) return null;
        var value: u16 = 0;
        for (digits) |digit| {
            if (digit < '0' or digit > '9') return null;
            value = value * 10 + (digit - '0');
        }
        break :blk value;
    } else default_prefix;

    if (is_v6) {
        if (prefix > 128) return null;
        const address = parseIpv6(address_text) orelse return null;
        // An IPv4-mapped subnet normalizes to IPv4, keeping only the low 32 mask
        // bits (Go `networkNumberAndMask` slices `mask[12:]`).
        if (address >> 32 == 0xffff) {
            const v4: u32 = @truncate(address);
            const v4_prefix: u6 = if (prefix <= 96) 0 else @intCast(@min(@as(u16, 32), prefix - 96));
            return .{ .v4 = .{ .network = v4 & maskV4(v4_prefix), .prefix = v4_prefix } };
        }
        const mask = maskV6(@intCast(prefix));
        return .{ .v6 = .{ .network = address & mask, .prefix = @intCast(prefix) } };
    }
    if (prefix > 32) return null;
    const address = parseIpv4(address_text) orelse return null;
    const mask = maskV4(@intCast(prefix));
    return .{ .v4 = .{ .network = address & mask, .prefix = @intCast(prefix) } };
}

fn maskV4(prefix: u6) u32 {
    if (prefix == 0) return 0;
    return @as(u32, 0xffff_ffff) << @intCast(32 - @as(u32, prefix));
}

fn maskV6(prefix: u8) u128 {
    if (prefix == 0) return 0;
    return @as(u128, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff) << @intCast(128 - @as(u32, prefix));
}

/// Whether `address` falls inside `cidr`. Cross-family comparisons never match.
pub fn contains(cidr: Cidr, address: Address) bool {
    return switch (cidr) {
        .v4 => |net| switch (address) {
            .v4 => |ip| (ip & maskV4(net.prefix)) == net.network,
            .v6 => false,
        },
        .v6 => |net| switch (address) {
            .v6 => |ip| (ip & maskV6(net.prefix)) == net.network,
            .v4 => false,
        },
    };
}

/// A ruleset-owned compiled `@ipMatch` argument: a set of subnets. Immutable and
/// shareable across request workers.
pub const Matcher = struct {
    allocator: std.mem.Allocator,
    subnets: []Cidr,

    /// Build from a comma-separated subnet list. Unparseable tokens are skipped,
    /// matching Coraza `net.ParseCIDR` error tolerance.
    pub fn build(allocator: std.mem.Allocator, argument: []const u8, limits: Limits) BuildError!Matcher {
        var subnets: std.ArrayList(Cidr) = .empty;
        errdefer subnets.deinit(allocator);
        var it = std.mem.splitScalar(u8, argument, ',');
        while (it.next()) |token| {
            if (parseCidr(token)) |cidr| {
                if (subnets.items.len >= limits.max_subnets) return error.TooManySubnets;
                try subnets.append(allocator, cidr);
            }
        }
        return .{ .allocator = allocator, .subnets = try subnets.toOwnedSlice(allocator) };
    }

    pub fn deinit(self: *Matcher) void {
        self.allocator.free(self.subnets);
        self.* = undefined;
    }

    /// Whether the parsed `input` address is inside any configured subnet.
    pub fn matches(self: *const Matcher, input: []const u8) bool {
        const address = parseAddress(input) orelse return false;
        for (self.subnets) |cidr| {
            if (contains(cidr, address)) return true;
        }
        return false;
    }
};

test "ipv4 CIDR membership matches pinned prefixes" {
    var matcher = try Matcher.build(std.testing.allocator, "10.10.10.0/21", .{});
    defer matcher.deinit();
    try std.testing.expect(matcher.matches("10.10.10.11"));
    try std.testing.expect(!matcher.matches("10.10.7.254"));
    try std.testing.expect(matcher.matches("10.10.8.1"));
    try std.testing.expect(!matcher.matches("10.10.16.1"));
    try std.testing.expect(matcher.matches("10.10.15.254"));
}

test "bare ipv4 address is an exact /32 match" {
    var matcher = try Matcher.build(std.testing.allocator, "10.10.10.10", .{});
    defer matcher.deinit();
    try std.testing.expect(matcher.matches("10.10.10.10"));
    try std.testing.expect(!matcher.matches("10.10.10.11"));
}

test "invalid ipv4 prefix is skipped and never matches" {
    var matcher = try Matcher.build(std.testing.allocator, "10.0.0.0/100", .{});
    defer matcher.deinit();
    try std.testing.expectEqual(@as(usize, 0), matcher.subnets.len);
    try std.testing.expect(!matcher.matches("10.10.10.11"));
}

test "ipv6 CIDR membership and zero-compression" {
    var matcher = try Matcher.build(std.testing.allocator, "2001:db8::/32", .{});
    defer matcher.deinit();
    try std.testing.expect(matcher.matches("2001:0db8:ffff:ffff:ffff:ffff:ff00:00ff"));

    var narrow = try Matcher.build(std.testing.allocator, "2001:db8::/63", .{});
    defer narrow.deinit();
    try std.testing.expect(!narrow.matches("2001:0db8:ffff:ffff:ffff:ffff:ff00:00ff"));

    var loopback = try Matcher.build(std.testing.allocator, "::1", .{});
    defer loopback.deinit();
    try std.testing.expect(loopback.matches("0000:0000:0000:0000:0000:0000:0000:0001"));
    try std.testing.expect(loopback.matches("::1"));
    try std.testing.expect(!loopback.matches("::2"));
}

test "cross-family comparisons never match" {
    var matcher = try Matcher.build(std.testing.allocator, "10.0.0.0/8", .{});
    defer matcher.deinit();
    try std.testing.expect(!matcher.matches("::1"));

    var v6 = try Matcher.build(std.testing.allocator, "2001:db8::/32", .{});
    defer v6.deinit();
    try std.testing.expect(!v6.matches("10.0.0.1"));
}

test "comma-separated subnets and multiple families" {
    var matcher = try Matcher.build(std.testing.allocator, "10.0.0.0/8, 2001:db8::/32 , bogus", .{});
    defer matcher.deinit();
    try std.testing.expectEqual(@as(usize, 2), matcher.subnets.len);
    try std.testing.expect(matcher.matches("10.5.5.5"));
    try std.testing.expect(matcher.matches("2001:db8::1"));
    try std.testing.expect(!matcher.matches("192.168.1.1"));
}
